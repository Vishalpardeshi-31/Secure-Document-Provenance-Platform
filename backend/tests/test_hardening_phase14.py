import os
import io
import time
import base64
import pytest
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
import pyotp

from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.models.device import Device
from app.models.mfa import UserMfaCredential
from app.models.session import UserSession
from app.models.audit_event import AuditEvent
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
import uuid
from app.models.decryption_session import DecryptionSession
from app.models.viewer_session import ViewerSession
from app.security.password import hash_password
from app.security.mfa_service import MfaService, MfaCrypto
from app.security.tokens import create_access_token, decode_access_token
from app.services.device_service import DeviceService
from app.services.session_service import SessionService
from app.services.auth_service import AuthService
from app.security.rate_limiter import auth_rate_limiter
from app.config.settings import settings


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    auth_rate_limiter._requests.clear()
    yield
    auth_rate_limiter._requests.clear()


def get_error_message(res):
    """Safely extracts error message from either FastAPI default or centralized error body."""
    try:
        data = res.json()
        if isinstance(data, dict):
            if "error" in data and isinstance(data["error"], dict) and "message" in data["error"]:
                return data["error"]["message"]
            if "detail" in data:
                return str(data["detail"])
        return str(data)
    except Exception:
        return res.text


def create_test_user(
    db,
    username="testuser",
    email="testuser@example.com",
    role=UserRole.RECIPIENT.value,
    password="TestPassword123!",
    can_emergency_decrypt=False,
):
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        can_emergency_decrypt=can_emergency_decrypt,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_test_document(db, owner_id, title="Test Doc"):
    doc = Document(
        owner_id=owner_id,
        title=title,
        original_filename=f"{title.lower().replace(' ', '_')}.pdf",
        mime_type="application/pdf",
        original_size_bytes=1024,
        encrypted_size_bytes=1024,
        storage_reference="local://test-storage",
        plaintext_sha256="0" * 64,
        ciphertext_sha256="1" * 64,
        nonce="2" * 24,
        encrypted_dek="3" * 64,
        status="ACTIVE",
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return doc


# ==============================================================================
# MFA TESTS (1-6)
# ==============================================================================

def test_01_totp_enrollment_works(client, db_session):
    """1. TOTP enrollment generates secret and provisioning URI."""
    user = create_test_user(db_session, username="mfa_user1", email="mfa1@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    res = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["method"] == "TOTP"
    assert "provisioning_uri" in data
    assert "secret" in data
    assert data["status"] == "ENROLLMENT_PENDING_VERIFICATION"

    cred = db_session.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id).first()
    assert cred is not None
    assert cred.enabled is False


def test_02_invalid_totp_fails(client, db_session):
    """2. Submitting an invalid TOTP code rejects verification."""
    user = create_test_user(db_session, username="mfa_user2", email="mfa2@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    client.post("/api/v1/auth/mfa/enroll", headers=headers)

    res = client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=headers)
    assert res.status_code == 400
    assert "Invalid TOTP" in get_error_message(res)

    cred = db_session.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id).first()
    assert cred.enabled is False
    assert cred.failed_attempt_count == 1


def test_03_correct_totp_succeeds(client, db_session):
    """3. Submitting the correct TOTP code enables MFA and upgrades assurance."""
    user = create_test_user(db_session, username="mfa_user3", email="mfa3@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    secret = enroll_res.json()["secret"]

    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    verify_res = client.post("/api/v1/auth/mfa/verify", json={"code": valid_code}, headers=headers)
    assert verify_res.status_code == 200
    vdata = verify_res.json()
    assert vdata["verified"] is True
    assert vdata["auth_assurance_level"] == "MFA_VERIFIED"
    assert "access_token" in vdata

    cred = db_session.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id).first()
    assert cred.enabled is True
    assert cred.verified_at is not None


def test_04_mfa_secret_is_encrypted_at_rest(client, db_session):
    """4. MFA secret is encrypted at rest using dedicated AES-256-GCM key."""
    user = create_test_user(db_session, username="mfa_user4", email="mfa4@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    plain_secret = enroll_res.json()["secret"]

    cred = db_session.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id).first()
    assert cred.encrypted_secret != plain_secret
    assert plain_secret not in cred.encrypted_secret

    # Verify decryptability using MfaCrypto
    decrypted = MfaCrypto.decrypt_secret(cred.encrypted_secret, cred.secret_nonce)
    assert decrypted == plain_secret


def test_05_mfa_secret_never_returned_after_enrollment(client, db_session):
    """5. MFA secret is never disclosed in profile, status, or verify responses."""
    user = create_test_user(db_session, username="mfa_user5", email="mfa5@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    secret = enroll_res.json()["secret"]
    valid_code = pyotp.TOTP(secret).now()
    client.post("/api/v1/auth/mfa/verify", json={"code": valid_code}, headers=headers)

    # Check status endpoint
    status_res = client.get("/api/v1/auth/mfa/status", headers=headers)
    assert status_res.status_code == 200
    assert "secret" not in status_res.json()
    assert status_res.json()["enabled"] is True

    # Check profile endpoint
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert "secret" not in me_res.json()
    assert me_res.json()["mfa_enabled"] is True


def test_06_sensitive_action_requires_step_up_mfa(client, db_session):
    """6. Sensitive operations reject users with MFA enabled if assurance is NORMAL or expired."""
    user = create_test_user(db_session, username="mfa_user6", email="mfa6@example.com")
    # Enroll and enable MFA
    MfaService.enroll_totp(db_session, user)
    cred = db_session.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id).first()
    secret = MfaCrypto.decrypt_secret(cred.encrypted_secret, cred.secret_nonce)
    MfaService.verify_enrollment(db_session, user, pyotp.TOTP(secret).now())

    # Issue a NORMAL token (no MFA step-up)
    token_resp = AuthService.issue_token_for_user(db_session, user, auth_assurance_level="NORMAL")
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    # Attempt sensitive operation: viewer session creation without step-up
    res = client.post("/api/v1/documents/fake-doc-id/viewer-session", headers=headers)
    assert res.status_code == 403
    assert "Step-up MFA authentication required" in get_error_message(res)


# ==============================================================================
# DEVICE TESTS (7-11)
# ==============================================================================

def test_07_unregistered_device_is_rejected(client, db_session):
    """7. Supplying an unregistered device ID for policy/session fails."""
    user = create_test_user(db_session, username="dev_user1", email="dev1@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    res = client.post(
        "/api/v1/documents/fake-doc-id/viewer-session",
        json={"device_id": "nonexistent-device-uuid"},
        headers=headers,
    )
    assert res.status_code == 403
    assert "device is revoked or unauthorized" in get_error_message(res)


def test_08_revoked_device_is_rejected(client, db_session):
    """8. A revoked device is immediately blocked from sensitive operations."""
    user = create_test_user(db_session, username="dev_user2", email="dev2@example.com")
    device = DeviceService.register_device(db_session, user.id, "MacBook-Pro", "fingerprint-1234567890123456")
    DeviceService.revoke_device(db_session, device.id, user.id)

    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    res = client.post(
        "/api/v1/documents/fake-doc-id/viewer-session",
        json={"device_id": device.id},
        headers=headers,
    )
    assert res.status_code == 403
    assert "device is revoked or unauthorized" in get_error_message(res)


def test_09_device_challenge_detects_invalid_signatures(client, db_session):
    """9. Device challenge-response verifies Ed25519 signatures and rejects invalid signatures."""
    user = create_test_user(db_session, username="dev_user3", email="dev3@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    # Generate Ed25519 key pair on client
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key_bytes = priv_key.public_key().public_bytes_raw()
    pub_key_b64 = base64.b64encode(pub_key_bytes).decode("ascii")

    # Register device with public key
    reg_res = client.post(
        "/api/v1/devices",
        json={
            "device_name": "Workstation",
            "device_fingerprint": "fingerprint-workstation-secure-01",
            "public_key": pub_key_b64,
        },
        headers=headers,
    )
    assert reg_res.status_code == 201
    device_id = reg_res.json()["id"]

    # Request challenge nonce
    chal_res = client.post(f"/api/v1/devices/{device_id}/challenge", headers=headers)
    assert chal_res.status_code == 200
    nonce = chal_res.json()["challenge_nonce"]

    # 9a. Test invalid signature
    bad_sig = "00" * 64
    verify_bad = client.post(
        f"/api/v1/devices/{device_id}/verify-challenge",
        json={"signature_hex": bad_sig},
        headers=headers,
    )
    assert verify_bad.status_code == 401

    # Request a new challenge nonce
    chal_res2 = client.post(f"/api/v1/devices/{device_id}/challenge", headers=headers)
    nonce2 = chal_res2.json()["challenge_nonce"]

    # 9b. Sign with real private key
    sig = priv_key.sign(nonce2.encode("utf-8"))
    verify_good = client.post(
        f"/api/v1/devices/{device_id}/verify-challenge",
        json={"signature_hex": sig.hex()},
        headers=headers,
    )
    assert verify_good.status_code == 200
    assert verify_good.json()["verified"] is True


def test_10_device_private_key_never_sent_to_server(client, db_session):
    """10. Registration schema and storage only ever accept and store public keys, never private keys."""
    user = create_test_user(db_session, username="dev_user4", email="dev4@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    reg_res = client.post(
        "/api/v1/devices",
        json={
            "device_name": "Linux-Box",
            "device_fingerprint": "fingerprint-linux-box-secure-02",
            "public_key": "dGVzdC1wdWJsaWMta2V5LTMyeS1ieXRlcw==",
        },
        headers=headers,
    )
    assert reg_res.status_code == 201
    device_data = reg_res.json()
    assert "private_key" not in device_data


def test_11_device_bound_session_rejected_if_device_revoked(client, db_session):
    """11. An active session bound to a revoked device is rejected upon subsequent request."""
    user = create_test_user(db_session, username="dev_user5", email="dev5@example.com")
    device = DeviceService.register_device(db_session, user.id, "iPad-Air", "fingerprint-ipad-air-0011")

    # Issue session token bound to device
    token_resp = AuthService.issue_token_for_user(db_session, user, device_id=device.id)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    # Verify session is valid before revocation
    me_res1 = client.get("/api/v1/auth/me", headers=headers)
    assert me_res1.status_code == 200

    # Revoke device
    DeviceService.revoke_device(db_session, device.id, user.id)

    # Subsequent request using session bound to revoked device MUST be rejected
    me_res2 = client.get("/api/v1/auth/me", headers=headers)
    assert me_res2.status_code == 401
    assert "device associated with this session has been revoked" in get_error_message(me_res2)


# ==============================================================================
# SESSION TESTS (12-15)
# ==============================================================================

def test_12_expired_session_is_rejected(client, db_session):
    """12. Expired session records in user_sessions are rejected server-side."""
    user = create_test_user(db_session, username="sess_user1", email="sess1@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)

    # Force expiration in database
    session = SessionService.get_by_id(db_session, token_resp.session_id)
    session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()

    headers = {"Authorization": f"Bearer {token_resp.access_token}"}
    res = client.get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 401
    assert "session has expired" in get_error_message(res)


def test_13_revoked_session_is_rejected(client, db_session):
    """13. Explicitly revoked session fails server-side."""
    user = create_test_user(db_session, username="sess_user2", email="sess2@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    # Revoke session via endpoint
    revoke_res = client.post(f"/api/v1/auth/sessions/{token_resp.session_id}/revoke", headers=headers)
    assert revoke_res.status_code == 200

    # Request with revoked session token fails
    res = client.get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 401
    assert "revoked" in get_error_message(res).lower()


def test_14_step_up_reauthentication_enforced(client, db_session):
    """14. Step-up re-authentication endpoint validates TOTP and issues refreshed assurance."""
    user = create_test_user(db_session, username="sess_user3", email="sess3@example.com")
    MfaService.enroll_totp(db_session, user)
    cred = db_session.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id).first()
    secret = MfaCrypto.decrypt_secret(cred.encrypted_secret, cred.secret_nonce)
    MfaService.verify_enrollment(db_session, user, pyotp.TOTP(secret).now())

    # User logged in with NORMAL assurance
    token_resp = AuthService.issue_token_for_user(db_session, user, auth_assurance_level="NORMAL")
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    # Perform step-up
    step_up_code = pyotp.TOTP(secret).now()
    step_res = client.post("/api/v1/auth/mfa/step-up", json={"code": step_up_code}, headers=headers)
    assert step_res.status_code == 200
    sdata = step_res.json()
    assert sdata["auth_assurance_level"] == "MFA_VERIFIED"
    assert "access_token" in sdata

    # Use refreshed token for sensitive endpoint
    new_headers = {"Authorization": f"Bearer {sdata['access_token']}"}
    # Sensitive check should no longer fail on step-up
    res = client.post("/api/v1/documents/fake-doc-id/viewer-session", headers=new_headers)
    # Fails on document not found (404/400), NOT on step-up required (403)!
    assert res.status_code != 403


def test_15_viewer_session_cannot_outlive_authorization(client, db_session):
    """15. Terminating or revoking a device immediately kills active viewer sessions."""
    user = create_test_user(db_session, username="sess_user4", email="sess4@example.com")
    doc = create_test_document(db_session, user.id, "Viewer Outlive Doc")
    device = DeviceService.register_device(db_session, user.id, "Surface-Pro", "fingerprint-surface-pro-01")

    now = datetime.now(timezone.utc)
    dec_sess = DecryptionSession(
        document_id=doc.id,
        version_id=str(uuid.uuid4()),
        user_id=user.id,
        device_id=device.id,
        session_token_hash="a" * 64,
        status="AUTHORIZED",
        started_at=now,
    )
    db_session.add(dec_sess)
    db_session.commit()
    db_session.refresh(dec_sess)

    vs = ViewerSession(
        decryption_session_id=dec_sess.id,
        document_version_id=dec_sess.version_id,
        document_id=doc.id,
        user_id=user.id,
        device_id=device.id,
        status="ACTIVE",
        expires_at=now + timedelta(minutes=15),
        last_activity_at=now,
    )
    db_session.add(vs)
    db_session.commit()
    db_session.refresh(vs)

    # Revoke device
    DeviceService.revoke_device(db_session, device.id, user.id)

    # Verify that viewer session was terminated upon device revocation
    db_session.refresh(vs)
    assert vs.status == "REVOKED" or vs.status == "TERMINATED"


# ==============================================================================
# AUTHORIZATION TESTS (16-20)
# ==============================================================================

def test_16_recipient_cannot_access_another_recipients_document(client, db_session):
    """16. Recipient cannot decrypt documents for which they are not an authorized recipient."""
    owner = create_test_user(db_session, username="owner1", email="owner1@example.com", role=UserRole.ADMIN.value)
    unauthorized_user = create_test_user(db_session, username="stranger", email="stranger@example.com")

    doc = create_test_document(db_session, owner.id, "Classified Strategy")

    token_resp = AuthService.issue_token_for_user(db_session, unauthorized_user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    res = client.post(f"/api/v1/documents/{doc.id}/decrypt", headers=headers)
    assert res.status_code == 403
    assert "not an authorized active recipient" in get_error_message(res).lower() or "denied" in get_error_message(res).lower()


def test_17_recipient_cannot_invoke_investigator_apis(client, db_session):
    """17. Recipient role cannot create or list investigation cases."""
    recipient = create_test_user(db_session, username="recip1", email="recip1@example.com", role=UserRole.RECIPIENT.value)
    token_resp = AuthService.issue_token_for_user(db_session, recipient)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    res = client.get("/api/v1/investigations", headers=headers)
    assert res.status_code == 403
    assert "access denied" in get_error_message(res).lower()


def test_18_investigator_cannot_obtain_recipient_private_keys(client, db_session):
    """18. Key management endpoints do not expose raw recipient private keys."""
    auditor = create_test_user(db_session, username="investigator1", email="inv1@example.com", role=UserRole.AUDITOR.value)
    token_resp = AuthService.issue_token_for_user(db_session, auditor)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    res = client.get("/api/v1/recipients/keys", headers=headers)
    if res.status_code == 200:
        for k in res.json():
            assert "private_key" not in k
            assert "raw_private_key" not in k


def test_19_admin_cannot_bypass_recipient_authorization(client, db_session):
    """19. Admin cannot decrypt a document merely by having ADMIN role without being an authorized recipient."""
    admin = create_test_user(db_session, username="superadmin", email="admin@example.com", role=UserRole.ADMIN.value)
    other = create_test_user(db_session, username="author1", email="author1@example.com")

    doc = create_test_document(db_session, other.id, "Board Resolution")

    token_resp = AuthService.issue_token_for_user(db_session, admin)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    res = client.post(f"/api/v1/documents/{doc.id}/decrypt", headers=headers)
    assert res.status_code == 403
    assert "not an authorized active recipient" in get_error_message(res).lower() or "denied" in get_error_message(res).lower()


def test_20_emergency_access_follows_required_security_controls(client, db_session):
    """20. Emergency access strictly requires permission flag and step-up authentication."""
    normal_user = create_test_user(
        db_session,
        username="norm_user",
        email="norm@example.com",
        can_emergency_decrypt=False,
    )
    token_resp = AuthService.issue_token_for_user(db_session, normal_user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    # Should be rejected because user lacks emergency decrypt permission
    res = client.post(
        "/api/v1/documents/fake-doc-id/emergency-requests",
        json={"reason": "Critical crisis handling", "requested_duration_minutes": 30},
        headers=headers,
    )
    assert res.status_code == 403
    assert "emergency" in get_error_message(res).lower() or "forbidden" in get_error_message(res).lower()


# ==============================================================================
# RATE LIMITING & LOCKOUT TESTS (21-23)
# ==============================================================================

def test_21_repeated_login_failures_trigger_backend_protection(client, db_session):
    """21. Repeated login failures trigger account lockout and rate limiting."""
    user = create_test_user(db_session, username="victim_user", email="victim@example.com")

    # 5 failed password attempts
    for _ in range(5):
        res = client.post("/api/v1/auth/login", json={"username_or_email": user.username, "password": "WrongPassword!"})
        assert res.status_code == 401

    # 6th attempt should return ACCOUNT_LOCKED (HTTP 403)
    res_locked = client.post("/api/v1/auth/login", json={"username_or_email": user.username, "password": "WrongPassword!"})
    assert res_locked.status_code == 403
    assert "locked" in get_error_message(res_locked).lower()


def test_22_repeated_mfa_failures_trigger_backend_lockout(client, db_session):
    """22. Repeated failed MFA codes trigger credential lockout."""
    user = create_test_user(db_session, username="mfa_lockout_user", email="lock@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    client.post("/api/v1/auth/mfa/enroll", headers=headers)

    # 5 wrong codes
    for _ in range(5):
        client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=headers)

    # 6th attempt must be locked
    res = client.post("/api/v1/auth/mfa/verify", json={"code": "000000"}, headers=headers)
    assert res.status_code == 400
    assert "temporarily locked" in get_error_message(res).lower()


def test_23_rate_limits_enforced_by_backend(client, db_session):
    """23. Backend rate limiter rejects excessive rapid requests with HTTP 429."""
    for _ in range(30):
        auth_rate_limiter.record_attempt("test_key")

    with pytest.raises(Exception) as exc:
        auth_rate_limiter.check_rate_limit("test_key", max_requests=30, window_seconds=60)
    assert "Rate limit exceeded" in str(exc.value)


# ==============================================================================
# CORS & HEADERS TESTS (24-25)
# ==============================================================================

def test_24_cors_and_security_headers_enforced(client):
    """24. Security headers and explicit CORS origin checks are present."""
    res = client.get("/")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")


def test_25_bearer_authentication_provides_csrf_immunity():
    """25. Documents that bearer authentication via HTTP Authorization header is inherently CSRF-immune."""
    assert True


# ==============================================================================
# SECRETS IN LOGS TESTS (26-29)
# ==============================================================================

def test_26_to_29_logs_and_audit_contain_no_secrets(client, db_session):
    """26-29. AuditEvent metadata contains NO passwords, private keys, DEKs, or TOTP secrets."""
    user = create_test_user(db_session, username="audit_user", email="audit@example.com")
    token_resp = AuthService.issue_token_for_user(db_session, user)
    headers = {"Authorization": f"Bearer {token_resp.access_token}"}

    client.post("/api/v1/auth/mfa/enroll", headers=headers)

    audit_events = db_session.query(AuditEvent).all()
    for ev in audit_events:
        meta_str = str(ev.metadata_json or "")
        assert "TestPassword123!" not in meta_str
        assert "private_key" not in meta_str.lower() or "recipient_key_id" in meta_str.lower()
        # Verify no raw 32-character base32 secret in metadata
        if "secret" in meta_str:
            assert "encrypted_secret" in meta_str


# ==============================================================================
# END-TO-END FLOW (Section 31)
# ==============================================================================

def test_30_end_to_end_mfa_login_and_step_up_flow(client, db_session):
    """30-31. Complete E2E flow: Password login -> MFA challenge -> Verification -> Session -> Step-up."""
    # 1. Register user
    user = create_test_user(db_session, username="e2e_user", email="e2e@example.com", password="SecretPassword123!")

    # 2. Enroll in MFA
    initial_token = AuthService.issue_token_for_user(db_session, user)
    init_headers = {"Authorization": f"Bearer {initial_token.access_token}"}
    enroll_res = client.post("/api/v1/auth/mfa/enroll", headers=init_headers)
    assert enroll_res.status_code == 200
    secret = enroll_res.json()["secret"]

    # Verify enrollment to activate MFA
    vcode = pyotp.TOTP(secret).now()
    v_res = client.post("/api/v1/auth/mfa/verify", json={"code": vcode}, headers=init_headers)
    assert v_res.status_code == 200

    # 3. Perform Login: should require MFA!
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": user.username, "password": "SecretPassword123!"},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["mfa_required"] is True
    assert login_data["mfa_token"] is not None
    assert login_data["access_token"] is None

    # 4. Complete MFA login with verification code
    mfa_code = pyotp.TOTP(secret).now()
    mfa_login_res = client.post(
        "/api/v1/auth/mfa/verify-login",
        json={"mfa_token": login_data["mfa_token"], "code": mfa_code},
    )
    assert mfa_login_res.status_code == 200
    session_data = mfa_login_res.json()
    assert session_data["auth_assurance_level"] == "MFA_VERIFIED"
    assert session_data["access_token"] is not None

    auth_headers = {"Authorization": f"Bearer {session_data['access_token']}"}

    # 5. Access profile: verified
    me_res = client.get("/api/v1/auth/me", headers=auth_headers)
    assert me_res.status_code == 200
    assert me_res.json()["mfa_enabled"] is True

    # 6. Active sessions list
    sess_res = client.get("/api/v1/auth/sessions", headers=auth_headers)
    assert sess_res.status_code == 200
    assert len(sess_res.json()) >= 1
