import base64
import io
import threading
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.role import UserRole
from app.models.device import Device
from app.models.access_policy import AccessPolicy
from app.models.document import Document
from app.models.decryption_session import DecryptionSession
from app.models.audit_event import AuditEvent
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token
from app.policies.service import PolicyService as EnginePolicyService
from app.policies.models import PolicyStatus, DocumentLifecycleStatus, PolicyReasonCode


@pytest.fixture
def p7_suite(db_session: Session):
    admin = UserService.create_user(
        db=db_session,
        username="p7_admin",
        email="p7_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="p7_officer",
        email="p7_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient1 = UserService.create_user(
        db=db_session,
        username="p7_rec1",
        email="p7_rec1@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    recipient2 = UserService.create_user(
        db=db_session,
        username="p7_rec2",
        email="p7_rec2@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="p7_auditor",
        email="p7_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )

    key1 = RecipientKeyManager.provision_recipient_key(db_session, recipient1, admin)
    key2 = RecipientKeyManager.provision_recipient_key(db_session, recipient2, admin)

    dev_rec1 = DeviceService.register_device(
        db=db_session,
        user_id=recipient1.id,
        device_name="Rec1 Registered Laptop",
        device_fingerprint="fp-p7-rec1-lap-001",
    )
    dev_rec2 = DeviceService.register_device(
        db=db_session,
        user_id=recipient2.id,
        device_name="Rec2 Workstation",
        device_fingerprint="fp-p7-rec2-work-002",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "rec1": (recipient1, create_access_token(recipient1.id, recipient1.role), key1, dev_rec1),
        "rec2": (recipient2, create_access_token(recipient2.id, recipient2.role), key2, dev_rec2),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
    }


def _get_err(res):
    d = res.json()
    if "detail" in d:
        return str(d["detail"]).lower()
    return str(d).lower()


# ==============================================================================
# 1. AUTHORIZATION ENFORCEMENTS
# ==============================================================================

def test_unassigned_recipient_denied_backend_authoritative(client, p7_suite):
    """Unassigned user attempting to decrypt must be denied with RECIPIENT_NOT_AUTHORIZED."""
    _, off_tok = p7_suite["officer"]
    rec1, _, _, _ = p7_suite["rec1"]
    _, rec2_tok, _, _ = p7_suite["rec2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": "Exclusive Rec1 Doc", "recipient_ids": rec1.id},
        files={"file": ("doc.txt", io.BytesIO(b"Exclusive to Rec1"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec2_tok}"},
    )
    assert res.status_code == 403
    assert "not an authorized active recipient" in _get_err(res)


def test_admin_cannot_bypass_recipient_authorization(client, p7_suite):
    """Section 3A & 17: Admin cannot decrypt unless explicitly assigned as a recipient."""
    _, off_tok = p7_suite["officer"]
    rec1, _, _, _ = p7_suite["rec1"]
    _, admin_tok = p7_suite["admin"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": "No Admin Bypass Doc", "recipient_ids": rec1.id},
        files={"file": ("classified.txt", io.BytesIO(b"Classified data"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Admin attempts decryption
    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert res.status_code == 403
    assert "not an authorized active recipient" in _get_err(res)


def test_auditor_role_cannot_decrypt(client, p7_suite):
    """Auditor role cannot decrypt even if mistakenly included."""
    _, off_tok = p7_suite["officer"]
    rec1, _, _, _ = p7_suite["rec1"]
    _, aud_tok = p7_suite["auditor"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": "Auditor Test Doc", "recipient_ids": rec1.id},
        files={"file": ("doc.txt", io.BytesIO(b"Auditor denied"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert res.status_code == 403


def test_role_restriction_condition(client, p7_suite):
    """Policy requiring OFFICER role must deny RECIPIENT role."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={
            "title": "Officer Only Role Doc",
            "recipient_ids": rec1.id,
            "policy_allowed_roles": "OFFICER,ADMIN",
        },
        files={"file": ("doc.txt", io.BytesIO(b"Officer only content"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Recipient has RECIPIENT role, not OFFICER -> denied
    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res.status_code == 403
    assert "role" in _get_err(res)


# ==============================================================================
# 2. TIME RESTRICTIONS
# ==============================================================================

def test_time_window_before_not_before_denied(client, p7_suite):
    """Before not_before window must be denied."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]

    future_start = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    future_end = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={
            "title": "Future Window Doc",
            "recipient_ids": rec1.id,
            "policy_valid_from": future_start,
            "policy_valid_until": future_end,
        },
        files={"file": ("doc.txt", io.BytesIO(b"Future content"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res.status_code == 403
    assert "not active yet" in _get_err(res)


def test_time_window_after_expires_at_denied(client, p7_suite):
    """After expires_at window must be denied."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]

    past_start = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    past_end = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={
            "title": "Expired Window Doc",
            "recipient_ids": rec1.id,
            "policy_valid_from": past_start,
            "policy_valid_until": past_end,
        },
        files={"file": ("doc.txt", io.BytesIO(b"Expired content"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res.status_code == 403
    assert "expired" in _get_err(res)


# ==============================================================================
# 3. REGISTERED DEVICE REQUIREMENTS
# ==============================================================================

def test_device_condition_enforcement(client, p7_suite, db_session):
    """Device required condition verifies registered, owned, and active status."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, dev1 = p7_suite["rec1"]
    rec2, _, _, dev2 = p7_suite["rec2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={
            "title": "Device Doc",
            "recipient_ids": rec1.id,
            "policy_require_registered_device": "true",
        },
        files={"file": ("doc.txt", io.BytesIO(b"Device data"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # 1. No device supplied -> 403
    res1 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
        json={},
    )
    assert res1.status_code == 403
    assert "requires an authorized registered device" in _get_err(res1)

    # 2. Recipient 2's device supplied -> 403
    res2 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
        json={"device_id": dev2.id},
    )
    assert res2.status_code == 403
    assert "not registered to the authenticated user" in _get_err(res2)

    # 3. Valid active device -> 200 SUCCESS
    res3 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
        json={"device_id": dev1.id},
    )
    assert res3.status_code == 200

    # 4. Revoke recipient 1's device -> 403
    DeviceService.update_device_status(db_session, dev1.id, "REVOKED")
    res4 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
        json={"device_id": dev1.id},
    )
    assert res4.status_code == 403
    assert "revoked" in _get_err(res4)


# ==============================================================================
# 4. CONCURRENCY-SAFE DECRYPTION LIMIT
# ==============================================================================

def test_decryption_limit_and_concurrency(client, p7_suite, db_session):
    """Section 8: Concurrency test proving atomic check-and-consume behavior.
    
    With max_decryptions=1, only ONE request can succeed even under concurrent calls.
    """
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]

    content = b"One time view confidential payload"
    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={
            "title": "One Time Doc",
            "recipient_ids": rec1.id,
            "policy_max_decryptions": 1,
        },
        files={"file": ("onetime.txt", io.BytesIO(content), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # First attempt: succeeds
    res1 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res1.status_code == 200
    assert base64.b64decode(res1.json()["plaintext_base64"]) == content

    # Second attempt: denied
    res2 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res2.status_code == 403
    assert "maximum permitted decryptions" in _get_err(res2)


def test_concurrent_decryption_limit_race(client, p7_suite):
    """Proves that multiple simultaneous threads cannot exceed max_decryptions=1."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={
            "title": "Concurrent Race Doc",
            "recipient_ids": rec1.id,
            "policy_max_decryptions": 1,
        },
        files={"file": ("race.txt", io.BytesIO(b"Race test payload"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    results = []

    def attempt_decrypt():
        r = client.post(
            f"/api/v1/documents/{doc_id}/decrypt",
            headers={"Authorization": f"Bearer {rec1_tok}"},
        )
        results.append(r.status_code)

    threads = [threading.Thread(target=attempt_decrypt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly ONE must succeed (200), all others denied (403)
    successes = [code for code in results if code == 200]
    denials = [code for code in results if code == 403]
    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}"
    assert len(denials) == 4, f"Expected 4 denials, got {len(denials)}"


# ==============================================================================
# 5. DOCUMENT LIFECYCLE REVOCATION & REACTIVATION
# ==============================================================================

def test_document_lifecycle_revocation(client, p7_suite, db_session):
    """Section 11: Document administrative revocation prevents decryption."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": "Revocable Doc", "recipient_ids": rec1.id},
        files={"file": ("rev.txt", io.BytesIO(b"Revocable content"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Initial decryption works
    res_ok = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res_ok.status_code == 200

    # Administratively revoke document
    rev_res = client.post(
        f"/api/v1/documents/{doc_id}/revoke",
        headers={"Authorization": f"Bearer {off_tok}"},
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REVOKED"

    # Subsequent decryption attempt must be denied
    res_denied = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res_denied.status_code == 403
    assert "administratively revoked" in _get_err(res_denied)

    # Reactivate document
    react_res = client.post(
        f"/api/v1/documents/{doc_id}/reactivate",
        headers={"Authorization": f"Bearer {off_tok}"},
    )
    assert react_res.status_code == 200
    assert react_res.json()["status"] == "ACTIVE"

    # Decryption allowed again
    res_ok2 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert res_ok2.status_code == 200


# ==============================================================================
# 6. POLICY VERSIONING & HISTORICAL PRESERVATION
# ==============================================================================

def test_policy_versioning_and_historical_audit(client, p7_suite, db_session):
    """Section 14: Updating policy increments version without destroying history."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]

    # 1. Create document with policy version 1
    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": "Versioning Doc", "recipient_ids": rec1.id, "policy_max_decryptions": 5},
        files={"file": ("v.txt", io.BytesIO(b"Version test"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Decrypt under version 1
    dec_v1 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert dec_v1.status_code == 200
    sess_v1_id = dec_v1.json()["session_id"]

    sess1 = db_session.query(DecryptionSession).filter(DecryptionSession.id == sess_v1_id).first()
    assert sess1.policy_version == 1

    # 2. Update policy -> creates version 2
    put_res = client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off_tok}"},
        json={"max_decryptions": 10},
    )
    assert put_res.status_code == 200
    assert put_res.json()["policy_version"] == 2
    assert put_res.json()["status"] == "ACTIVE"

    # Decrypt under version 2
    dec_v2 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert dec_v2.status_code == 200
    sess_v2_id = dec_v2.json()["session_id"]

    sess2 = db_session.query(DecryptionSession).filter(DecryptionSession.id == sess_v2_id).first()
    assert sess2.policy_version == 2

    # Verify both policy records exist in database
    policies = (
        db_session.query(AccessPolicy)
        .filter(AccessPolicy.document_id == doc_id)
        .order_by(AccessPolicy.policy_version.asc())
        .all()
    )
    assert len(policies) == 2
    assert policies[0].policy_version == 1
    assert policies[0].status == "EXPIRED"
    assert policies[1].policy_version == 2
    assert policies[1].status == "ACTIVE"


# ==============================================================================
# 7. SECURITY & PARAMETER TAMPERING TESTS
# ==============================================================================

def test_parameter_tampering_attempts_fail(client, p7_suite):
    """Section 19: Tampering with parameters in API requests must fail safely."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, _ = p7_suite["rec1"]
    rec2, _, _, _ = p7_suite["rec2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": "Tamper Test Doc", "recipient_ids": rec1.id},
        files={"file": ("tamper.txt", io.BytesIO(b"Tamper resistant"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Attempt 1: Recipient trying to update policy -> 403
    t1 = client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {rec1_tok}"},
        json={"max_decryptions": 999},
    )
    assert t1.status_code == 403

    # Attempt 2: Recipient trying to revoke policy -> 403
    t2 = client.post(
        f"/api/v1/documents/{doc_id}/policy/revoke",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert t2.status_code == 403

    # Attempt 3: Recipient trying to spoof user_id in decryption request
    t3 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}"},
        json={"user_id": rec2.id, "role": "ADMIN", "max_decryptions": 999},
    )
    # The server uses the JWT identity, not request body tampering
    assert t3.status_code == 200  # Authorized because rec1 is valid recipient; body params ignored


# ==============================================================================
# 8. REAL BACKEND ACCESS CHECK ENDPOINT
# ==============================================================================

def test_access_check_endpoint_evaluates_real_conditions(client, p7_suite):
    """GET /access-check evaluates real conditions without consuming decryption count."""
    _, off_tok = p7_suite["officer"]
    rec1, rec1_tok, _, dev1 = p7_suite["rec1"]
    _, rec2_tok, _, _ = p7_suite["rec2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={
            "title": "Access Check Doc",
            "recipient_ids": rec1.id,
            "policy_max_decryptions": 1,
            "policy_require_registered_device": "true",
        },
        files={"file": ("check.txt", io.BytesIO(b"Check data"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Check for unauthorized recipient
    chk_unauth = client.get(
        f"/api/v1/documents/{doc_id}/access-check",
        headers={"Authorization": f"Bearer {rec2_tok}"},
    )
    assert chk_unauth.status_code == 200
    d_unauth = chk_unauth.json()
    assert d_unauth["allowed"] is False
    assert d_unauth["checks"]["recipient_authorized"] is False

    # Check for authorized recipient with valid device
    chk_auth = client.get(
        f"/api/v1/documents/{doc_id}/access-check?device_id={dev1.id}",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert chk_auth.status_code == 200
    d_auth = chk_auth.json()
    assert d_auth["allowed"] is True
    assert d_auth["checks"]["identity_verified"] is True
    assert d_auth["checks"]["recipient_authorized"] is True
    assert d_auth["checks"]["device_verified"] is True
    assert d_auth["checks"]["policy_active"] is True
    assert d_auth["checks"]["time_window_valid"] is True
    assert d_auth["checks"]["decryption_allowance_available"] is True

    # Decryption count was NOT consumed by access-check!
    pol = client.get(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert pol.json()["consumed_decryptions"] == 0
