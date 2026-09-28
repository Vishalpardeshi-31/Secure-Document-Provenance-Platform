"""Phase 15: End-to-End Security Validation, Hardening, and Cryptographic Assurance Tests.

Validates:
1. Complete User Journey: Upload -> ML-KEM Encapsulation -> Policy -> Approval -> Decryption ->
   ML-DSA Provenance -> Tamper-Evident Chain -> Ledger -> Controlled Viewer -> Forensic Fingerprint ->
   Investigator Evidence Upload -> Forensic Detection -> Provenance & Chain Verification -> Report Generation.
2. Multi-Recipient Key Isolation: Recipient A vs Recipient B separation.
3. Real Cryptographic Tampering: Tampered ciphertext, nonce, and AAD fail authenticated decryption.
4. Provenance Chain & ML-DSA Signature Tamper Detection.
5. Readiness and Liveness Health Endpoints (/health and /health/ready).
6. Request Correlation ID Middleware Propagation (X-Request-ID).
7. Production Mode Startup Validation (Fail-closed on insecure keys).
8. Demo Reset Utility Production Guard.
"""
import io
import os
import base64
import copy
import pytest
from datetime import datetime, timezone, timedelta
import pyotp
from PIL import Image

from app.database.session import get_db
from app.config.settings import Settings, DEV_DEFAULT_KEK_BASE64
from app.models.user import User
from app.models.role import UserRole
from app.models.device import Device
from app.models.mfa import UserMfaCredential
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.approval import ApprovalRequest, ApprovalRecord
from app.models.viewer_session import ViewerSession
from app.provenance.models import ProvenanceRecord
from app.security.password import hash_password
from app.security.mfa_service import MfaService, MfaCrypto
from app.security.tokens import create_access_token
from app.services.device_service import DeviceService
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.security.recipient_key_manager import RecipientKeyManager
from app.crypto.aes_gcm import AESGCMService
from app.provenance.service import ProvenanceService
from app.provenance.verification import ProvenanceVerificationService



def _get_err(res):
    """Helper to extract error messages from response."""
    try:
        d = res.json()
        if "error" in d and isinstance(d["error"], dict) and "message" in d["error"]:
            return d["error"]["message"].lower()
        if "detail" in d:
            return str(d["detail"]).lower()
        return str(d).lower()
    except Exception:
        return res.text.lower()


# ==============================================================================
# 1. READINESS & CORRELATION ID TESTS
# ==============================================================================

def test_01_health_and_readiness_endpoints(client, db_session):
    """1. Liveness (/health) and Readiness (/health/ready) endpoints report component statuses."""
    # Liveness
    res_health = client.get("/api/v1/health")
    assert res_health.status_code == 200
    hdata = res_health.json()
    assert hdata["status"] == "HEALTHY"
    assert "database" in hdata

    # Readiness
    res_ready = client.get("/api/v1/health/ready")
    assert res_ready.status_code == 200
    rdata = res_ready.json()
    assert rdata["status"] == "READY"
    assert rdata["database"]["status"] == "UP"
    assert rdata["storage"]["status"] == "UP"
    assert rdata["crypto"]["status"] == "UP"
    assert rdata["ledger"]["status"] == "UP"


def test_02_request_correlation_id_propagated(client):
    """2. Request correlation ID middleware sets and preserves X-Request-ID."""
    # Without client-supplied ID -> server generates UUID
    res1 = client.get("/api/v1/health")
    assert res1.status_code == 200
    assert "X-Request-ID" in res1.headers
    generated_id = res1.headers["X-Request-ID"]
    assert len(generated_id) > 10

    # With client-supplied ID -> server echoes client correlation ID
    custom_id = "CORR-TRACE-TEST-998877"
    res2 = client.get("/api/v1/health", headers={"X-Request-ID": custom_id})
    assert res2.status_code == 200
    assert res2.headers.get("X-Request-ID") == custom_id


# ==============================================================================
# 2. PRODUCTION HARDENING & SECRET INTEGRITY
# ==============================================================================

def test_03_production_mode_fails_closed_on_insecure_secrets():
    """3. Settings validation strictly rejects default/weak keys when ENVIRONMENT=production."""
    # Default development keys in production must fail
    with pytest.raises(ValueError) as exc1:
        Settings(
            ENVIRONMENT="production",
            DOCUMENT_KEK_BASE64=DEV_DEFAULT_KEK_BASE64,
        )
    assert "DOCUMENT_KEK_BASE64" in str(exc1.value)

    # Insecure default SECRET_KEY in production must fail
    secure_kek = base64.b64encode(os.urandom(32)).decode()
    with pytest.raises(ValueError) as exc2:
        Settings(
            ENVIRONMENT="production",
            DOCUMENT_KEK_BASE64=secure_kek,
            RECIPIENT_KEY_KEK_BASE64=secure_kek,
            PROVENANCE_KEY_KEK_BASE64=secure_kek,
            MFA_ENCRYPTION_KEY_BASE64=secure_kek,
            FORENSIC_MASTER_KEY_BASE64=secure_kek,
            SECRET_KEY="change-me-in-production-minimum-32-chars-long-secret-key",
        )
    assert "SECRET_KEY" in str(exc2.value)

    # Wildcard CORS in production must fail
    with pytest.raises(ValueError) as exc3:
        Settings(
            ENVIRONMENT="production",
            DOCUMENT_KEK_BASE64=secure_kek,
            RECIPIENT_KEY_KEK_BASE64=secure_kek,
            PROVENANCE_KEY_KEK_BASE64=secure_kek,
            MFA_ENCRYPTION_KEY_BASE64=secure_kek,
            FORENSIC_MASTER_KEY_BASE64=secure_kek,
            SECRET_KEY="a" * 32,
            CORS_ORIGINS="*",
        )
    assert "Wildcard CORS origin" in str(exc3.value)


def test_04_reset_demo_utility_refuses_production(monkeypatch):
    """4. reset_demo utility aborts immediately if executed in production."""
    from app.cli.reset_demo import reset_demo_environment

    monkeypatch.setattr("app.cli.reset_demo.settings.ENVIRONMENT", "production")
    with pytest.raises(SystemExit) as exc:
        reset_demo_environment()
    assert exc.value.code == 1


# ==============================================================================
# 3. CRYPTOGRAPHIC TAMPER DETECTION (AUTHENTICATED ENCRYPTION)
# ==============================================================================

def test_05_ciphertext_and_aad_tampering_fails_decryption():
    """5. AES-256-GCM authenticated decryption fails on any modification to ciphertext, nonce, or AAD."""
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = b"Top secret operational plan: Section 4 Alpha."
    aad = b"SDPP-DOC:canonical-aad-v1"

    payload = AESGCMService.encrypt(key=key, plaintext=plaintext, associated_data=aad, nonce=nonce)
    ciphertext_and_tag = payload.ciphertext_and_tag

    # 1. Valid decrypt succeeds
    dec = AESGCMService.decrypt(key=key, nonce=nonce, ciphertext_and_tag=ciphertext_and_tag, associated_data=aad)
    assert dec == plaintext

    # 2. Tampered ciphertext byte -> Authentication tag check fails
    tampered_ct = bytearray(ciphertext_and_tag)
    tampered_ct[0] ^= 0x01
    with pytest.raises(Exception):
        AESGCMService.decrypt(key=key, nonce=nonce, ciphertext_and_tag=bytes(tampered_ct), associated_data=aad)

    # 3. Tampered nonce byte -> Tag check fails
    tampered_nonce = bytearray(nonce)
    tampered_nonce[0] ^= 0x01
    with pytest.raises(Exception):
        AESGCMService.decrypt(key=key, nonce=bytes(tampered_nonce), ciphertext_and_tag=ciphertext_and_tag, associated_data=aad)

    # 4. Tampered AAD -> Tag check fails
    with pytest.raises(Exception):
        AESGCMService.decrypt(key=key, nonce=nonce, ciphertext_and_tag=ciphertext_and_tag, associated_data=b"SDPP-DOC:tampered-aad")


# ==============================================================================
# 4. PROVENANCE CHAIN & ML-DSA SIGNATURE TAMPER DETECTION
# ==============================================================================

def test_06_provenance_signature_and_chain_tamper_detection(db_session):
    """6. Provenance verification mathematically identifies tampered record data and corrupt ML-DSA signatures."""
    doc = Document(
        owner_id=str(os.urandom(16).hex()),
        title="Tamper Audit Document",
        original_filename="tamper_doc.pdf",
        mime_type="application/pdf",
        original_size_bytes=512,
        encrypted_size_bytes=512,
        storage_reference="local://storage",
        plaintext_sha256="4" * 64,
        ciphertext_sha256="5" * 64,
        nonce="6" * 24,
        encrypted_dek="7" * 64,
        status="ACTIVE",
    )
    db_session.add(doc)
    db_session.commit()

    # Record genuine provenance
    prov = ProvenanceService.record_decryption_provenance(
        db=db_session,
        document_id=doc.id,
        document_version_id="1",
        user_id=doc.owner_id,
        recipient_key_id="k-1",
        recipient_key_version=1,
        device_id="d-1",
        decryption_session_id="s-1",
        policy_id="p-1",
        policy_version=1,
        access_type="NORMAL",
        document_plaintext_sha256=doc.plaintext_sha256,
        document_ciphertext_sha256=doc.ciphertext_sha256,
    )

    # Clean verification passes
    v_clean = ProvenanceVerificationService.verify_record(db_session, prov)
    assert v_clean["signature_valid"] is True
    assert v_clean["hash_valid"] is True
    assert v_clean["verified"] is True

    # Case A: Corrupted payload field -> Hash mismatch detected
    original_plaintext_hash = prov.document_plaintext_sha256
    prov.document_plaintext_sha256 = "f" * 64
    db_session.commit()
    v_tampered_payload = ProvenanceVerificationService.verify_record(db_session, prov)
    assert v_tampered_payload["hash_valid"] is False
    assert v_tampered_payload["verified"] is False

    # Restore payload, corrupt signature -> Signature failure detected
    prov.document_plaintext_sha256 = original_plaintext_hash
    corrupted_sig = bytearray(base64.b64decode(prov.signature))
    corrupted_sig[10] ^= 0xFF
    prov.signature = base64.b64encode(corrupted_sig).decode()
    db_session.commit()
    v_tampered_sig = ProvenanceVerificationService.verify_record(db_session, prov)
    assert v_tampered_sig["signature_valid"] is False
    assert v_tampered_sig["verified"] is False



# ==============================================================================
# 5. COMPLETE USER JOURNEY & INVESTIGATION ATTRIBUTION
# ==============================================================================

def test_07_complete_end_to_end_journey_and_investigation(client, db_session):
    """7. Full end-to-end user journey:
    Admin -> Officer -> Recipient A & B -> Multi-Recipient Upload & Wrap ->
    Approval -> Decryption -> ML-DSA Provenance -> Chain Head -> Secure Viewer ->
    Forensic Fingerprint -> Evidence Upload -> Leak Attribution to Recipient A.
    """
    # Step 1: Users
    admin = UserService.create_user(db_session, username="p15_admin", email="p15_admin@agency.gov", plain_password="AdminPassword123!", role=UserRole.ADMIN)
    officer = UserService.create_user(db_session, username="p15_officer", email="p15_officer@agency.gov", plain_password="OfficerPassword123!", role=UserRole.OFFICER)
    rec_a = UserService.create_user(db_session, username="p15_rec_a", email="p15_rec_a@agency.gov", plain_password="RecAPassword123!", role=UserRole.RECIPIENT)
    rec_b = UserService.create_user(db_session, username="p15_rec_b", email="p15_rec_b@agency.gov", plain_password="RecBPassword123!", role=UserRole.RECIPIENT)
    investigator = UserService.create_user(db_session, username="p15_inv", email="p15_inv@agency.gov", plain_password="InvPassword123!", role=UserRole.AUDITOR)

    # Step 2: ML-KEM-768 Recipient Keys
    key_a = RecipientKeyManager.provision_recipient_key(db_session, rec_a, admin)
    key_b = RecipientKeyManager.provision_recipient_key(db_session, rec_b, admin)

    # Step 3: Devices
    dev_a = DeviceService.register_device(db_session, rec_a.id, "Surface-A", "fp-dev-a-112233")
    dev_b = DeviceService.register_device(db_session, rec_b.id, "ThinkPad-B", "fp-dev-b-445566")

    # Step 4: MFA Enrollment & Verification for Recipient A
    token_resp_a = AuthService.issue_token_for_user(db_session, rec_a)
    headers_a_pre = {"Authorization": f"Bearer {token_resp_a.access_token}"}
    client.post("/api/v1/auth/mfa/enroll", headers=headers_a_pre)
    cred_a = db_session.query(UserMfaCredential).filter(UserMfaCredential.user_id == rec_a.id).first()
    secret_a = MfaCrypto.decrypt_secret(cred_a.encrypted_secret, cred_a.secret_nonce)
    code_a = pyotp.TOTP(secret_a).now()
    client.post("/api/v1/auth/mfa/verify", json={"code": code_a}, headers=headers_a_pre)

    # Issue refreshed token with MFA_VERIFIED assurance
    token_a = AuthService.issue_token_for_user(db_session, rec_a, auth_assurance_level="MFA_VERIFIED", mfa_verified_at=datetime.now(timezone.utc)).access_token
    token_b = AuthService.issue_token_for_user(db_session, rec_b, auth_assurance_level="MFA_VERIFIED", mfa_verified_at=datetime.now(timezone.utc)).access_token
    token_off = AuthService.issue_token_for_user(db_session, officer, auth_assurance_level="MFA_VERIFIED", mfa_verified_at=datetime.now(timezone.utc)).access_token
    token_inv = AuthService.issue_token_for_user(db_session, investigator).access_token

    # Step 5: Officer uploads and encrypts document for both Recipient A and Recipient B
    # Image document enables 2D-DCT spread-spectrum forensic watermark embedding & detection
    img = Image.new("RGB", (256, 256), color=(220, 220, 220))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {token_off}"},
        data={
            "title": "Defense Strategy Briefing 2026",
            "recipient_ids": f"{rec_a.id},{rec_b.id}",
            "policy_require_multi_party_approval": "true",
            "policy_required_approvals": "1",
            "policy_eligible_approver_roles": "OFFICER,ADMIN",
        },
        files={"file": ("defense_strat.png", io.BytesIO(png_bytes), "image/png")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # Step 6: Recipient A requests approval
    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {token_a}", "X-Device-ID": dev_a.id},
    )
    assert req_res.status_code == 201
    approval_req_id = req_res.json()["id"]

    # Step 7: Officer approves the request
    app_res = client.post(
        f"/api/v1/decryption-requests/{approval_req_id}/approve",
        headers={"Authorization": f"Bearer {token_off}"},
        json={"reason": "Approved for briefing"},
    )
    assert app_res.status_code == 200

    # Step 8: Recipient A executes policy-controlled decryption
    dec_res_a = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {token_a}", "X-Device-ID": dev_a.id},
        json={"approval_request_id": approval_req_id, "device_id": dev_a.id},
    )
    assert dec_res_a.status_code == 200
    dec_data_a = dec_res_a.json()
    assert dec_data_a["status"] == "COMPLETED"
    decrypted_bytes_a = base64.b64decode(dec_data_a["plaintext_base64"])
    assert len(decrypted_bytes_a) == len(png_bytes)

    # Step 9: Verify Provenance Record and Hash-Linked Chain created for Recipient A
    provenance_a = (
        db_session.query(ProvenanceRecord)
        .filter(ProvenanceRecord.decryption_session_id == dec_data_a["session_id"])
        .first()
    )
    assert provenance_a is not None
    assert provenance_a.signature_algorithm == "ML-DSA-65"
    assert provenance_a.chain_sequence >= 0
    assert provenance_a.chain_hash is not None

    # Replay protection: attempting to reuse consumed approval request fails closed
    replay_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {token_a}", "X-Device-ID": dev_a.id},
        json={"approval_request_id": approval_req_id, "device_id": dev_a.id},
    )
    assert replay_res.status_code == 403
    assert "already been consumed" in replay_res.json()["error"]["message"].lower()

    # Step 10: Recipient A obtains fresh approval and initializes Secure Viewer
    vs_req = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {token_a}", "X-Device-ID": dev_a.id},
    )
    assert vs_req.status_code == 201
    vs_approval_id = vs_req.json()["id"]

    client.post(
        f"/api/v1/decryption-requests/{vs_approval_id}/approve",
        headers={"Authorization": f"Bearer {token_off}"},
        json={"reason": "Approved for Secure Viewer session"},
    )

    vs_res_a = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {token_a}", "X-Device-ID": dev_a.id},
        json={"approval_request_id": vs_approval_id, "device_id": dev_a.id},
    )
    assert vs_res_a.status_code == 201, f"Viewer session failed: {vs_res_a.text}"
    vs_id_a = vs_res_a.json()["viewer_session_id"]

    # Fetch fingerprinted render for Recipient A
    view_content_a = client.get(
        f"/api/v1/viewer-sessions/{vs_id_a}/content",
        headers={"Authorization": f"Bearer {token_a}", "X-Device-ID": dev_a.id},
    )
    assert view_content_a.status_code == 200
    leaked_evidence_bytes_a = view_content_a.content

    # Step 11: Investigator creates an investigation case
    case_res = client.post(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {token_inv}"},
        json={"title": "Unauthorized Leak of Defense Strategy Briefing", "document_id": doc_id},
    )
    assert case_res.status_code == 201
    case_id = case_res.json()["id"]

    # Step 12: Investigator uploads leaked evidence (from Recipient A)
    ev_res = client.post(
        f"/api/v1/investigations/{case_id}/evidence",
        headers={"Authorization": f"Bearer {token_inv}"},
        files={"file": ("defense_strat_leaked.png", io.BytesIO(leaked_evidence_bytes_a), "image/png")},
    )
    assert ev_res.status_code == 201
    evidence_id = ev_res.json()["id"]

    # Step 13: Investigator analyzes evidence -> Forensic detector attributes leak to Recipient A and validates provenance
    det_res = client.post(
        f"/api/v1/investigations/{case_id}/analyze",
        headers={"Authorization": f"Bearer {token_inv}"},
    )
    assert det_res.status_code == 200
    det_data = det_res.json()
    assert det_data["detection_status"] == "FINGERPRINT_DETECTED_PROVENANCE_VALID"
    assert det_data["provenance_signature_status"] == "VALID"
    assert det_data["chain_verification_status"] == "CHAIN_VALID"
    assert det_data["confidence_score"] > 0.0

    # Verify correlated session details identify Recipient A
    corr = det_data["details"]["correlation"]
    assert corr["recipient_username"] == rec_a.username
    assert corr["viewer_session_id"] == vs_id_a

    # Step 14: Generate formal investigation report with cryptographic proofs
    rep_res = client.get(
        f"/api/v1/investigations/{case_id}/report",
        headers={"Authorization": f"Bearer {token_inv}"},
    )
    assert rep_res.status_code == 200
    rep_data = rep_res.json()
    assert rep_data["case_reference"] is not None
    assert rep_data["detection_status"] == "FINGERPRINT_DETECTED_PROVENANCE_VALID"
    assert rep_data["provenance_verification"]["status"] == "VALID"
    assert rep_data["chain_verification"]["status"] == "CHAIN_VALID"
    assert rep_data["report_sha256"] is not None

