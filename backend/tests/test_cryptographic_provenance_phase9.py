"""Comprehensive security and cryptographic tests for Phase 9: Real Cryptographic Provenance with ML-DSA-65."""
import io
import base64
import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric import mldsa

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.audit_event import AuditEvent
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token
from app.provenance.service import ProvenanceService
from app.provenance.models import ProvenanceRecord, ProvenanceSigningKey
from app.provenance.verification import ProvenanceVerificationService


@pytest.fixture
def prov_suite(db_session: Session):
    admin = UserService.create_user(
        db=db_session,
        username="prov_admin",
        email="prov_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    admin.can_emergency_decrypt = True

    officer1 = UserService.create_user(
        db=db_session,
        username="prov_officer1",
        email="prov_officer1@agency.gov",
        plain_password="Officer1Password123!",
        role=UserRole.OFFICER,
    )
    officer1.can_emergency_decrypt = True

    officer2 = UserService.create_user(
        db=db_session,
        username="prov_officer2",
        email="prov_officer2@agency.gov",
        plain_password="Officer2Password123!",
        role=UserRole.OFFICER,
    )
    officer2.can_emergency_decrypt = True

    recipient1 = UserService.create_user(
        db=db_session,
        username="prov_rec1",
        email="prov_rec1@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )

    recipient2 = UserService.create_user(
        db=db_session,
        username="prov_rec2",
        email="prov_rec2@agency.gov",
        plain_password="Recipient2Password123!",
        role=UserRole.RECIPIENT,
    )

    auditor = UserService.create_user(
        db=db_session,
        username="prov_auditor",
        email="prov_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )

    db_session.commit()

    key_rec1 = RecipientKeyManager.provision_recipient_key(db_session, recipient1, admin)
    key_rec2 = RecipientKeyManager.provision_recipient_key(db_session, recipient2, admin)

    dev_rec1 = DeviceService.register_device(
        db=db_session,
        user_id=recipient1.id,
        device_name="Rec1 Workstation",
        device_fingerprint="fp-prov-rec1",
    )
    dev_rec2 = DeviceService.register_device(
        db=db_session,
        user_id=recipient2.id,
        device_name="Rec2 Workstation",
        device_fingerprint="fp-prov-rec2",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer1": (officer1, create_access_token(officer1.id, officer1.role)),
        "officer2": (officer2, create_access_token(officer2.id, officer2.role)),
        "rec1": (recipient1, create_access_token(recipient1.id, recipient1.role), key_rec1, dev_rec1),
        "rec2": (recipient2, create_access_token(recipient2.id, recipient2.role), key_rec2, dev_rec2),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
    }


def _upload_doc(client, token, title, recipients=None, content=b"Classified Report for Provenance Testing"):
    data = {"title": title}
    if recipients:
        data["recipient_ids"] = recipients
    return client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {token}"},
        data=data,
        files={"file": (f"{title}.txt", io.BytesIO(content), "text/plain")},
    )


def test_provenance_lifecycle_signing_and_verification(client, prov_suite):
    """Section 1, 2, 9, 17: Successful decryption creates a real ML-DSA-65 signed provenance record that verifies."""
    _, off1_tok = prov_suite["officer1"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]

    up = _upload_doc(client, off1_tok, "Provenance Test Doc", [rec1.id])
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Execute normal decryption
    dec = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert dec.status_code == 200

    # Query provenance records for document
    prov_res = client.get(
        f"/api/v1/documents/{doc_id}/provenance",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert prov_res.status_code == 200
    records = prov_res.json()
    assert len(records) >= 1

    rec = records[0]
    event_id = rec["event_id"]
    assert rec["document_id"] == doc_id
    assert rec["user_id"] == rec1.id
    assert rec["signature_algorithm"] == "ML-DSA-65"
    assert rec["access_type"] == "NORMAL"
    assert rec["signature"] is not None
    assert rec["canonical_record_hash"] is not None

    # Cryptographically verify the provenance record via the API
    verify_res = client.post(
        f"/api/v1/provenance/{event_id}/verify",
        headers={"Authorization": f"Bearer {rec1_tok}"},
    )
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["event_id"] == event_id
    assert v_data["hash_valid"] is True
    assert v_data["signature_valid"] is True
    assert v_data["verified"] is True
    assert v_data["signing_key_version"] >= 1


def test_tampering_any_field_fails_verification(client, prov_suite, db_session: Session):
    """Section 18: Tampering with ANY signed field must cause cryptographic verification failure."""
    _, off1_tok = prov_suite["officer1"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]

    up = _upload_doc(client, off1_tok, "Tamper Resistance Doc", [rec1.id])
    doc_id = up.json()["id"]

    dec = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert dec.status_code == 200

    # Retrieve record from DB
    record = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()
    assert record is not None

    # Baseline: verify clean record passes
    clean_ver = ProvenanceVerificationService.verify_record(db_session, record)
    assert clean_ver["verified"] is True

    # Test tampering each critical field individually
    fields_to_tamper = [
        ("document_id", "00000000-0000-0000-0000-000000000000"),
        ("document_version_id", "version-tampered-999"),
        ("user_id", "00000000-0000-0000-0000-000000000001"),
        ("recipient_key_version", 999),
        ("device_id", "tampered-device-id"),
        ("policy_id", "tampered-policy-id"),
        ("policy_version", 99),
        ("access_type", "EMERGENCY"),
        ("event_timestamp", "2030-01-01T00:00:00Z"),
        ("document_plaintext_sha256", "0" * 64),
        ("document_ciphertext_sha256", "f" * 64),
    ]

    for field_name, tampered_val in fields_to_tamper:
        original_val = getattr(record, field_name)
        setattr(record, field_name, tampered_val)

        ver_result = ProvenanceVerificationService.verify_record(db_session, record)
        assert ver_result["verified"] is False, f"Tampering {field_name} did not fail verification!"
        assert (ver_result["hash_valid"] is False or ver_result["signature_valid"] is False)

        # Restore original value for next iteration
        setattr(record, field_name, original_val)


def test_signature_corruption_fails_verification(client, prov_suite, db_session: Session):
    """Section 24: Modifying one byte of the ML-DSA signature causes verification failure."""
    _, off1_tok = prov_suite["officer1"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]

    up = _upload_doc(client, off1_tok, "Sig Corrupt Doc", [rec1.id])
    doc_id = up.json()["id"]

    dec = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert dec.status_code == 200

    record = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()
    raw_sig = bytearray(base64.b64decode(record.signature))

    # Corrupt a byte in the middle of the ML-DSA signature
    raw_sig[100] ^= 0xFF
    record.signature = base64.b64encode(raw_sig).decode("ascii")

    ver_res = ProvenanceVerificationService.verify_record(db_session, record)
    assert ver_res["hash_valid"] is True  # Canonical record hash is unchanged
    assert ver_res["signature_valid"] is False  # Signature verification MUST fail
    assert ver_res["verified"] is False


def test_public_key_mismatch_fails_verification(client, prov_suite, db_session: Session):
    """Section 24: Attempting verification using another signing key fails."""
    _, off1_tok = prov_suite["officer1"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]

    up = _upload_doc(client, off1_tok, "Key Mismatch Doc", [rec1.id])
    doc_id = up.json()["id"]

    client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )

    record = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()

    # Generate an independent ML-DSA-65 key pair to simulate an attacker's key
    attacker_priv = mldsa.MLDSA65PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    attacker_pub_pem = attacker_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    ver_res = ProvenanceVerificationService.verify_record(
        db=db_session,
        record=record,
        override_public_key_pem=attacker_pub_pem,
    )
    assert ver_res["signature_valid"] is False
    assert ver_res["verified"] is False


def test_key_rotation_and_historical_verifiability(client, prov_suite, db_session: Session):
    """Section 8 & 23: Rotating the signing key preserves historical verifiability while new events use v2."""
    admin, admin_tok = prov_suite["admin"]
    _, off1_tok = prov_suite["officer1"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]

    # 1. Decrypt Doc 1 with Key v1
    up1 = _upload_doc(client, off1_tok, "Doc Key v1", [rec1.id])
    doc1_id = up1.json()["id"]
    client.post(
        f"/api/v1/documents/{doc1_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )

    rec1_model = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc1_id).first()
    assert rec1_model.signature_key_version == 1

    # Verify Doc 1 record
    v1_check = ProvenanceVerificationService.verify_record(db_session, rec1_model)
    assert v1_check["verified"] is True
    assert v1_check["signing_key_version"] == 1

    # 2. Administratively rotate signing key via API (Section 23)
    rot_res = client.post(
        "/api/v1/provenance/keys/rotate",
        headers={"Authorization": f"Bearer {admin_tok}"},
    )
    assert rot_res.status_code == 200
    rot_data = rot_res.json()
    assert rot_data["key_version"] == 2
    assert rot_data["status"] == "ACTIVE"

    # 3. Decrypt Doc 2 with newly active Key v2
    up2 = _upload_doc(client, off1_tok, "Doc Key v2", [rec1.id])
    doc2_id = up2.json()["id"]
    client.post(
        f"/api/v1/documents/{doc2_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )

    rec2_model = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc2_id).first()
    assert rec2_model.signature_key_version == 2

    # Verify Doc 2 record with v2
    v2_check = ProvenanceVerificationService.verify_record(db_session, rec2_model)
    assert v2_check["verified"] is True
    assert v2_check["signing_key_version"] == 2

    # 4. Crucial: Old historical Doc 1 record MUST STILL VERIFY with historical key v1
    v1_recheck = ProvenanceVerificationService.verify_record(db_session, rec1_model)
    assert v1_recheck["verified"] is True
    assert v1_recheck["signing_key_version"] == 1


def test_provenance_access_types_normal_multiparty_emergency(client, prov_suite, db_session: Session):
    """Section 13 & 14: Provenance correctly distinguishes NORMAL, MULTI_PARTY_APPROVED, and EMERGENCY."""
    _, off1_tok = prov_suite["officer1"]
    _, off2_tok = prov_suite["officer2"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]

    # --- 1. NORMAL ACCESS ---
    up_norm = _upload_doc(client, off1_tok, "Doc Normal Access", [rec1.id])
    doc_norm_id = up_norm.json()["id"]
    client.post(
        f"/api/v1/documents/{doc_norm_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    p_norm = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_norm_id).first()
    assert p_norm.access_type == "NORMAL"
    assert p_norm.approval_request_id is None
    assert p_norm.emergency_access_request_id is None
    assert ProvenanceVerificationService.verify_record(db_session, p_norm)["verified"] is True

    # --- 2. MULTI-PARTY APPROVED ACCESS ---
    up_mpa = _upload_doc(client, off1_tok, "Doc MPA Access", [rec1.id])
    doc_mpa_id = up_mpa.json()["id"]
    client.put(
        f"/api/v1/documents/{doc_mpa_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={
            "require_multi_party_approval": True,
            "required_approvals": 2,
            "eligible_approver_roles": ["OFFICER", "ADMIN"],
        },
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_mpa_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    mpa_req_id = req_res.json()["id"]
    client.post(f"/api/v1/decryption-requests/{mpa_req_id}/approve", headers={"Authorization": f"Bearer {off1_tok}"})
    client.post(f"/api/v1/decryption-requests/{mpa_req_id}/approve", headers={"Authorization": f"Bearer {off2_tok}"})

    client.post(
        f"/api/v1/documents/{doc_mpa_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
        json={"approval_request_id": mpa_req_id},
    )
    p_mpa = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_mpa_id).first()
    assert p_mpa.access_type == "MULTI_PARTY_APPROVED"
    assert p_mpa.approval_request_id == mpa_req_id
    assert p_mpa.emergency_access_request_id is None
    assert ProvenanceVerificationService.verify_record(db_session, p_mpa)["verified"] is True

    # --- 3. EMERGENCY BREAK-GLASS ACCESS ---
    admin, admin_tok = prov_suite["admin"]
    up_emerg = _upload_doc(client, off1_tok, "Doc Emerg Access")
    doc_emerg_id = up_emerg.json()["id"]
    client.put(
        f"/api/v1/documents/{doc_emerg_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    em_req = client.post(
        f"/api/v1/documents/{doc_emerg_id}/emergency-requests",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"reason": "Critical emergency incident investigation.", "requested_duration_minutes": 15},
    )
    emerg_id = em_req.json()["id"]
    # Independent officer approves
    client.post(f"/api/v1/emergency-requests/{emerg_id}/approve", headers={"Authorization": f"Bearer {off1_tok}"})

    # Admin executes emergency decryption
    em_res = client.post(
        f"/api/v1/documents/{doc_emerg_id}/emergency-decrypt",
        headers={"Authorization": f"Bearer {admin_tok}"},
        json={"emergency_request_id": emerg_id},
    )
    assert em_res.status_code == 200, f"Emergency decrypt failed: {em_res.status_code} {em_res.text}"
    p_em = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_emerg_id).first()
    assert p_em.access_type == "EMERGENCY"
    assert p_em.emergency_access_request_id == emerg_id
    assert p_em.approval_request_id is None
    assert ProvenanceVerificationService.verify_record(db_session, p_em)["verified"] is True


def test_failed_decryption_does_not_create_provenance(client, prov_suite, db_session: Session):
    """Section 10 & 24: Failed decryption attempts must NEVER generate a successful provenance record."""
    _, off1_tok = prov_suite["officer1"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]
    rec2, rec2_tok, _, dev2 = prov_suite["rec2"]

    # Upload document assigned ONLY to rec1
    up = _upload_doc(client, off1_tok, "Unauthorized Access Doc", [rec1.id])
    doc_id = up.json()["id"]

    count_before = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).count()
    assert count_before == 0

    # rec2 attempts decryption without authorization
    dec_fail = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec2_tok}", "X-Device-ID": dev2.id},
    )
    assert dec_fail.status_code == 403

    count_after = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).count()
    assert count_after == 0, "Failed decryption created a provenance record!"


def test_provenance_access_control_and_auditor_verification(client, prov_suite, db_session: Session):
    """Section 16 & 20: Auditor can inspect and verify provenance without decrypting; recipients isolated."""
    _, off1_tok = prov_suite["officer1"]
    rec1, rec1_tok, _, dev1 = prov_suite["rec1"]
    _, rec2_tok, _, _ = prov_suite["rec2"]
    _, aud_tok = prov_suite["auditor"]

    up = _upload_doc(client, off1_tok, "Auditor Provenance Doc", [rec1.id])
    doc_id = up.json()["id"]

    client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )

    record = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.document_id == doc_id).first()

    # rec2 (unrelated user) attempts to inspect provenance -> gets empty list or forbidden
    unauth_list = client.get(
        f"/api/v1/documents/{doc_id}/provenance",
        headers={"Authorization": f"Bearer {rec2_tok}"},
    )
    assert len(unauth_list.json()) == 0

    unauth_single = client.get(
        f"/api/v1/provenance/{record.event_id}",
        headers={"Authorization": f"Bearer {rec2_tok}"},
    )
    assert unauth_single.status_code == 403

    # Auditor inspects provenance
    aud_res = client.get(
        f"/api/v1/documents/{doc_id}/provenance",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert aud_res.status_code == 200
    assert len(aud_res.json()) >= 1

    # Auditor cryptographically verifies provenance
    aud_ver = client.post(
        f"/api/v1/provenance/{record.event_id}/verify",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert aud_ver.status_code == 200
    assert aud_ver.json()["verified"] is True

    # Audit event PROVENANCE_VERIFIED is generated
    audit_evt = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "PROVENANCE_VERIFIED")
        .order_by(AuditEvent.timestamp.desc())
        .first()
    )
    assert audit_evt is not None
    assert audit_evt.metadata_json["event_id"] == record.event_id
    assert audit_evt.metadata_json["verified"] is True
