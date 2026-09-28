import base64
import io
import pytest
from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.decryption_session import DecryptionSession
from app.models.audit_event import AuditEvent
from app.services.user_service import UserService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token
from app.services.document_storage_service import DocumentStorageService


@pytest.fixture
def auth_suite(db_session):
    admin = UserService.create_user(
        db=db_session,
        username="phase5_admin",
        email="p5_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="phase5_officer",
        email="p5_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient_a = UserService.create_user(
        db=db_session,
        username="phase5_recipient_a",
        email="p5_recipient_a@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    recipient_b = UserService.create_user(
        db=db_session,
        username="phase5_recipient_b",
        email="p5_recipient_b@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="phase5_auditor",
        email="p5_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )

    # Provision active ML-KEM-768 keys for both recipients
    key_a = RecipientKeyManager.provision_recipient_key(db_session, recipient_a, admin)
    key_b = RecipientKeyManager.provision_recipient_key(db_session, recipient_b, admin)

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "recipient_a": (recipient_a, create_access_token(recipient_a.id, recipient_a.role), key_a),
        "recipient_b": (recipient_b, create_access_token(recipient_b.id, recipient_b.role), key_b),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
    }


def test_recipient_decryption_success(client, auth_suite, db_session):
    """Officer uploads document for Recipient A. Recipient A successfully decrypts document."""
    _, officer_token = auth_suite["officer"]
    rec_a, rec_a_token, _ = auth_suite["recipient_a"]

    plaintext_payload = b"Top secret operational payload: mission Alpha verified."
    file_bytes = io.BytesIO(plaintext_payload)

    # Upload and encrypt document once for Recipient A
    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={
            "title": "Alpha Operations Document",
            "classification": "TOP_SECRET",
            "recipient_ids": rec_a.id,
        },
        files={"file": ("alpha_ops.txt", file_bytes, "text/plain")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # Recipient A decrypts document
    decrypt_res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_a_token}"},
    )
    assert decrypt_res.status_code == 200
    res_data = decrypt_res.json()

    assert res_data["document_id"] == doc_id
    assert res_data["status"] == "COMPLETED"
    assert res_data["original_filename"] == "alpha_ops.txt"
    assert res_data["mime_type"] == "text/plain"
    assert res_data["original_size_bytes"] == len(plaintext_payload)

    # Decode and verify recovered plaintext
    recovered_bytes = base64.b64decode(res_data["plaintext_base64"])
    assert recovered_bytes == plaintext_payload

    # Verify database session state
    session = db_session.query(DecryptionSession).filter(DecryptionSession.id == res_data["session_id"]).first()
    assert session is not None
    assert session.status == "COMPLETED"
    assert session.user_id == rec_a.id
    assert session.started_at is not None
    assert session.authorized_at is not None
    assert session.completed_at is not None

    # Verify audit events
    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.document_id == doc_id)
        .all()
    )
    event_types = [e.event_type for e in events]
    assert "DOCUMENT_DECRYPTION_REQUESTED" in event_types
    assert "DOCUMENT_DECRYPTION_AUTHORIZED" in event_types
    assert "DOCUMENT_DECRYPTION_COMPLETED" in event_types


def test_unauthenticated_decrypt_returns_401(client, auth_suite):
    """Unauthenticated requests must be rejected with 401 Unauthorized."""
    res = client.post("/api/v1/documents/any-id/decrypt")
    assert res.status_code == 401


def get_error_message(res):
    data = res.json()
    if "error" in data and "message" in data["error"]:
        return data["error"]["message"].lower()
    if "detail" in data:
        return str(data["detail"]).lower()
    return str(data).lower()


def test_unassigned_recipient_cannot_decrypt(client, auth_suite, db_session):
    """User who is a valid RECIPIENT but not assigned to this document cannot decrypt."""
    _, officer_token = auth_suite["officer"]
    rec_a, _, _ = auth_suite["recipient_a"]
    rec_b, rec_b_token, _ = auth_suite["recipient_b"]

    # Upload document distributed ONLY to recipient A
    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={"title": "Exclusive Doc for A", "recipient_ids": rec_a.id},
        files={"file": ("exclusive.txt", io.BytesIO(b"Exclusive to A"), "text/plain")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # Recipient B attempts decryption
    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_b_token}"},
    )
    assert res.status_code == 403
    assert "not an authorized active recipient" in get_error_message(res)

    # Verify denial audit event recorded
    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.document_id == doc_id, AuditEvent.event_type == "DOCUMENT_DECRYPTION_DENIED")
        .all()
    )
    assert len(events) >= 1
    assert events[0].metadata_json["reason_code"] == "NOT_DOCUMENT_RECIPIENT"


def test_admin_cannot_bypass_recipient_authorization(client, auth_suite):
    """ADMIN role must NOT automatically bypass recipient authorization without explicit assignment."""
    _, officer_token = auth_suite["officer"]
    _, admin_token = auth_suite["admin"]
    rec_a, _, _ = auth_suite["recipient_a"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={"title": "No Admin Bypass Doc", "recipient_ids": rec_a.id},
        files={"file": ("classified.txt", io.BytesIO(b"Classified data"), "text/plain")},
    )
    doc_id = upload_res.json()["id"]

    # Admin attempts to decrypt document
    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 403
    assert "not an authorized active recipient" in get_error_message(res)


def test_auditor_cannot_decrypt(client, auth_suite):
    """AUDITOR role cannot decrypt documents under any circumstances."""
    _, officer_token = auth_suite["officer"]
    _, auditor_token = auth_suite["auditor"]
    rec_a, _, _ = auth_suite["recipient_a"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={"title": "Auditor Test Doc", "recipient_ids": rec_a.id},
        files={"file": ("audit_target.txt", io.BytesIO(b"Auditor cannot view"), "text/plain")},
    )
    doc_id = upload_res.json()["id"]

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert res.status_code == 403


def test_revoked_key_recipient_cannot_decrypt(client, auth_suite, db_session):
    """If a recipient's cryptographic key is revoked, they can no longer decrypt."""
    admin, admin_token = auth_suite["admin"]
    _, officer_token = auth_suite["officer"]
    rec_a, rec_a_token, key_a = auth_suite["recipient_a"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={"title": "Revocation Test Doc", "recipient_ids": rec_a.id},
        files={"file": ("rev_target.txt", io.BytesIO(b"Revoke my key"), "text/plain")},
    )
    doc_id = upload_res.json()["id"]

    # Revoke Recipient A's key
    RecipientKeyManager.revoke_key(db_session, key_a.id, admin)

    # Attempt decryption
    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_a_token}"},
    )
    assert res.status_code == 403
    assert "revoked" in get_error_message(res)


def test_tampered_ciphertext_fails_integrity_check(client, auth_suite, db_session):
    """Tampering with stored ciphertext triggers SHA-256 integrity check failure before decryption."""
    _, officer_token = auth_suite["officer"]
    rec_a, rec_a_token, _ = auth_suite["recipient_a"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={"title": "Tamper Test Doc", "recipient_ids": rec_a.id},
        files={"file": ("tamper.txt", io.BytesIO(b"Original untampered bytes"), "text/plain")},
    )
    doc_id = upload_res.json()["id"]

    # Locate and tamper with ciphertext in storage
    doc = db_session.query(Document).filter(Document.id == doc_id).first()
    storage_path = DocumentStorageService.validate_safe_path(doc.storage_reference)
    with open(storage_path, "wb") as f:
        f.write(b"CORRUPTED_CIPHERTEXT_BYTES_TAMPERED")

    # Attempt decryption
    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_a_token}"},
    )
    assert res.status_code == 400
    assert "integrity verification failed" in get_error_message(res)

    # Verify audit event for integrity check failure
    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.document_id == doc_id, AuditEvent.event_type == "INTEGRITY_CHECK_FAILED")
        .all()
    )
    assert len(events) >= 1


def test_tampered_nonce_fails_aes_gcm_authentication(client, auth_suite, db_session):
    """Tampering with the AES-GCM nonce causes authentication verification failure."""
    _, officer_token = auth_suite["officer"]
    rec_a, rec_a_token, _ = auth_suite["recipient_a"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={"title": "Nonce Tamper Doc", "recipient_ids": rec_a.id},
        files={"file": ("nonce_tamper.txt", io.BytesIO(b"Valid content"), "text/plain")},
    )
    doc_id = upload_res.json()["id"]

    # Tamper with document nonce in DB
    doc = db_session.query(Document).filter(Document.id == doc_id).first()
    doc.nonce = base64.b64encode(b"012345678901").decode("ascii")  # Different 12-byte nonce
    db_session.commit()

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_a_token}"},
    )
    assert res.status_code == 400
    assert "authentication failed" in get_error_message(res)
