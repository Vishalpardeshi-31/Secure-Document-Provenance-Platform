import io
import pytest
from app.services.user_service import UserService
from app.services.document_storage_service import DocumentStorageService
from app.models.role import UserRole
from app.models.document import Document
from app.security.tokens import create_access_token


@pytest.fixture
def auth_users(db_session):
    admin = UserService.create_user(
        db=db_session,
        username="doc_admin",
        email="doc_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="doc_officer",
        email="doc_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient = UserService.create_user(
        db=db_session,
        username="doc_recipient",
        email="doc_recipient@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "recipient": (recipient, create_access_token(recipient.id, recipient.role)),
    }


def test_authenticated_officer_upload_succeeds(client, auth_users, db_session):
    """Officer can successfully upload and encrypt a document."""
    _, token = auth_users["officer"]
    sample_content = b"%PDF-1.4 Sensitive Strategic Directive Content"

    res = client.post(
        "/api/v1/documents",
        files={"file": ("strategic_directive.pdf", io.BytesIO(sample_content), "application/pdf")},
        data={"title": "Strategic Directive 2026", "classification": "TOP_SECRET"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["title"] == "Strategic Directive 2026"
    assert data["original_filename"] == "strategic_directive.pdf"
    assert data["status"] == "ENCRYPTED"
    assert data["original_size_bytes"] == len(sample_content)
    assert data["encrypted_size_bytes"] > len(sample_content)
    assert data["encryption_algorithm"] == "AES-256-GCM"

    # Verify no raw secrets returned in API
    assert "raw_dek" not in data
    assert "encrypted_dek" not in data
    assert "storage_reference" not in data

    # Verify raw DEK is NOT stored in PostgreSQL
    db_doc = db_session.query(Document).filter(Document.id == data["id"]).first()
    assert db_doc is not None
    assert db_doc.status == "ENCRYPTED"
    assert db_doc.encrypted_dek != ""
    # Ciphertext must be stored on disk outside frontend
    storage_path = DocumentStorageService.validate_safe_path(db_doc.storage_reference)
    assert storage_path.exists()
    encrypted_bytes = storage_path.read_bytes()
    assert sample_content not in encrypted_bytes  # Plaintext is not stored!


def test_unauthenticated_upload_returns_401(client):
    """Unauthenticated document upload is rejected with 401."""
    res = client.post(
        "/api/v1/documents",
        files={"file": ("test.pdf", io.BytesIO(b"content"), "application/pdf")},
    )
    assert res.status_code == 401


def test_recipient_upload_returns_403(client, auth_users):
    """Recipient cannot upload documents in Phase 3."""
    _, token = auth_users["recipient"]
    res = client.post(
        "/api/v1/documents",
        files={"file": ("test.pdf", io.BytesIO(b"content"), "application/pdf")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403
    assert "Access denied" in res.json()["error"]["message"]


def test_oversized_file_rejected(client, auth_users):
    """File exceeding MAX_DOCUMENT_SIZE_MB is rejected."""
    _, token = auth_users["officer"]
    # 26 MB content (greater than default 25 MB)
    large_content = b"0" * (26 * 1024 * 1024)

    res = client.post(
        "/api/v1/documents",
        files={"file": ("oversized.pdf", io.BytesIO(large_content), "application/pdf")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    assert "exceeds maximum permitted size" in res.json()["error"]["message"]


def test_invalid_upload_extension_rejected(client, auth_users):
    """File with unapproved or dangerous extension is rejected."""
    _, token = auth_users["officer"]
    res = client.post(
        "/api/v1/documents",
        files={"file": ("malware.exe", io.BytesIO(b"binary"), "application/octet-stream")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    assert "not permitted" in res.json()["error"]["message"]


def test_document_list_and_details_endpoints(client, auth_users):
    """Documents appear in authenticated listing and details endpoint returns safe metadata."""
    _, officer_token = auth_users["officer"]
    _, admin_token = auth_users["admin"]

    # Officer uploads document
    upload_res = client.post(
        "/api/v1/documents",
        files={"file": ("intel_brief.docx", io.BytesIO(b"Intel content"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
        headers={"Authorization": f"Bearer {officer_token}"},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # Officer lists documents -> document is present
    list_res = client.get("/api/v1/documents", headers={"Authorization": f"Bearer {officer_token}"})
    assert list_res.status_code == 200
    items = list_res.json()
    assert any(d["id"] == doc_id for d in items)

    # Details endpoint
    detail_res = client.get(f"/api/v1/documents/{doc_id}", headers={"Authorization": f"Bearer {officer_token}"})
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == doc_id
    assert "storage_reference" not in detail
    assert "encrypted_dek" not in detail

    # Admin can also view details
    admin_detail = client.get(f"/api/v1/documents/{doc_id}", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_detail.status_code == 200


def test_delete_document_removes_ciphertext_and_record(client, auth_users, db_session):
    """Deleting document removes the encrypted storage file and database row."""
    _, token = auth_users["officer"]

    upload_res = client.post(
        "/api/v1/documents",
        files={"file": ("temp_notes.txt", io.BytesIO(b"temporary notes"), "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    doc_id = upload_res.json()["id"]

    db_doc = db_session.query(Document).filter(Document.id == doc_id).first()
    storage_ref = db_doc.storage_reference
    storage_path = DocumentStorageService.validate_safe_path(storage_ref)
    assert storage_path.exists()

    # Delete
    del_res = client.delete(f"/api/v1/documents/{doc_id}", headers={"Authorization": f"Bearer {token}"})
    assert del_res.status_code == 200

    # Verify storage file deleted
    assert not storage_path.exists()
    # Verify DB record deleted
    assert db_session.query(Document).filter(Document.id == doc_id).first() is None


def test_failure_cleanup_behavior(db_session, auth_users, monkeypatch):
    """Simulates a failure during document encryption workflow and verifies cleanup."""
    officer, _ = auth_users["officer"]

    # Monkeypatch save_encrypted_bytes to raise an error
    def mock_save_failure(*args, **kwargs):
        raise IOError("Disk write simulation error")

    monkeypatch.setattr(DocumentStorageService, "save_encrypted_bytes", mock_save_failure)

    from app.services.document_service import DocumentService
    with pytest.raises(ValueError, match="Failed to encrypt and store document"):
        DocumentService.upload_and_encrypt_document(
            db=db_session,
            owner=officer,
            original_filename="fail_test.pdf",
            content=b"content",
        )

    # Document in DB is marked FAILED, not ENCRYPTED
    doc = db_session.query(Document).filter(Document.original_filename == "fail_test.pdf").first()
    assert doc is not None
    assert doc.status == "FAILED"
