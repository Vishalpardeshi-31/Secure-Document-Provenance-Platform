import io
import pytest
from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.services.user_service import UserService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token


@pytest.fixture
def auth_users(db_session):
    admin = UserService.create_user(
        db=db_session,
        username="rec_admin_user",
        email="rec_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="rec_officer_user",
        email="rec_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient = UserService.create_user(
        db=db_session,
        username="rec_user_primary",
        email="rec_user_primary@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "recipient": (recipient, create_access_token(recipient.id, recipient.role)),
    }


def test_admin_can_provision_and_revoke_recipient_key(client, auth_users, db_session):
    """Admin provisions an ML-KEM-768 key for a recipient, checks status, and revokes it."""
    _, admin_token = auth_users["admin"]
    recipient, _ = auth_users["recipient"]

    # 1. Check initial key status
    res = client.get(
        f"/api/v1/recipients/{recipient.id}/key-status",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["has_active_key"] is False

    # 2. Provision key
    res = client.post(
        f"/api/v1/recipients/{recipient.id}/provision-key",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["key_version"] == 1
    assert data["algorithm"] == "ML-KEM-768"
    assert data["status"] == "ACTIVE"

    # Private key must NEVER be in response
    assert "private_key" not in data
    assert "encrypted_private_key" not in data

    # 3. Check status again
    res = client.get(
        f"/api/v1/recipients/{recipient.id}/key-status",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["has_active_key"] is True
    assert res.json()["active_key_version"] == 1

    # 4. Revoke key
    res = client.post(
        f"/api/v1/recipients/{recipient.id}/revoke-key",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "REVOKED"


def test_officer_and_recipient_cannot_provision_keys(client, auth_users):
    """Verifies that non-admin roles cannot provision or revoke cryptographic keys."""
    _, officer_token = auth_users["officer"]
    recipient, recipient_token = auth_users["recipient"]

    # Officer forbidden
    res = client.post(
        f"/api/v1/recipients/{recipient.id}/provision-key",
        headers={"Authorization": f"Bearer {officer_token}"},
    )
    assert res.status_code == 403

    # Recipient forbidden
    res = client.post(
        f"/api/v1/recipients/{recipient.id}/provision-key",
        headers={"Authorization": f"Bearer {recipient_token}"},
    )
    assert res.status_code == 403


def test_officer_upload_with_multiple_recipients_succeeds(client, auth_users, db_session):
    """Verifies that an officer can encrypt a document once and wrap the DEK for multiple recipients."""
    admin, admin_token = auth_users["admin"]
    _, officer_token = auth_users["officer"]
    rec1, rec1_token = auth_users["recipient"]

    # Create second recipient
    rec2 = User(
        username="recipient_two",
        email="rec2@example.com",
        password_hash="argon2id$mockhash",
        role=UserRole.RECIPIENT.value,
        is_active=True,
    )
    db_session.add(rec2)
    db_session.commit()

    # Provision keys for both recipients
    RecipientKeyManager.provision_recipient_key(db_session, rec1, admin)
    RecipientKeyManager.provision_recipient_key(db_session, rec2, admin)

    file_payload = b"Multi-recipient encrypted operational report payload 2026."
    response = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        files={"file": ("operational_brief.pdf", io.BytesIO(file_payload), "application/pdf")},
        data={
            "title": "Multi-Recipient Operational Brief",
            "classification": "CONFIDENTIAL",
            "recipient_ids": f"{rec1.id},{rec2.id}",
        },
    )
    assert response.status_code == 201
    doc_data = response.json()
    assert doc_data["title"] == "Multi-Recipient Operational Brief"
    assert doc_data["status"] == "ENCRYPTED"
    assert doc_data["recipient_count"] == 2

    # Verify recipients in database
    doc_id = doc_data["id"]
    recipients = db_session.query(DocumentRecipient).filter(DocumentRecipient.document_id == doc_id).all()
    assert len(recipients) == 2

    # Verify both recipients received DIFFERENT encapsulated keys and wrapped DEKs
    rec_dict = {r.user_id: r for r in recipients}
    assert rec1.id in rec_dict
    assert rec2.id in rec_dict

    r1_data = rec_dict[rec1.id]
    r2_data = rec_dict[rec2.id]

    assert r1_data.encapsulated_key != ""
    assert r2_data.encapsulated_key != ""
    assert r1_data.encapsulated_key != r2_data.encapsulated_key
    assert r1_data.wrapped_dek != r2_data.wrapped_dek
    assert r1_data.nonce != r2_data.nonce

    # Verify raw DEK and plaintext do NOT appear
    assert file_payload not in r1_data.wrapped_dek.encode()
    assert file_payload not in r2_data.wrapped_dek.encode()


def test_upload_fails_atomically_if_recipient_has_no_key(client, auth_users, db_session):
    """If one recipient has a key and another does NOT, the upload must fail atomically."""
    admin, _ = auth_users["admin"]
    _, officer_token = auth_users["officer"]
    rec1, _ = auth_users["recipient"]

    # Provision key for rec1 only
    RecipientKeyManager.provision_recipient_key(db_session, rec1, admin)

    # Create rec2 with NO key
    rec2 = User(
        username="recipient_nokey",
        email="nokey@example.com",
        password_hash="argon2id$mockhash",
        role=UserRole.RECIPIENT.value,
        is_active=True,
    )
    db_session.add(rec2)
    db_session.commit()

    file_payload = b"Atomic test content."
    response = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        files={"file": ("atomic.pdf", io.BytesIO(file_payload), "application/pdf")},
        data={
            "title": "Atomic Failure Test",
            "recipient_ids": f"{rec1.id},{rec2.id}",
        },
    )
    assert response.status_code == 400
    err_msg = response.json().get("error", {}).get("message") or response.json().get("detail", "")
    assert "no active cryptographic key" in err_msg

    # Verify NO document or recipient records were created
    assert db_session.query(Document).filter(Document.title == "Atomic Failure Test").first() is None
    assert db_session.query(DocumentRecipient).count() == 0


def test_recipient_can_list_only_assigned_documents(client, auth_users, db_session):
    """Verifies that a recipient user can list only documents explicitly distributed to them."""
    admin, _ = auth_users["admin"]
    _, officer_token = auth_users["officer"]
    rec1, rec1_token = auth_users["recipient"]

    RecipientKeyManager.provision_recipient_key(db_session, rec1, admin)

    # 1. Officer uploads Doc A distributed to rec1
    client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        files={"file": ("doc_a.pdf", io.BytesIO(b"Doc A content"), "application/pdf")},
        data={"title": "Shared with Recipient", "recipient_ids": rec1.id},
    )

    # 2. Officer uploads Doc B without rec1
    client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        files={"file": ("doc_b.pdf", io.BytesIO(b"Doc B content"), "application/pdf")},
        data={"title": "Private Officer Doc"},
    )

    # 3. Recipient lists documents: should see Doc A only!
    res = client.get(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {rec1_token}"},
    )
    assert res.status_code == 200
    rec_docs = res.json()
    assert len(rec_docs) == 1
    assert rec_docs[0]["title"] == "Shared with Recipient"

    # 4. Recipient details request for Doc A succeeds
    doc_a_id = rec_docs[0]["id"]
    res_detail = client.get(
        f"/api/v1/documents/{doc_a_id}",
        headers={"Authorization": f"Bearer {rec1_token}"},
    )
    assert res_detail.status_code == 200

    # 5. Raw DEK, KEK, and private keys never leak
    data = res_detail.json()
    assert "encrypted_dek" not in data
    assert "private_key" not in data
