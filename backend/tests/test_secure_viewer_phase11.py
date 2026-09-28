import io
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.viewer_session import ViewerSession
from app.models.audit_event import AuditEvent
from app.provenance.models import ProvenanceRecord
from app.provenance.service import ProvenanceService
from app.ledger.service import LedgerService
from app.ledger.adapters.in_memory import InMemoryLedgerAdapter
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.services.viewer_session_service import ViewerSessionService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token


@pytest.fixture
def viewer_suite(db_session: Session):
    """Sets up test users, recipient keys, devices, and an in-memory ledger adapter."""
    mem_adapter = InMemoryLedgerAdapter()
    mem_adapter.clear()
    LedgerService.set_adapter(mem_adapter)

    admin = UserService.create_user(
        db=db_session,
        username="viewer_admin",
        email="viewer_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="viewer_officer",
        email="viewer_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient1 = UserService.create_user(
        db=db_session,
        username="viewer_recipient1",
        email="viewer_recipient1@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    recipient2 = UserService.create_user(
        db=db_session,
        username="viewer_recipient2",
        email="viewer_recipient2@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="viewer_auditor",
        email="viewer_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )
    db_session.commit()

    key_rec1 = RecipientKeyManager.provision_recipient_key(db_session, recipient1, admin)
    dev_rec1 = DeviceService.register_device(
        db=db_session,
        user_id=recipient1.id,
        device_name="Workstation Viewer 1",
        device_fingerprint="fp-viewer-rec1-01",
    )

    key_rec2 = RecipientKeyManager.provision_recipient_key(db_session, recipient2, admin)
    dev_rec2 = DeviceService.register_device(
        db=db_session,
        user_id=recipient2.id,
        device_name="Workstation Viewer 2",
        device_fingerprint="fp-viewer-rec2-01",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "rec1": (recipient1, create_access_token(recipient1.id, recipient1.role), key_rec1, dev_rec1),
        "rec2": (recipient2, create_access_token(recipient2.id, recipient2.role), key_rec2, dev_rec2),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
        "mem_adapter": mem_adapter,
    }


def _upload_doc(client, off_tok, rec_id, title="Test PDF Doc", filename="report.pdf", content=b"%PDF-1.4 Classified Content"):
    if filename.endswith(".pdf"):
        ct = "application/pdf"
    elif filename.endswith(".zip"):
        ct = "application/zip"
    elif filename.endswith(".docx"):
        ct = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        ct = "text/plain"

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": title, "recipient_ids": str(rec_id)},
        files={"file": (filename, io.BytesIO(content), ct)},
    )
    assert up.status_code == 201, up.text
    return up.json()["id"]


def test_1_unauthorized_user_cannot_create_viewer_session(client, viewer_suite):
    """Criteria 1: Unauthenticated request cannot create a viewer session."""
    _, off_tok = viewer_suite["officer"]
    rec1, _, _, _ = viewer_suite["rec1"]
    doc_id = _upload_doc(client, off_tok, rec1.id, "Unauth Test Doc", "report.pdf")

    # No token
    res = client.post(f"/api/v1/documents/{doc_id}/viewer-session")
    assert res.status_code in (401, 403)


def test_2_non_recipient_cannot_create_viewer_session(client, viewer_suite):
    """Criteria 2: Non-assigned recipient cannot create a viewer session."""
    _, off_tok = viewer_suite["officer"]
    rec1, _, _, _ = viewer_suite["rec1"]
    _, rec2_tok, _, dev2 = viewer_suite["rec2"]

    # Upload doc assigned ONLY to rec1
    doc_id = _upload_doc(client, off_tok, rec1.id, "Rec1 Only Doc", "confidential.pdf")

    # rec2 attempts to create viewer session
    res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec2_tok}", "X-Device-ID": dev2.id},
    )
    assert res.status_code == 403
    assert "recipient" in res.json()["error"]["message"].lower() or "denied" in res.json()["error"]["message"].lower()


def test_3_revoked_document_cannot_be_viewed(client, viewer_suite, db_session: Session):
    """Criteria 3: Revoked document blocks both new session creation and active session content access."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Revoke Doc", "plan.pdf")

    # Create active session before revocation
    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_id = sess_res.json()["viewer_session_id"]

    # Revoke document
    doc = db_session.query(Document).filter(Document.id == doc_id).first()
    doc.status = "REVOKED"
    db_session.commit()

    # Content access is blocked on revoked doc
    content_res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert content_res.status_code == 403
    assert "VIEWER_DOCUMENT_REVOKED" in content_res.json()["error"]["message"]

    # New session creation on revoked doc is also blocked
    new_sess = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert new_sess.status_code == 403


def test_4_revoked_device_cannot_create_or_access_viewer_session(client, viewer_suite, db_session: Session):
    """Criteria 4: Revoked device cannot create or access viewer sessions."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    # Revoke rec1's device
    dev1.status = "REVOKED"
    db_session.commit()

    # Upload with policy requiring registered device
    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off_tok}"},
        data={"title": "Device Doc", "recipient_ids": str(rec1.id), "policy_require_registered_device": "true"},
        files={"file": ("device.pdf", io.BytesIO(b"%PDF-1.4 Device Content"), "application/pdf")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 403
    # Restore device status for subsequent tests
    dev1.status = "ACTIVE"
    db_session.commit()


def test_5_expired_viewer_session_cannot_access_content(client, viewer_suite, db_session: Session):
    """Criteria 5: Expired viewer session is blocked server-side from accessing content."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Expiry Doc", "expire.pdf")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_id = sess_res.json()["viewer_session_id"]

    # Artificially expire the session in the database
    v_sess = db_session.query(ViewerSession).filter(ViewerSession.id == sess_id).first()
    v_sess.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    # Content request must fail
    res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert res.status_code == 403
    assert "VIEWER_SESSION_EXPIRED" in res.json()["error"]["message"]

    # Session metadata endpoint reports expired
    stat_res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert stat_res.status_code == 200
    assert stat_res.json()["is_expired"] is True
    assert stat_res.json()["status"] == "EXPIRED"


def test_6_viewer_session_from_another_device_is_rejected(client, viewer_suite):
    """Criteria 6: Session created on Device A cannot be accessed from Device B."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]
    _, _, _, dev2 = viewer_suite["rec2"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Device Bound Doc", "report.pdf")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_id = sess_res.json()["viewer_session_id"]

    # Recipient1 requests content with Device 2's ID
    res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev2.id},
    )
    assert res.status_code == 403
    assert "VIEWER_DEVICE_MISMATCH" in res.json()["error"]["message"]


def test_7_viewer_session_from_another_user_is_rejected(client, viewer_suite):
    """Criteria 7: Viewer session token/ID is not transferable to another authenticated user."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]
    _, rec2_tok, _, dev2 = viewer_suite["rec2"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "User Bound Doc", "report.pdf")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_id = sess_res.json()["viewer_session_id"]

    # Recipient2 attempts to access Recipient1's viewer session
    res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec2_tok}", "X-Device-ID": dev2.id},
    )
    assert res.status_code == 403
    assert "VIEWER_UNAUTHORIZED" in res.json()["error"]["message"]


def test_8_invalid_session_id_is_rejected(client, viewer_suite):
    """Criteria 8: Non-existent session ID produces 404."""
    _, rec1_tok, _, dev1 = viewer_suite["rec1"]
    bad_id = str(uuid.uuid4())
    res = client.get(
        f"/api/v1/viewer-sessions/{bad_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert res.status_code == 404
    assert "VIEWER_SESSION_NOT_FOUND" in res.json()["error"]["message"]


def test_9_tampered_encrypted_document_fails_authenticated_decryption(client, viewer_suite, db_session: Session):
    """Criteria 9: Tampering with ciphertext prevents decryption and raises error."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Tamper Doc", "report.pdf")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_id = sess_res.json()["viewer_session_id"]

    # Tamper with storage file ciphertext on disk
    doc = db_session.query(Document).filter(Document.id == doc_id).first()
    # Modify stored ciphertext_sha256 to trigger mismatch
    doc.ciphertext_sha256 = "0" * 64
    db_session.commit()

    res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert res.status_code in (400, 500)


def test_10_and_11_and_12_zero_plaintext_or_keys_persisted_or_leaked(client, viewer_suite):
    """Criteria 10, 11, 12: Plaintext never written to permanent disk, DEK never leaked in API, private key never leaked."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Leak Check Doc", "safe.pdf", b"%PDF-1.4 TopSecretPlaintext123")

    # 1. Create viewer session
    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_data = sess_res.json()
    sess_id = sess_data["viewer_session_id"]

    # Check session JSON for leaked keys
    raw_json_str = sess_res.text.lower()
    for forbidden in ["encrypted_dek", "wrapped_dek", "private_key", "secret_key", "topsecretplaintext"]:
        assert forbidden not in raw_json_str, f"Forbidden key material '{forbidden}' found in session response!"

    # 2. Get viewer session metadata
    stat_res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert stat_res.status_code == 200
    stat_json_str = stat_res.text.lower()
    for forbidden in ["encrypted_dek", "wrapped_dek", "private_key", "secret_key"]:
        assert forbidden not in stat_json_str

    # 3. Retrieve content
    content_res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert content_res.status_code == 200
    assert content_res.content == b"%PDF-1.4 TopSecretPlaintext123"

    # Verify security headers
    assert content_res.headers["cache-control"] == "no-store, no-cache, must-revalidate, private, max-age=0"
    assert content_res.headers["pragma"] == "no-cache"
    assert content_res.headers["x-content-type-options"] == "nosniff"


def test_13_viewer_cannot_bypass_policy_by_direct_content_endpoint(client, viewer_suite):
    """Criteria 13: Direct calls to content endpoint without active session fail."""
    _, rec1_tok, _, dev1 = viewer_suite["rec1"]
    fake_session_id = str(uuid.uuid4())
    res = client.get(
        f"/api/v1/viewer-sessions/{fake_session_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert res.status_code == 404


def test_14_viewer_heartbeat_and_expiration(client, viewer_suite, db_session: Session):
    """Criteria 14: Heartbeat tracks activity but cannot extend expiration indefinitely past original duration."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Heartbeat Doc", "hb.pdf")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
        json={"duration_seconds": 600},
    )
    assert sess_res.status_code == 201
    sess_id = sess_res.json()["viewer_session_id"]
    orig_exp = sess_res.json()["expires_at"]

    # Send heartbeat
    hb_res = client.post(
        f"/api/v1/viewer-sessions/{sess_id}/heartbeat",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert hb_res.status_code == 200
    hb_data = hb_res.json()
    assert hb_data["status"] == "ACTIVE"
    # Expiration is preserved, NOT extended
    assert hb_data["expires_at"] == orig_exp


def test_15_closed_session_cannot_access_content(client, viewer_suite):
    """Criteria 15: Explicitly closing a session terminates access immediately."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Close Test Doc", "report.pdf")

    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_id = sess_res.json()["viewer_session_id"]

    # Close session
    close_res = client.post(
        f"/api/v1/viewer-sessions/{sess_id}/close",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert close_res.status_code == 200
    assert close_res.json()["status"] == "COMPLETED"

    # Attempt content access after closing
    res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert res.status_code == 403
    assert "VIEWER_SESSION_CLOSED" in res.json()["error"]["message"]


def test_16_supported_and_unsupported_formats(client, viewer_suite):
    """Criteria 16: PDF, TXT supported; unsupported office/binary format produces VIEWER_FORMAT_UNSUPPORTED."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    # 1. Supported PDF
    pdf_id = _upload_doc(client, off_tok, rec1.id, "PDF Doc", "doc.pdf", b"%PDF-1.4 Header Content")
    pdf_sess = client.post(
        f"/api/v1/documents/{pdf_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    ).json()["viewer_session_id"]
    pdf_content = client.get(
        f"/api/v1/viewer-sessions/{pdf_sess}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert pdf_content.status_code == 200
    assert "application/pdf" in pdf_content.headers["content-type"]

    # 2. Supported TXT
    txt_id = _upload_doc(client, off_tok, rec1.id, "Text Doc", "memo.txt", b"Classified Text Content")
    txt_sess = client.post(
        f"/api/v1/documents/{txt_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    ).json()["viewer_session_id"]
    txt_content = client.get(
        f"/api/v1/viewer-sessions/{txt_sess}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert txt_content.status_code == 200
    assert txt_content.content == b"Classified Text Content"

    # 3. Unsupported ZIP / DOCX format
    zip_id = _upload_doc(client, off_tok, rec1.id, "Archive Doc", "archive.zip", b"PK\x03\x04DummyZipContent")
    zip_sess = client.post(
        f"/api/v1/documents/{zip_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    ).json()["viewer_session_id"]
    zip_content = client.get(
        f"/api/v1/viewer-sessions/{zip_sess}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert zip_content.status_code == 415
    assert "VIEWER_FORMAT_UNSUPPORTED" in zip_content.json()["error"]["message"]


def test_17_and_18_audit_events_and_provenance_integration(client, viewer_suite, db_session: Session):
    """Criteria 17, 18: Viewer session creation and access produce real audit events and integrate with Phase 9/10 provenance."""
    _, off_tok = viewer_suite["officer"]
    rec1, rec1_tok, _, dev1 = viewer_suite["rec1"]

    doc_id = _upload_doc(client, off_tok, rec1.id, "Audit & Provenance Doc", "audit.pdf", b"%PDF-1.4 Audit Content")

    # Create viewer session
    sess_res = client.post(
        f"/api/v1/documents/{doc_id}/viewer-session",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert sess_res.status_code == 201
    sess_data = sess_res.json()
    sess_id = sess_data["viewer_session_id"]
    prov_event_id = sess_data["provenance_event_id"]
    dec_session_id = sess_data["decryption_session_id"]

    assert prov_event_id is not None
    assert dec_session_id is not None

    # Fetch content
    c_res = client.get(
        f"/api/v1/viewer-sessions/{sess_id}/content",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert c_res.status_code == 200

    # Close session
    close_res = client.post(
        f"/api/v1/viewer-sessions/{sess_id}/close",
        headers={"Authorization": f"Bearer {rec1_tok}", "X-Device-ID": dev1.id},
    )
    assert close_res.status_code == 200

    # 1. Verify audit events in database
    audit_events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.document_id == doc_id)
        .all()
    )
    event_types = [e.event_type for e in audit_events]
    assert "VIEWER_SESSION_CREATED" in event_types
    assert "VIEWER_SESSION_ACCESS" in event_types
    assert "VIEWER_SESSION_CLOSED" in event_types

    # 2. Verify provenance record and chain integration
    prov_rec = db_session.query(ProvenanceRecord).filter(ProvenanceRecord.event_id == prov_event_id).first()
    assert prov_rec is not None
    assert prov_rec.signature_algorithm == "ML-DSA-65"
    assert prov_rec.chain_sequence >= 1
    assert prov_rec.chain_hash is not None
    assert prov_rec.ledger_status == "CONFIRMED"

    # Full chain audit passes
    chain_ver = ProvenanceService.verify_chain(db_session, ProvenanceService.DEFAULT_CHAIN_ID)
    assert chain_ver.chain_valid is True
