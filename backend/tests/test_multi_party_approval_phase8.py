import io
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.role import UserRole
from app.models.approval import ApprovalRequest, ApprovalRecord
from app.models.audit_event import AuditEvent
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token
from app.policies.service import PolicyService as EnginePolicyService


@pytest.fixture
def p8_suite(db_session: Session):
    admin = UserService.create_user(
        db=db_session,
        username="p8_admin",
        email="p8_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer1 = UserService.create_user(
        db=db_session,
        username="p8_officer1",
        email="p8_officer1@agency.gov",
        plain_password="Officer1Password123!",
        role=UserRole.OFFICER,
    )
    officer2 = UserService.create_user(
        db=db_session,
        username="p8_officer2",
        email="p8_officer2@agency.gov",
        plain_password="Officer2Password123!",
        role=UserRole.OFFICER,
    )
    recipient = UserService.create_user(
        db=db_session,
        username="p8_recipient",
        email="p8_recipient@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="p8_auditor",
        email="p8_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )

    rec_key = RecipientKeyManager.provision_recipient_key(db_session, recipient, admin)
    dev = DeviceService.register_device(
        db=db_session,
        user_id=recipient.id,
        device_name="Recipient Device",
        device_fingerprint="fp-p8-rec-001",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer1": (officer1, create_access_token(officer1.id, officer1.role)),
        "officer2": (officer2, create_access_token(officer2.id, officer2.role)),
        "recipient": (recipient, create_access_token(recipient.id, recipient.role), rec_key, dev),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
    }


def _get_err(res):
    d = res.json()
    if "detail" in d:
        return str(d["detail"]).lower()
    return str(d).lower()


def test_approval_required_without_approval_fails(client, p8_suite):
    """If policy requires approval, direct decryption without approval must be denied."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    # Upload document with multi-party approval required (2 approvals)
    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Multi-Party Policy Doc", "recipient_ids": rec.id},
        files={"file": ("classified.txt", io.BytesIO(b"Multi-party protected data"), "text/plain")},
    )
    assert up.status_code == 201
    doc_id = up.json()["id"]

    # Configure policy requiring 2 approvals
    pol_res = client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={
            "require_approval": True,
            "require_multi_party_approval": True,
            "required_approvals": 2,
            "eligible_approver_roles": ["OFFICER", "ADMIN"],
        },
    )
    assert pol_res.status_code == 200
    assert pol_res.json()["require_approval"] is True
    assert pol_res.json()["required_approvals"] == 2

    # Direct decryption attempt without approval
    dec_res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    assert dec_res.status_code == 403
    assert "approval" in _get_err(dec_res)


def test_threshold_enforcement_and_successful_decryption(client, p8_suite):
    """1 approval when 2 required -> denied; 2 distinct approvals -> authorized and decrypted."""
    _, off1_tok = p8_suite["officer1"]
    _, off2_tok = p8_suite["officer2"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Threshold Test Doc", "recipient_ids": rec.id},
        files={"file": ("secret.txt", io.BytesIO(b"Top secret multi-party plaintext"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={
            "require_approval": True,
            "require_multi_party_approval": True,
            "required_approvals": 2,
            "eligible_approver_roles": ["OFFICER", "ADMIN"],
        },
    )

    # Recipient requests approval
    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    assert req_res.status_code == 201
    req_data = req_res.json()
    req_id = req_data["id"]
    assert req_data["status"] == "PENDING"
    assert req_data["current_approvals"] == 0
    assert req_data["required_approvals"] == 2

    # Approver 1 approves (1/2)
    app1 = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Approved after reviewing clearance"},
    )
    assert app1.status_code == 200
    assert app1.json()["current_approvals"] == 1
    assert app1.json()["status"] == "PENDING"

    # Attempt decrypt with only 1/2 approvals -> Must FAIL
    dec1 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"approval_request_id": req_id},
    )
    assert dec1.status_code == 403

    # Approver 2 approves (2/2) -> Threshold reached!
    app2 = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off2_tok}"},
        json={"reason": "Second confirmation granted"},
    )
    assert app2.status_code == 200
    assert app2.json()["current_approvals"] == 2
    assert app2.json()["status"] == "APPROVED"

    # Decrypt with approved request -> SUCCESS!
    dec2 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"approval_request_id": req_id},
    )
    assert dec2.status_code == 200
    assert dec2.json()["status"] == "COMPLETED"
    import base64
    pt = base64.b64decode(dec2.json()["plaintext_base64"])
    assert pt == b"Top secret multi-party plaintext"


def test_requester_cannot_approve_own_request(client, p8_suite):
    """Section 4: The requester must NOT be able to approve their own request."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Self Approval Test", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"require_approval": True, "required_approvals": 2},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # Requester attempts to approve their own request
    self_app = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"reason": "Self-approving my own request"},
    )
    assert self_app.status_code == 403
    assert "cannot approve their own request" in _get_err(self_app)


def test_duplicate_approval_by_same_user_prevented(client, p8_suite):
    """Section 5: Alice approving twice must remain 1/2, duplicate approval is rejected."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Duplicate Approval Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"require_approval": True, "required_approvals": 2},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # First approval by officer1
    app1 = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )
    assert app1.status_code == 200
    assert app1.json()["current_approvals"] == 1

    # Second approval attempt by officer1
    app2 = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )
    assert app2.status_code == 400
    assert "already recorded a decision" in _get_err(app2)

    # Verify count is still 1
    status_res = client.get(
        f"/api/v1/decryption-requests/{req_id}",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    assert status_res.json()["current_approvals"] == 1
    assert status_res.json()["status"] == "PENDING"


def test_unauthorized_role_cannot_approve(client, p8_suite):
    """Section 4 & 12: Users with ineligible roles (e.g. AUDITOR or RECIPIENT) cannot approve."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]
    _, aud_tok = p8_suite["auditor"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Role Test Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={
            "require_approval": True,
            "required_approvals": 1,
            "eligible_approver_roles": ["OFFICER", "ADMIN"],
        },
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # Auditor attempts approval
    aud_app = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {aud_tok}"},
    )
    assert aud_app.status_code == 403


def test_rejection_marks_request_rejected_and_prevents_decryption(client, p8_suite):
    """Section 5 & 12: If an approver rejects with a reason, request is REJECTED and cannot authorize decryption."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Rejection Test Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"require_approval": True, "required_approvals": 1},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # Rejection without reason fails
    rej_no_reason = client.post(
        f"/api/v1/decryption-requests/{req_id}/reject",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": ""},
    )
    assert rej_no_reason.status_code in [400, 422]

    # Rejection with reason succeeds
    rej = client.post(
        f"/api/v1/decryption-requests/{req_id}/reject",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Suspected unauthorized access attempt."},
    )
    assert rej.status_code == 200
    assert rej.json()["status"] == "REJECTED"

    # Decrypt attempt must be denied
    dec = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"approval_request_id": req_id},
    )
    assert dec.status_code == 403
    assert "rejected" in _get_err(dec)


def test_cancelled_request_cannot_authorize(client, p8_suite):
    """Section 2: Cancelled approval requests cannot be approved or authorize decryption."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Cancellation Test Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"require_approval": True, "required_approvals": 1},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # Cancel request
    cancel_res = client.post(
        f"/api/v1/decryption-requests/{req_id}/cancel",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # Attempt to approve cancelled request
    app_res = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )
    assert app_res.status_code == 400

    # Attempt decryption with cancelled request
    dec = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"approval_request_id": req_id},
    )
    assert dec.status_code == 403


def test_expired_approval_request_cannot_authorize(client, p8_suite, db_session):
    """Section 6: Expired requests cannot be approved and cannot authorize decryption."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Expiry Test Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"require_approval": True, "required_approvals": 1},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # Artificially expire the request in the database
    db_req = db_session.query(ApprovalRequest).filter(ApprovalRequest.id == req_id).first()
    db_req.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    # Attempt to approve expired request -> Must FAIL
    app_res = client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )
    assert app_res.status_code == 400
    assert "expired" in _get_err(app_res)


def test_policy_re_evaluation_after_approval(client, p8_suite):
    """Section 8: Re-evaluate policy immediately before decryption even if request was APPROVED."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Re-evaluation Test Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"require_approval": True, "required_approvals": 1},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # Approve request
    client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )

    # Now administratively revoke the document
    rev_res = client.post(
        f"/api/v1/documents/{doc_id}/revoke",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )
    assert rev_res.status_code == 200

    # Decrypt attempt must be denied during pre-decryption re-evaluation
    dec = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"approval_request_id": req_id},
    )
    assert dec.status_code == 403
    assert "revoked" in _get_err(dec)


def test_concurrency_race_condition_protection_with_decryption_limit(client, p8_suite):
    """Section 9: With max_decryptions=1, even if two approvals are granted, only one final decryption succeeds."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Concurrency Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Secret concurrency data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={
            "require_approval": True,
            "required_approvals": 1,
            "max_decryptions": 1,
        },
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req_res.json()["id"]

    # Approve request
    client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )

    # First decryption succeeds and consumes the single allowance
    dec1 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"approval_request_id": req_id},
    )
    assert dec1.status_code == 200

    # Second decryption attempt must FAIL because allowance is consumed
    dec2 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_tok}"},
        json={"approval_request_id": req_id},
    )
    assert dec2.status_code == 403
    assert "limit" in _get_err(dec2) or "consumed" in _get_err(dec2) or "denied" in _get_err(dec2)


def test_audit_events_recorded_for_approval_actions(client, p8_suite, db_session):
    """Section 10: Explicit audit events logged for all approval lifecycle transitions."""
    _, off1_tok = p8_suite["officer1"]
    rec, rec_tok, _, _ = p8_suite["recipient"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Audit Approval Doc", "recipient_ids": rec.id},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"require_approval": True, "required_approvals": 1},
    )

    # Request approval
    req = client.post(
        f"/api/v1/documents/{doc_id}/decryption-requests",
        headers={"Authorization": f"Bearer {rec_tok}"},
    )
    req_id = req.json()["id"]

    # Approve
    client.post(
        f"/api/v1/decryption-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )

    # Verify audit events
    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.document_id == doc_id)
        .order_by(AuditEvent.timestamp.asc())
        .all()
    )
    event_types = [e.event_type for e in events]
    assert "DECRYPTION_APPROVAL_REQUESTED" in event_types
    assert "DECRYPTION_APPROVED" in event_types

