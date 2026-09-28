import io
import base64
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.role import UserRole
from app.models.emergency_access import EmergencyAccessRequest
from app.models.audit_event import AuditEvent
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token


@pytest.fixture
def emerg_suite(db_session: Session):
    admin = UserService.create_user(
        db=db_session,
        username="em_admin",
        email="em_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    admin.can_emergency_decrypt = True

    officer1 = UserService.create_user(
        db=db_session,
        username="em_officer1",
        email="em_officer1@agency.gov",
        plain_password="Officer1Password123!",
        role=UserRole.OFFICER,
    )
    officer1.can_emergency_decrypt = True

    officer2 = UserService.create_user(
        db=db_session,
        username="em_officer2",
        email="em_officer2@agency.gov",
        plain_password="Officer2Password123!",
        role=UserRole.OFFICER,
    )
    officer2.can_emergency_decrypt = True

    # Normal recipient WITHOUT emergency privilege
    normal_recipient = UserService.create_user(
        db=db_session,
        username="em_normal_rec",
        email="em_normal_rec@agency.gov",
        plain_password="NormalPassword123!",
        role=UserRole.RECIPIENT,
    )
    normal_recipient.can_emergency_decrypt = False

    # Emergency actor recipient WITH emergency privilege
    emerg_recipient = UserService.create_user(
        db=db_session,
        username="em_emerg_rec",
        email="em_emerg_rec@agency.gov",
        plain_password="EmergPassword123!",
        role=UserRole.RECIPIENT,
    )
    emerg_recipient.can_emergency_decrypt = True

    auditor = UserService.create_user(
        db=db_session,
        username="em_auditor",
        email="em_auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )
    auditor.can_emergency_decrypt = False

    db_session.commit()

    key_normal = RecipientKeyManager.provision_recipient_key(db_session, normal_recipient, admin)
    key_emerg = RecipientKeyManager.provision_recipient_key(db_session, emerg_recipient, admin)

    dev_normal = DeviceService.register_device(
        db=db_session,
        user_id=normal_recipient.id,
        device_name="Normal Device",
        device_fingerprint="fp-norm-01",
    )
    dev_emerg = DeviceService.register_device(
        db=db_session,
        user_id=emerg_recipient.id,
        device_name="Emerg Device",
        device_fingerprint="fp-emerg-01",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer1": (officer1, create_access_token(officer1.id, officer1.role)),
        "officer2": (officer2, create_access_token(officer2.id, officer2.role)),
        "normal_rec": (normal_recipient, create_access_token(normal_recipient.id, normal_recipient.role), key_normal, dev_normal),
        "emerg_rec": (emerg_recipient, create_access_token(emerg_recipient.id, emerg_recipient.role), key_emerg, dev_emerg),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
    }


def _get_err(res):
    d = res.json()
    if "detail" in d:
        return str(d["detail"]).lower()
    return str(d).lower()


def test_user_without_emergency_permission_cannot_request(client, emerg_suite):
    """Section 14 & 15: Users without explicit EMERGENCY_DECRYPT permission cannot initiate break-glass."""
    _, off1_tok = emerg_suite["officer1"]
    _, norm_tok, _, _ = emerg_suite["normal_rec"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Emergency Policy Doc"},
        files={"file": ("incident.txt", io.BytesIO(b"Incident document content"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    # Normal user without emergency permission attempts to initiate emergency request
    res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {norm_tok}"},
        json={"reason": "Urgent incident response required for active outage."},
    )
    assert res.status_code == 403
    assert "emergency_decrypt permission" in _get_err(res)


def test_missing_or_short_reason_rejected(client, emerg_suite):
    """Section 14: Emergency access requires an explicit incident reason (minimum 15 characters)."""
    _, off1_tok = emerg_suite["officer1"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Emergency Reason Doc"},
        files={"file": ("incident.txt", io.BytesIO(b"Incident data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    # Empty or short reason (< 15 chars)
    res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "urgent fix"},
    )
    assert res.status_code in [400, 422]


def test_document_policy_disallowing_emergency_access_rejected(client, emerg_suite):
    """Section 14: Emergency access requires allow_emergency_access=True in policy."""
    _, off1_tok = emerg_suite["officer1"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "No Emergency Policy Doc"},
        files={"file": ("incident.txt", io.BytesIO(b"Incident data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": False},
    )

    res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Urgent critical production investigation required."},
    )
    assert res.status_code == 403
    assert "not permitted" in _get_err(res)


def test_requester_cannot_approve_own_emergency_request(client, emerg_suite):
    """Section 16: The emergency requester must NOT approve their own emergency request."""
    _, off1_tok = emerg_suite["officer1"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Self Emergency Doc"},
        files={"file": ("incident.txt", io.BytesIO(b"Incident data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Urgent incident response required for national security."},
    )
    assert req_res.status_code == 201
    req_id = req_res.json()["id"]

    # Requester officer1 attempts to approve own request
    app_res = client.post(
        f"/api/v1/emergency-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off1_tok}"},
    )
    assert app_res.status_code == 403
    assert "cannot authorize their own" in _get_err(app_res)


def test_independent_authorization_and_emergency_decryption(client, emerg_suite):
    """Sections 16, 17, 19: Independent emergency approver authorizes, time-limited window, successful decryption."""
    _, off1_tok = emerg_suite["officer1"]
    _, off2_tok = emerg_suite["officer2"]
    _, em_rec_tok, _, _ = emerg_suite["emerg_rec"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Break-Glass Protected Doc"},
        files={"file": ("secret.txt", io.BytesIO(b"Emergency break-glass plaintext payload"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True, "maximum_emergency_duration": 15},
    )

    # Officer 1 requests emergency access
    req_res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "System compromise detected; immediate access required for forensic preservation."},
    )
    assert req_res.status_code == 201
    req_id = req_res.json()["id"]
    assert req_res.json()["status"] == "REQUESTED"

    # Officer 2 (independent authorized approver) authorizes emergency access
    app_res = client.post(
        f"/api/v1/emergency-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off2_tok}"},
        json={"reason": "Confirmed incident ticket #SEC-9912 authorized by SOC"},
    )
    assert app_res.status_code == 200
    assert app_res.json()["status"] == "AUTHORIZED"

    # Execute emergency decryption
    dec_res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-decrypt",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"emergency_request_id": req_id},
    )
    assert dec_res.status_code == 200
    assert dec_res.json()["status"] == "COMPLETED"
    pt = base64.b64decode(dec_res.json()["plaintext_base64"])
    assert pt == b"Emergency break-glass plaintext payload"


def test_used_emergency_request_cannot_decrypt_again(client, emerg_suite):
    """Section 13: Emergency requests transition to USED and cannot be replayed."""
    _, off1_tok = emerg_suite["officer1"]
    _, off2_tok = emerg_suite["officer2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Single-Use Emergency Doc"},
        files={"file": ("data.txt", io.BytesIO(b"Confidential single-use emergency data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Critical triage requires immediate emergency decryption."},
    )
    req_id = req_res.json()["id"]

    # Independent approval
    client.post(
        f"/api/v1/emergency-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off2_tok}"},
    )

    # First emergency decryption succeeds
    dec1 = client.post(
        f"/api/v1/documents/{doc_id}/emergency-decrypt",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"emergency_request_id": req_id},
    )
    assert dec1.status_code == 200

    # Second emergency decryption with same request must be DENIED (status is USED)
    dec2 = client.post(
        f"/api/v1/documents/{doc_id}/emergency-decrypt",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"emergency_request_id": req_id},
    )
    assert dec2.status_code == 403
    assert "not authorized" in _get_err(dec2) or "used" in _get_err(dec2)


def test_expired_emergency_authorization_rejected(client, emerg_suite, db_session):
    """Section 17: Emergency authorization window is short-lived; expired requests cannot decrypt."""
    _, off1_tok = emerg_suite["officer1"]
    _, off2_tok = emerg_suite["officer2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Expiry Emergency Doc"},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Incident response triage active on host 10.0.0.5."},
    )
    req_id = req_res.json()["id"]

    # Independent approval
    client.post(
        f"/api/v1/emergency-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off2_tok}"},
    )

    # Artificially expire the emergency authorization window
    db_req = db_session.query(EmergencyAccessRequest).filter(EmergencyAccessRequest.id == req_id).first()
    db_req.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    # Attempt emergency decrypt after expiration
    dec_res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-decrypt",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"emergency_request_id": req_id},
    )
    assert dec_res.status_code == 403
    assert "expired" in _get_err(dec_res)


def test_rejected_emergency_request_cannot_decrypt(client, emerg_suite):
    """Section 13 & 18: Rejected emergency requests cannot authorize decryption."""
    _, off1_tok = emerg_suite["officer1"]
    _, off2_tok = emerg_suite["officer2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Rejection Emergency Doc"},
        files={"file": ("data.txt", io.BytesIO(b"Data"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    req_res = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Attempting access without standard ticket justification."},
    )
    req_id = req_res.json()["id"]

    # Reject request
    rej_res = client.post(
        f"/api/v1/emergency-requests/{req_id}/reject",
        headers={"Authorization": f"Bearer {off2_tok}"},
        json={"reason": "Invalid justification; no active incident ticket exists."},
    )
    assert rej_res.status_code == 200
    assert rej_res.json()["status"] == "REJECTED"

    # Attempt decrypt
    dec = client.post(
        f"/api/v1/documents/{doc_id}/emergency-decrypt",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"emergency_request_id": req_id},
    )
    assert dec.status_code == 403
    assert "rejected" in _get_err(dec)


def test_emergency_audit_trail_recorded(client, emerg_suite, db_session):
    """Section 18: Real audit events logged for EMERGENCY_ACCESS_REQUESTED, APPROVED, and USED."""
    _, off1_tok = emerg_suite["officer1"]
    _, off2_tok = emerg_suite["officer2"]

    up = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {off1_tok}"},
        data={"title": "Audit Emergency Doc"},
        files={"file": ("data.txt", io.BytesIO(b"Data for emergency audit"), "text/plain")},
    )
    doc_id = up.json()["id"]

    client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"allow_emergency_access": True},
    )

    req = client.post(
        f"/api/v1/documents/{doc_id}/emergency-requests",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"reason": "Audited incident response scenario #TEST-AUDIT-001."},
    )
    req_id = req.json()["id"]

    client.post(
        f"/api/v1/emergency-requests/{req_id}/approve",
        headers={"Authorization": f"Bearer {off2_tok}"},
        json={"reason": "Approved by senior officer."},
    )

    client.post(
        f"/api/v1/documents/{doc_id}/emergency-decrypt",
        headers={"Authorization": f"Bearer {off1_tok}"},
        json={"emergency_request_id": req_id},
    )

    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.document_id == doc_id)
        .order_by(AuditEvent.timestamp.asc())
        .all()
    )
    event_types = [e.event_type for e in events]
    assert "EMERGENCY_ACCESS_REQUESTED" in event_types
    assert "EMERGENCY_ACCESS_APPROVED" in event_types
    assert "EMERGENCY_ACCESS_USED" in event_types
