import base64
import io
import threading
from datetime import datetime, timezone, timedelta
import pytest
from app.models.user import User
from app.models.role import UserRole
from app.models.device import Device
from app.models.access_policy import AccessPolicy
from app.services.user_service import UserService
from app.services.device_service import DeviceService
from app.security.recipient_key_manager import RecipientKeyManager
from app.security.tokens import create_access_token


@pytest.fixture
def policy_suite(db_session):
    admin = UserService.create_user(
        db=db_session,
        username="pol_admin",
        email="pol_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="pol_officer",
        email="pol_officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient = UserService.create_user(
        db=db_session,
        username="pol_recipient",
        email="pol_recipient@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )

    key = RecipientKeyManager.provision_recipient_key(db_session, recipient, admin)

    device_a = DeviceService.register_device(
        db=db_session,
        user_id=recipient.id,
        device_name="Recipient Secure Workstation",
        device_fingerprint="fp-rec-workstation-001",
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "recipient": (recipient, create_access_token(recipient.id, recipient.role), key),
        "device_a": device_a,
    }


def get_error_message(res):
    data = res.json()
    if "error" in data and "message" in data["error"]:
        return data["error"]["message"].lower()
    if "detail" in data:
        return str(data["detail"]).lower()
    return str(data).lower()


def test_time_window_future_valid_from_denies(client, policy_suite, db_session):
    """Access policy with future valid_from must deny decryption with ACCESS_NOT_YET_VALID."""
    _, officer_token = policy_suite["officer"]
    recipient, rec_token, _ = policy_suite["recipient"]

    future_start = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    future_end = (datetime.now(timezone.utc) + timedelta(hours=5)).isoformat()

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={
            "title": "Future Access Document",
            "recipient_ids": recipient.id,
            "policy_valid_from": future_start,
            "policy_valid_until": future_end,
        },
        files={"file": ("future.txt", io.BytesIO(b"Future access only"), "text/plain")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
    )
    assert res.status_code == 403
    assert "not started yet" in get_error_message(res)


def test_time_window_expired_denies(client, policy_suite, db_session):
    """Access policy with past valid_until must deny decryption with ACCESS_EXPIRED."""
    _, officer_token = policy_suite["officer"]
    recipient, rec_token, _ = policy_suite["recipient"]

    past_start = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    past_end = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={
            "title": "Expired Access Document",
            "recipient_ids": recipient.id,
            "policy_valid_from": past_start,
            "policy_valid_until": past_end,
        },
        files={"file": ("expired.txt", io.BytesIO(b"Expired access"), "text/plain")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
    )
    assert res.status_code == 403
    assert "expired" in get_error_message(res)


def test_device_restriction_enforcement(client, policy_suite, db_session):
    """Device restriction policy verifies registered, active, and matching user device."""
    admin, _ = policy_suite["admin"]
    _, officer_token = policy_suite["officer"]
    recipient, rec_token, _ = policy_suite["recipient"]
    device_a = policy_suite["device_a"]

    # Register a device belonging to another user (admin)
    admin_device = DeviceService.register_device(
        db=db_session,
        user_id=admin.id,
        device_name="Admin Laptop",
        device_fingerprint="fp-admin-lap-999",
    )

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={
            "title": "Device Restricted Doc",
            "recipient_ids": recipient.id,
            "policy_require_registered_device": "true",
        },
        files={"file": ("dev_rest.txt", io.BytesIO(b"Device bound content"), "text/plain")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # Case 1: No device supplied -> 403
    res1 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
        json={},
    )
    assert res1.status_code == 403
    assert "requires an authorized registered device" in get_error_message(res1)

    # Case 2: Unknown device ID -> 403
    res2 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
        json={"device_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert res2.status_code == 403
    assert "device is not registered" in get_error_message(res2)

    # Case 3: Another user's device -> 403
    res3 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
        json={"device_id": admin_device.id},
    )
    assert res3.status_code == 403
    assert "not registered to the authenticated user" in get_error_message(res3)

    # Case 4: Correct active registered device -> 200 SUCCESS
    res4 = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
        json={"device_id": device_a.id},
    )
    assert res4.status_code == 200
    assert res4.json()["status"] == "COMPLETED"


def test_max_decryptions_enforcement(client, policy_suite, db_session):
    """Policy with max_decryptions=1 allows exactly 1 successful decryption, then denies subsequent attempts."""
    _, officer_token = policy_suite["officer"]
    recipient, rec_token, _ = policy_suite["recipient"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={
            "title": "One-Time Document",
            "recipient_ids": recipient.id,
            "policy_max_decryptions": 1,
        },
        files={"file": ("onetime.txt", io.BytesIO(b"One time view only"), "text/plain")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    # First decryption attempt -> Allowed
    first_res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
    )
    assert first_res.status_code == 200
    assert first_res.json()["status"] == "COMPLETED"

    # Second decryption attempt -> Denied
    second_res = client.post(
        f"/api/v1/documents/{doc_id}/decrypt",
        headers={"Authorization": f"Bearer {rec_token}"},
    )
    assert second_res.status_code == 403
    assert "maximum permitted decryptions" in get_error_message(second_res)


def test_concurrent_decryptions_race_condition_protection(client, policy_suite, db_session):
    """Two concurrent decryption requests against max_decryptions=1: exactly 1 succeeds and 1 fails."""
    _, officer_token = policy_suite["officer"]
    recipient, rec_token, _ = policy_suite["recipient"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={
            "title": "Concurrency Test Document",
            "recipient_ids": recipient.id,
            "policy_max_decryptions": 1,
        },
        files={"file": ("concurrency.txt", io.BytesIO(b"Atomic single decryption test"), "text/plain")},
    )
    assert upload_res.status_code == 201
    doc_id = upload_res.json()["id"]

    results = []

    def attempt_decryption():
        res = client.post(
            f"/api/v1/documents/{doc_id}/decrypt",
            headers={"Authorization": f"Bearer {rec_token}"},
        )
        results.append(res.status_code)

    t1 = threading.Thread(target=attempt_decryption)
    t2 = threading.Thread(target=attempt_decryption)

    t1.start()
    t2.start()

    t1.join()
    t2.join()

    # Exactly one request must be 200 and one must be 403
    assert sorted(results) == [200, 403]


def test_policy_creation_and_update_validation(client, policy_suite, db_session):
    """Officer can view and update policy. Invalid date windows or negative limits are rejected."""
    _, officer_token = policy_suite["officer"]
    recipient, rec_token, _ = policy_suite["recipient"]

    upload_res = client.post(
        "/api/v1/documents",
        headers={"Authorization": f"Bearer {officer_token}"},
        data={"title": "Policy Edit Doc", "recipient_ids": recipient.id},
        files={"file": ("pol_edit.txt", io.BytesIO(b"Configurable policy"), "text/plain")},
    )
    doc_id = upload_res.json()["id"]

    # 1. Reject invalid time range where expiration <= start
    invalid_res = client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {officer_token}"},
        json={
            "valid_from": "2026-10-01T12:00:00Z",
            "valid_until": "2026-10-01T10:00:00Z",
        },
    )
    assert invalid_res.status_code in [400, 422]

    # 2. Reject negative / 0 max decryptions
    invalid_max = client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {officer_token}"},
        json={"max_decryptions": 0},
    )
    assert invalid_max.status_code in [400, 422]

    # 3. Valid policy configuration succeeds
    valid_res = client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {officer_token}"},
        json={
            "max_decryptions": 3,
            "require_registered_device": True,
        },
    )
    assert valid_res.status_code == 200
    assert valid_res.json()["max_decryptions"] == 3
    assert valid_res.json()["require_registered_device"] is True

    # 4. Recipient cannot modify access policy
    unauth_res = client.put(
        f"/api/v1/documents/{doc_id}/policy",
        headers={"Authorization": f"Bearer {rec_token}"},
        json={"max_decryptions": 10},
    )
    assert unauth_res.status_code == 403
