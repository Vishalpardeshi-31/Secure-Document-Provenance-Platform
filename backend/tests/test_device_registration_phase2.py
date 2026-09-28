import pytest
from app.services.user_service import UserService
from app.models.role import UserRole
from app.security.tokens import create_access_token


@pytest.fixture
def user_client(client, db_session):
    user = UserService.create_user(
        db=db_session,
        username="device_user",
        email="device_user@agency.gov",
        plain_password="UserPassword123!",
        role=UserRole.RECIPIENT,
    )
    token = create_access_token(user.id, user.role)
    return client, token, user


def test_register_device(user_client):
    client, token, user = user_client
    res = client.post(
        "/api/v1/devices",
        json={
            "device_name": "Workstation Alpha-9",
            "device_fingerprint": "sha256-fingerprint-workstation-hw-uuid-12345678",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["user_id"] == user.id
    assert data["device_name"] == "Workstation Alpha-9"
    assert data["registration_status"] == "ACTIVE"


def test_list_user_devices(user_client):
    client, token, _ = user_client
    client.post(
        "/api/v1/devices",
        json={
            "device_name": "Laptop Mobile-1",
            "device_fingerprint": "sha256-fingerprint-laptop-hw-uuid-87654321",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    res = client.get("/api/v1/devices", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    devices = res.json()
    assert len(devices) >= 1
    assert any(d["device_name"] == "Laptop Mobile-1" for d in devices)


def test_update_device_status(user_client):
    client, token, _ = user_client
    create_res = client.post(
        "/api/v1/devices",
        json={
            "device_name": "Tablet Field-3",
            "device_fingerprint": "sha256-fingerprint-tablet-hw-uuid-99998888",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    device_id = create_res.json()["id"]

    patch_res = client.patch(
        f"/api/v1/devices/{device_id}",
        json={"registration_status": "REVOKED"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["registration_status"] == "REVOKED"
