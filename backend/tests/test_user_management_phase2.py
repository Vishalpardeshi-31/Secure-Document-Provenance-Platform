import pytest
from app.services.user_service import UserService
from app.models.role import UserRole
from app.security.tokens import create_access_token


@pytest.fixture
def admin_client(client, db_session):
    admin = UserService.create_user(
        db=db_session,
        username="superadmin",
        email="superadmin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    token = create_access_token(admin.id, admin.role)
    return client, token, admin


def test_admin_creates_user_successfully(admin_client):
    client, token, _ = admin_client
    res = client.post(
        "/api/v1/users",
        json={
            "username": "newofficer",
            "email": "officer@agency.gov",
            "password": "StrongPassword123!",
            "role": "OFFICER",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "newofficer"
    assert data["role"] == "OFFICER"
    assert data["is_active"] is True
    assert "password_hash" not in data


def test_duplicate_username_rejected(admin_client):
    client, token, _ = admin_client
    res1 = client.post(
        "/api/v1/users",
        json={
            "username": "duplicate_user",
            "email": "user1@agency.gov",
            "password": "StrongPassword123!",
            "role": "RECIPIENT",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res1.status_code == 201

    res2 = client.post(
        "/api/v1/users",
        json={
            "username": "duplicate_user",
            "email": "user2@agency.gov",
            "password": "StrongPassword123!",
            "role": "RECIPIENT",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 400
    assert "already in use" in res2.json()["error"]["message"]


def test_duplicate_email_rejected(admin_client):
    client, token, _ = admin_client
    res1 = client.post(
        "/api/v1/users",
        json={
            "username": "unique_user1",
            "email": "shared@agency.gov",
            "password": "StrongPassword123!",
            "role": "RECIPIENT",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res1.status_code == 201

    res2 = client.post(
        "/api/v1/users",
        json={
            "username": "unique_user2",
            "email": "shared@agency.gov",
            "password": "StrongPassword123!",
            "role": "RECIPIENT",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res2.status_code == 400
    assert "already in use" in res2.json()["error"]["message"]


def test_invalid_role_rejected(admin_client):
    client, token, _ = admin_client
    res = client.post(
        "/api/v1/users",
        json={
            "username": "badroleuser",
            "email": "badrole@agency.gov",
            "password": "StrongPassword123!",
            "role": "SUPERUSER_NOT_EXIST",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    assert "Invalid role" in res.json()["error"]["message"]


def test_admin_can_activate_deactivate_user(admin_client):
    client, token, _ = admin_client
    create_res = client.post(
        "/api/v1/users",
        json={
            "username": "target_user",
            "email": "target@agency.gov",
            "password": "StrongPassword123!",
            "role": "RECIPIENT",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    user_id = create_res.json()["id"]

    # Deactivate
    patch_res1 = client.patch(
        f"/api/v1/users/{user_id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch_res1.status_code == 200
    assert patch_res1.json()["is_active"] is False

    # Deactivated user cannot authenticate
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "target_user", "password": "StrongPassword123!"},
    )
    assert login_res.status_code == 403

    # Reactivate
    patch_res2 = client.patch(
        f"/api/v1/users/{user_id}",
        json={"is_active": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch_res2.status_code == 200
    assert patch_res2.json()["is_active"] is True


def test_password_reset_by_admin(admin_client):
    client, token, _ = admin_client
    create_res = client.post(
        "/api/v1/users",
        json={
            "username": "reset_target",
            "email": "reset@agency.gov",
            "password": "InitialPassword123!",
            "role": "RECIPIENT",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    user_id = create_res.json()["id"]

    # Admin resets password
    reset_res = client.post(
        f"/api/v1/users/{user_id}/reset-password",
        json={"new_password": "NewStrongPassword456!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert reset_res.status_code == 200

    # Old password no longer works
    old_login = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "reset_target", "password": "InitialPassword123!"},
    )
    assert old_login.status_code == 401

    # New password works
    new_login = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "reset_target", "password": "NewStrongPassword456!"},
    )
    assert new_login.status_code == 200
