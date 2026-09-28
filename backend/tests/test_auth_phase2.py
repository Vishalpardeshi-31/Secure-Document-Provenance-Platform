from datetime import timedelta
import pytest
from app.services.user_service import UserService
from app.models.role import UserRole
from app.security.tokens import create_access_token


def test_valid_login(client, db_session):
    """Verifies that a registered active user can successfully authenticate and receive a token."""
    UserService.create_user(
        db=db_session,
        username="validuser",
        email="valid@agency.gov",
        plain_password="ValidPassword123!",
        role=UserRole.RECIPIENT,
    )

    response = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "validuser", "password": "ValidPassword123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["username"] == "validuser"
    assert data["role"] == "RECIPIENT"
    assert "password" not in data
    assert "password_hash" not in data


def test_invalid_password(client, db_session):
    """Verifies that authentication fails with 401 when an incorrect password is provided."""
    UserService.create_user(
        db=db_session,
        username="user1",
        email="user1@agency.gov",
        plain_password="CorrectPassword123!",
        role=UserRole.RECIPIENT,
    )

    response = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "user1", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["error"]["message"]


def test_inactive_account_login_rejected(client, db_session):
    """Verifies that inactive/deactivated accounts are rejected with 403."""
    user = UserService.create_user(
        db=db_session,
        username="inactive_agent",
        email="inactive@agency.gov",
        plain_password="ActivePassword123!",
        role=UserRole.OFFICER,
    )
    user.is_active = False
    db_session.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "inactive_agent", "password": "ActivePassword123!"},
    )
    assert response.status_code == 403
    assert "Account is inactive" in response.json()["error"]["message"]


def test_expired_token_rejected(client, db_session):
    """Verifies that an expired JWT token is rejected with 401."""
    user = UserService.create_user(
        db=db_session,
        username="expire_test",
        email="expire@agency.gov",
        plain_password="ValidPassword123!",
        role=UserRole.RECIPIENT,
    )

    # Issue token that already expired 10 minutes ago
    expired_token = create_access_token(
        subject=user.id,
        role=user.role,
        expires_delta=timedelta(minutes=-10),
    )

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401


def test_malformed_token_rejected(client):
    """Verifies that malformed or garbage tokens are rejected with 401."""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer not.a.valid.jwt.token"},
    )
    assert response.status_code == 401


def test_logout_and_session_invalidation(client, db_session):
    """Verifies that calling logout invalidates the token, rejecting subsequent requests with 401."""
    user = UserService.create_user(
        db=db_session,
        username="logoutuser",
        email="logout@agency.gov",
        plain_password="LogoutPassword123!",
        role=UserRole.RECIPIENT,
    )

    # Login to obtain token
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "logoutuser", "password": "LogoutPassword123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Verify access works before logout
    me_res1 = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res1.status_code == 200

    # Perform logout
    logout_res = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_res.status_code == 200
    assert "Session invalidated" in logout_res.json()["message"]

    # Attempt to use the same token after logout -> must be rejected with 401
    me_res2 = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res2.status_code == 401
    assert "revoked" in me_res2.json()["error"]["message"]
