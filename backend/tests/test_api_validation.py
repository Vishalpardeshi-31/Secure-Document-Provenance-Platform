from app.services.user_service import UserService
from app.models.role import UserRole


def test_login_validation_empty_body(client):
    """Verify that submitting an empty payload to /auth/login returns 422 with standard error format."""
    response = client.post("/api/v1/auth/login", json={})
    assert response.status_code == 422
    data = response.json()

    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert isinstance(data["error"]["details"], list)
    assert len(data["error"]["details"]) > 0


def test_login_validation_missing_password(client):
    """Verify missing password in login payload returns standard validation error."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "admin_user"},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    fields = [d["field"] for d in data["error"]["details"]]
    assert any("password" in str(f) for f in fields)


def test_login_authentication_failure(client, db_session):
    """Verify that submitting non-existent user credentials returns 401 Unauthorized without stack trace."""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "username_or_email": "non_existent_user",
            "password": "WrongPassword123!",
        },
    )
    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "UNAUTHORIZED"
    assert "Invalid credentials" in data["error"]["message"]


def test_login_authentication_success(client, db_session):
    """Verify that a real registered user can authenticate and retrieve a valid JWT token."""
    # Seed a real user using UserService
    user = UserService.create_user(
        db=db_session,
        username="test_officer",
        email="officer@agency.internal",
        plain_password="Strong#Password123!",
        role=UserRole.OFFICER,
    )

    response = client.post(
        "/api/v1/auth/login",
        json={
            "username_or_email": "test_officer",
            "password": "Strong#Password123!",
        },
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["user_id"] == user.id
    assert token_data["role"] == "OFFICER"

    # Now verify /api/v1/auth/me with the issued token
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    profile_response = client.get("/api/v1/auth/me", headers=headers)
    assert profile_response.status_code == 200
    profile_data = profile_response.json()
    assert profile_data["username"] == "test_officer"
    assert profile_data["email"] == "officer@agency.internal"
    assert "password" not in profile_data
    assert "password_hash" not in profile_data


def test_protected_endpoint_without_token(client):
    """Verify accessing /api/v1/auth/me without a bearer token returns 401 Unauthorized."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "UNAUTHORIZED"
