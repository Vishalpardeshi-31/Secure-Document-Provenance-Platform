import pytest
from app.services.user_service import UserService
from app.models.role import UserRole
from app.security.tokens import create_access_token


@pytest.fixture
def auth_tokens(db_session):
    admin = UserService.create_user(
        db=db_session,
        username="admin_user",
        email="admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    officer = UserService.create_user(
        db=db_session,
        username="officer_user",
        email="officer@agency.gov",
        plain_password="OfficerPassword123!",
        role=UserRole.OFFICER,
    )
    recipient = UserService.create_user(
        db=db_session,
        username="recipient_user",
        email="recipient@agency.gov",
        plain_password="RecipientPassword123!",
        role=UserRole.RECIPIENT,
    )
    auditor = UserService.create_user(
        db=db_session,
        username="auditor_user",
        email="auditor@agency.gov",
        plain_password="AuditorPassword123!",
        role=UserRole.AUDITOR,
    )

    return {
        "admin": (admin, create_access_token(admin.id, admin.role)),
        "officer": (officer, create_access_token(officer.id, officer.role)),
        "recipient": (recipient, create_access_token(recipient.id, recipient.role)),
        "auditor": (auditor, create_access_token(auditor.id, auditor.role)),
    }


def test_admin_can_access_admin_endpoint(client, auth_tokens):
    """Admin can list all users."""
    _, token = auth_tokens["admin"]
    res = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    users = res.json()
    assert len(users) >= 4


def test_officer_cannot_access_admin_endpoint(client, auth_tokens):
    """Officer gets 403 Forbidden when trying to list or create users."""
    _, token = auth_tokens["officer"]
    res = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403

    post_res = client.post(
        "/api/v1/users",
        json={
            "username": "newuser",
            "email": "new@agency.gov",
            "password": "Password123!",
            "role": "RECIPIENT",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert post_res.status_code == 403


def test_recipient_cannot_access_admin_endpoint(client, auth_tokens):
    """Recipient gets 403 Forbidden when accessing admin endpoints."""
    _, token = auth_tokens["recipient"]
    res = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


def test_auditor_cannot_modify_users(client, auth_tokens):
    """Auditor gets 403 Forbidden when attempting to create, edit, or deactivate users."""
    _, auditor_token = auth_tokens["auditor"]
    recipient, _ = auth_tokens["recipient"]

    # Attempt to modify recipient
    res = client.patch(
        f"/api/v1/users/{recipient.id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert res.status_code == 403


def test_auditor_and_admin_can_view_audit_events(client, auth_tokens):
    """Both ADMIN and AUDITOR roles are authorized to view audit events."""
    _, admin_token = auth_tokens["admin"]
    _, auditor_token = auth_tokens["auditor"]
    _, officer_token = auth_tokens["officer"]

    # Admin can view
    admin_res = client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_res.status_code == 200

    # Auditor can view
    auditor_res = client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {auditor_token}"})
    assert auditor_res.status_code == 200

    # Officer cannot view
    officer_res = client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {officer_token}"})
    assert officer_res.status_code == 403


def test_unauthenticated_requests_get_401(client):
    """Unauthenticated requests to protected endpoints return 401."""
    res1 = client.get("/api/v1/users")
    assert res1.status_code == 401

    res2 = client.get("/api/v1/departments")
    assert res2.status_code == 401

    res3 = client.get("/api/v1/devices")
    assert res3.status_code == 401
