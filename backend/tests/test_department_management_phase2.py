import pytest
from app.services.user_service import UserService
from app.models.role import UserRole
from app.security.tokens import create_access_token


@pytest.fixture
def admin_client(client, db_session):
    admin = UserService.create_user(
        db=db_session,
        username="dept_admin",
        email="dept_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    token = create_access_token(admin.id, admin.role)
    return client, token, admin


def test_create_department(admin_client):
    client, token, _ = admin_client
    res = client.post(
        "/api/v1/departments",
        json={
            "name": "Cyber Defense Operations",
            "code": "CYBER_OPS",
            "description": "Enterprise defensive cyber command",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Cyber Defense Operations"
    assert data["code"] == "CYBER_OPS"
    assert data["is_active"] is True


def test_update_and_deactivate_department(admin_client):
    client, token, _ = admin_client
    create_res = client.post(
        "/api/v1/departments",
        json={"name": "Logistics", "code": "LOG_DIV"},
        headers={"Authorization": f"Bearer {token}"},
    )
    dept_id = create_res.json()["id"]

    patch_res = client.patch(
        f"/api/v1/departments/{dept_id}",
        json={"name": "Strategic Logistics Directorate", "is_active": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["name"] == "Strategic Logistics Directorate"
    assert patch_res.json()["is_active"] is False


def test_delete_department_prevented_if_users_assigned(admin_client, db_session):
    client, token, _ = admin_client
    create_res = client.post(
        "/api/v1/departments",
        json={"name": "Intel Unit", "code": "INTEL"},
        headers={"Authorization": f"Bearer {token}"},
    )
    dept_id = create_res.json()["id"]

    # Assign a user to this department
    UserService.create_user(
        db=db_session,
        username="intel_agent",
        email="agent@intel.gov",
        plain_password="IntelAgentPassword123!",
        role=UserRole.OFFICER,
        department_id=dept_id,
    )

    # Attempt delete -> must fail with 409 Conflict to protect referential integrity
    del_res = client.delete(
        f"/api/v1/departments/{dept_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_res.status_code == 409
    assert "user(s) are currently assigned" in del_res.json()["error"]["message"]


def test_delete_department_succeeds_if_empty(admin_client):
    client, token, _ = admin_client
    create_res = client.post(
        "/api/v1/departments",
        json={"name": "Temporary Project", "code": "TEMP_PROJ"},
        headers={"Authorization": f"Bearer {token}"},
    )
    dept_id = create_res.json()["id"]

    del_res = client.delete(
        f"/api/v1/departments/{dept_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_res.status_code == 200
    assert "deleted successfully" in del_res.json()["message"]
