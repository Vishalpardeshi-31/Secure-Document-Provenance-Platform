import pytest
from fastapi import HTTPException
from app.models.role import Role, UserRole
from app.models.user import User
from app.security.permissions import require_roles


def test_supported_roles_enum():
    """Verify that the required enterprise roles exist and have expected identifier values."""
    expected_roles = {"ADMIN", "OFFICER", "RECIPIENT", "AUDITOR"}
    enum_values = {role.value for role in UserRole}
    assert expected_roles == enum_values


def test_role_model_creation(db_session):
    """Verify role model instantiation and database uniqueness constraint."""
    admin_role = Role(name=UserRole.ADMIN.value, description="System Administrator")
    db_session.add(admin_role)
    db_session.commit()

    retrieved = db_session.query(Role).filter(Role.name == "ADMIN").first()
    assert retrieved is not None
    assert retrieved.name == "ADMIN"
    assert retrieved.description == "System Administrator"


def test_role_permission_checker():
    """Verify require_roles dependency factory enforces authorization."""
    admin_user = User(
        username="admin1",
        email="admin@test.local",
        password_hash="hash",
        role=UserRole.ADMIN.value,
        is_active=True,
    )
    officer_user = User(
        username="officer1",
        email="officer@test.local",
        password_hash="hash",
        role=UserRole.OFFICER.value,
        is_active=True,
    )
    recipient_user = User(
        username="recipient1",
        email="recipient@test.local",
        password_hash="hash",
        role=UserRole.RECIPIENT.value,
        is_active=True,
    )

    admin_only_checker = require_roles([UserRole.ADMIN])
    # Admin allowed
    assert admin_only_checker(current_user=admin_user) == admin_user

    # Officer denied for admin-only
    with pytest.raises(HTTPException) as exc_info:
        admin_only_checker(current_user=officer_user)
    assert exc_info.value.status_code == 403
    assert "Access denied" in exc_info.value.detail

    # Multiple allowed roles
    elevated_checker = require_roles([UserRole.ADMIN, UserRole.OFFICER])
    assert elevated_checker(current_user=admin_user) == admin_user
    assert elevated_checker(current_user=officer_user) == officer_user

    # Recipient denied
    with pytest.raises(HTTPException) as exc_info:
        elevated_checker(current_user=recipient_user)
    assert exc_info.value.status_code == 403
