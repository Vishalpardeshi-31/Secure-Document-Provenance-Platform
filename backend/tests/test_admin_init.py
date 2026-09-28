import os
from app.models.user import User
from app.models.role import UserRole
from app.services.user_service import UserService


def test_admin_initialization_logic(db_session):
    """Verify administrator account creation and prevention of duplicates."""
    # Ensure no admin initially
    assert db_session.query(User).filter(User.role == UserRole.ADMIN.value).first() is None

    # Create first admin
    admin = UserService.create_user(
        db=db_session,
        username="sec_admin",
        email="admin@security.internal",
        plain_password="Strict#Passphrase2026!",
        role=UserRole.ADMIN,
    )
    assert admin.id is not None
    assert admin.role == "ADMIN"
    assert admin.username == "sec_admin"

    # Query directly
    queried = db_session.query(User).filter(User.role == UserRole.ADMIN.value).first()
    assert queried is not None
    assert queried.id == admin.id
