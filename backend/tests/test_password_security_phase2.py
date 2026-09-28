from app.services.user_service import UserService
from app.models.role import UserRole
from app.models.user import User
from app.security.tokens import create_access_token


def test_password_is_argon2id_hashed(db_session):
    plain = "SuperSecurePassword123!"
    user = UserService.create_user(
        db=db_session,
        username="argon_test_user",
        email="argon@agency.gov",
        plain_password=plain,
        role=UserRole.RECIPIENT,
    )

    db_user = db_session.query(User).filter(User.id == user.id).first()
    assert db_user.password_hash != plain
    assert db_user.password_hash.startswith("$argon2id$")


def test_plaintext_password_never_stored(db_session):
    plain = "PlaintextNeverInDB999!"
    user = UserService.create_user(
        db=db_session,
        username="db_scan_user",
        email="scan@agency.gov",
        plain_password=plain,
        role=UserRole.RECIPIENT,
    )

    # Inspect all attributes of the stored row
    db_user = db_session.query(User).filter(User.id == user.id).first()
    for col in User.__table__.columns:
        val = getattr(db_user, col.name)
        assert val != plain, f"Plaintext password leaked in column {col.name}"


def test_password_hash_never_returned_through_api(client, db_session):
    admin = UserService.create_user(
        db=db_session,
        username="pw_admin",
        email="pw_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )
    token = create_access_token(admin.id, admin.role)

    # 1. Login response
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "pw_admin", "password": "AdminPassword123!"},
    )
    assert "password_hash" not in login_res.text
    assert "password" not in login_res.text or "password_hash" not in login_res.json()

    # 2. /me profile endpoint
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert "password_hash" not in me_res.json()

    # 3. /users list endpoint
    users_res = client.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
    for u in users_res.json():
        assert "password_hash" not in u
        assert "password" not in u

    # 4. User creation response
    create_res = client.post(
        "/api/v1/users",
        json={
            "username": "hash_check_user",
            "email": "hash_check@agency.gov",
            "password": "ValidPassword123!",
            "role": "OFFICER",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert "password_hash" not in create_res.json()
