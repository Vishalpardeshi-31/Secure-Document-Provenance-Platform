from app.services.user_service import UserService
from app.services.audit_service import AuditService
from app.models.role import UserRole
from app.models.audit_event import AuditEvent


def test_login_success_creates_audit_event(client, db_session):
    UserService.create_user(
        db=db_session,
        username="audit_login_user",
        email="audit_login@agency.gov",
        plain_password="ValidPassword123!",
        role=UserRole.RECIPIENT,
    )

    # Perform valid login
    res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "audit_login_user", "password": "ValidPassword123!"},
    )
    assert res.status_code == 200

    # Query audit event
    events = AuditService.get_events(db=db_session, event_type="USER_LOGIN_SUCCESS")
    assert len(events) >= 1
    event = events[0]
    assert event.event_type == "USER_LOGIN_SUCCESS"
    assert event.metadata_json["username"] == "audit_login_user"
    assert event.event_hash is not None


def test_login_failure_creates_audit_event(client, db_session):
    res = client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "nonexistent_user", "password": "WrongPassword123!"},
    )
    assert res.status_code == 401

    events = AuditService.get_events(db=db_session, event_type="USER_LOGIN_FAILURE")
    assert len(events) >= 1
    assert any(e.metadata_json.get("reason") == "user_not_found" for e in events)


def test_user_creation_creates_audit_event(client, db_session):
    admin = UserService.create_user(
        db=db_session,
        username="audit_admin",
        email="audit_admin@agency.gov",
        plain_password="AdminPassword123!",
        role=UserRole.ADMIN,
    )

    UserService.create_user(
        db=db_session,
        username="newly_created",
        email="newly_created@agency.gov",
        plain_password="ValidPassword123!",
        role=UserRole.OFFICER,
        actor_id=admin.id,
    )

    events = AuditService.get_events(db=db_session, event_type="USER_CREATED")
    assert len(events) >= 1
    created_event = [e for e in events if e.metadata_json.get("username") == "newly_created"][0]
    assert created_event.user_id == admin.id
    assert created_event.metadata_json["role"] == "OFFICER"


def test_audit_chain_integrity(db_session):
    """Verifies that consecutive audit events maintain cryptographic hash linkage."""
    e1 = AuditService.log_event(db=db_session, event_type="TEST_EVENT_1")
    e2 = AuditService.log_event(db=db_session, event_type="TEST_EVENT_2")

    # e2 must reference e1's hash as previous_event_hash
    assert e2.previous_event_hash == e1.event_hash
    assert len(e2.event_hash) == 64  # SHA-256 length
