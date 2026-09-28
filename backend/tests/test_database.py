import uuid
from datetime import datetime, timezone
from sqlalchemy import text
from app.models import (
    User,
    Role,
    UserRole,
    Department,
    Device,
    Document,
    DocumentVersion,
    DocumentRecipient,
    AccessPolicy,
    DecryptionSession,
    AuditEvent,
)


def test_database_is_initially_empty(db_session):
    """Verify strictly that the database starts empty with no fake or demo records."""
    assert db_session.query(User).count() == 0
    assert db_session.query(Role).count() == 0
    assert db_session.query(Department).count() == 0
    assert db_session.query(Device).count() == 0
    assert db_session.query(Document).count() == 0
    assert db_session.query(DocumentVersion).count() == 0
    assert db_session.query(DocumentRecipient).count() == 0
    assert db_session.query(AccessPolicy).count() == 0
    assert db_session.query(DecryptionSession).count() == 0
    assert db_session.query(AuditEvent).count() == 0


def test_database_ping_connectivity(db_session):
    """Verify low-level parameterized query execution on the connection."""
    result = db_session.execute(text("SELECT 1 AS alive")).scalar()
    assert result == 1


def test_model_persistence_and_relationships(db_session):
    """Verify that models across the 10 core tables can be correctly instantiated and persisted."""
    # 1. Department
    dept = Department(name="Security Operations", code="SEC-OPS")
    db_session.add(dept)
    db_session.commit()
    assert dept.id is not None

    # 2. Role
    role = Role(name="ADMIN", description="Administrator role")
    db_session.add(role)
    db_session.commit()

    # 3. User
    user = User(
        username="sec_officer_1",
        email="officer1@secplatform.internal",
        password_hash="mock_hash_for_db_test",
        role=UserRole.OFFICER.value,
        department_id=dept.id,
        role_id=role.id,
    )
    db_session.add(user)
    db_session.commit()
    assert user.id is not None
    assert user.department.code == "SEC-OPS"

    # 4. Device
    device = Device(
        user_id=user.id,
        device_name="Workstation-Alpha",
        device_fingerprint="sha256-fingerprint-sample",
        registration_status="APPROVED",
    )
    db_session.add(device)
    db_session.commit()
    assert device.id is not None

    # 5. Document
    doc = Document(
        title="Classified Briefing Note",
        classification="SECRET",
        owner_id=user.id,
        status="ACTIVE",
    )
    db_session.add(doc)
    db_session.commit()
    assert doc.id is not None

    # 6. Document Version
    version = DocumentVersion(
        document_id=doc.id,
        version_number=1,
        original_filename="briefing_v1.pdf",
        encrypted_storage_reference="enc://vault/docs/sample_ref_001.bin",
        content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    db_session.add(version)
    db_session.commit()
    assert version.id is not None

    # 7. Document Recipient
    recipient = DocumentRecipient(
        document_id=doc.id,
        user_id=user.id,
        permission_level="READ",
    )
    db_session.add(recipient)
    db_session.commit()
    assert recipient.id is not None

    # 8. Access Policy
    policy = AccessPolicy(
        document_id=doc.id,
        device_restriction=True,
        approval_requirement=False,
        maximum_sessions=3,
        one_time_decryption=False,
    )
    db_session.add(policy)
    db_session.commit()
    assert policy.id is not None

    # 9. Decryption Session
    session = DecryptionSession(
        document_id=doc.id,
        version_id=version.id,
        user_id=user.id,
        device_id=device.id,
        policy_id=policy.id,
        session_token_hash="sess_hash_placeholder",
        status="INITIATED",
    )
    db_session.add(session)
    db_session.commit()
    assert session.id is not None

    # 10. Audit Event
    audit = AuditEvent(
        event_type="SESSION_INITIATED",
        user_id=user.id,
        document_id=doc.id,
        session_id=session.id,
        timestamp=datetime.now(timezone.utc),
        event_hash="hash_value_placeholder",
        previous_event_hash=None,
        metadata_json={"ip": "127.0.0.1"},
    )
    db_session.add(audit)
    db_session.commit()
    assert audit.id is not None
