import os
import sys
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
import threading
from sqlalchemy import event
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models import Role, UserRole

TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
    expire_on_commit=False,
)


@pytest.fixture(scope="function")
def db_session():
    """Creates a fresh in-memory database schema for each test and drops it afterwards."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Provides a FastAPI TestClient with the database dependency overridden."""
    def override_get_db():
        s = TestingSessionLocal()
        try:
            yield s
        finally:
            s.close()

    from app.security.rate_limiter import auth_rate_limiter
    auth_rate_limiter._requests.clear()
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    auth_rate_limiter._requests.clear()
    app.dependency_overrides.clear()
