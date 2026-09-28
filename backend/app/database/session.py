from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.config.settings import settings

# Engine configuration with connection health checking
# pool_pre_ping ensures stale/disconnected pool connections are recycled safely
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency yielding a database session with guaranteed closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
