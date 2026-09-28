import enum
import uuid
from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base, TimestampMixin


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    OFFICER = "OFFICER"
    RECIPIENT = "RECIPIENT"
    AUDITOR = "AUDITOR"


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(
        String(32), unique=True, index=True, nullable=False
    )
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="role_rel")  # noqa: F821
