import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.session import UserSession
from app.models.revoked_token import RevokedToken
from app.models.user import User
from app.models.device import Device
from app.services.audit_service import AuditService
from app.config.settings import settings


class SessionService:
    @staticmethod
    def create_session(
        db: Session,
        user_id: str,
        token_jti: str,
        expires_at: datetime,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        authentication_level: str = "NORMAL",
        mfa_verified_at: Optional[datetime] = None,
        ip_metadata: Optional[str] = None,
        user_agent_metadata: Optional[str] = None,
    ) -> UserSession:
        now = datetime.now(timezone.utc)
        session = UserSession(
            id=session_id or str(uuid.uuid4()),
            user_id=user_id,
            device_id=device_id,
            token_jti=token_jti,
            created_at=now,
            last_activity_at=now,
            expires_at=expires_at,
            authentication_level=authentication_level,
            mfa_verified_at=mfa_verified_at,
            ip_metadata=ip_metadata,
            user_agent_metadata=user_agent_metadata,
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        AuditService.log_event(
            db=db,
            event_type="SESSION_CREATED",
            user_id=user_id,
            metadata={
                "session_id": session.id,
                "device_id": device_id,
                "authentication_level": authentication_level,
            },
        )
        return session

    @staticmethod
    def get_by_jti(db: Session, token_jti: str) -> Optional[UserSession]:
        return db.query(UserSession).filter(UserSession.token_jti == token_jti).first()

    @staticmethod
    def get_by_id(db: Session, session_id: str) -> Optional[UserSession]:
        return db.query(UserSession).filter(UserSession.id == session_id).first()

    @staticmethod
    def list_user_sessions(db: Session, user_id: str) -> List[UserSession]:
        return (
            db.query(UserSession)
            .filter(UserSession.user_id == user_id)
            .order_by(desc(UserSession.created_at))
            .all()
        )

    @staticmethod
    def revoke_session(
        db: Session,
        session_id: str,
        actor: User,
    ) -> UserSession:
        session = SessionService.get_by_id(db, session_id)
        if not session:
            raise ValueError(f"Session with ID '{session_id}' not found.")

        # Check permission: owning user or ADMIN
        if actor.role != "ADMIN" and session.user_id != actor.id:
            raise PermissionError("Access denied. You can only revoke your own sessions.")

        now = datetime.now(timezone.utc)
        session.revoked_at = now

        # Add JTI to RevokedToken blacklist
        revoked = RevokedToken(
            token_jti=session.token_jti,
            user_id=session.user_id,
            expires_at=session.expires_at,
        )
        db.add(revoked)
        db.commit()
        db.refresh(session)

        AuditService.log_event(
            db=db,
            event_type="SESSION_REVOKED",
            user_id=session.user_id,
            metadata={
                "session_id": session.id,
                "revoked_by": actor.id,
            },
        )
        return session

    @staticmethod
    def touch_session(db: Session, session: UserSession) -> None:
        """Updates last_activity_at for active session."""
        session.last_activity_at = datetime.now(timezone.utc)
        db.commit()
