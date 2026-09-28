import uuid
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.revoked_token import RevokedToken
from app.models.session import UserSession
from app.models.mfa import UserMfaCredential
from app.security.password import verify_password
from app.security.tokens import create_access_token, decode_access_token
from app.config.settings import settings
from app.schemas.auth import TokenResponse
from app.services.audit_service import AuditService
from app.services.session_service import SessionService


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class AuthService:
    @staticmethod
    def authenticate_user(
        db: Session,
        username_or_email: str,
        plain_password: str,
    ) -> Tuple[Optional[User], Optional[str]]:
        """Looks up a user by username or email and validates password using Argon2id.
        Enforces account lockout after repeated failures and account enumeration protection."""
        user = db.query(User).filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        now = datetime.now(timezone.utc)

        if not user:
            AuditService.log_event(
                db=db,
                event_type="USER_LOGIN_FAILURE",
                user_id=None,
                metadata={"reason": "user_not_found"},
            )
            return None, "INVALID_CREDENTIALS"

        # Check account lockout
        locked_at = _to_utc(user.locked_until)
        if locked_at and locked_at > now:
            AuditService.log_event(
                db=db,
                event_type="USER_LOGIN_FAILURE",
                user_id=user.id,
                metadata={"reason": "account_locked"},
            )
            return user, "ACCOUNT_LOCKED"

        if not verify_password(plain_password, user.password_hash):
            user.failed_login_attempts = getattr(user, "failed_login_attempts", 0) + 1
            if user.failed_login_attempts >= 5:
                user.locked_until = now + timedelta(minutes=15)
                AuditService.log_event(
                    db=db,
                    event_type="ACCOUNT_LOCKED",
                    user_id=user.id,
                    metadata={"reason": "repeated_failed_logins", "failed_attempts": user.failed_login_attempts},
                )
            AuditService.log_event(
                db=db,
                event_type="USER_LOGIN_FAILURE",
                user_id=user.id,
                metadata={"reason": "invalid_password", "failed_attempts": user.failed_login_attempts},
            )
            db.commit()
            return None, "INVALID_CREDENTIALS"

        if not user.is_active:
            AuditService.log_event(
                db=db,
                event_type="USER_LOGIN_FAILURE",
                user_id=user.id,
                metadata={"reason": "account_inactive"},
            )
            return user, "ACCOUNT_INACTIVE"

        # Successful credentials validation - reset failure count
        if user.failed_login_attempts > 0 or user.locked_until is not None:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.commit()

        AuditService.log_event(
            db=db,
            event_type="USER_LOGIN_SUCCESS",
            user_id=user.id,
            metadata={"username": user.username, "role": user.role},
        )
        return user, None

    @staticmethod
    def is_mfa_enabled(db: Session, user_id: str) -> bool:
        cred = db.query(UserMfaCredential).filter(
            UserMfaCredential.user_id == user_id,
            UserMfaCredential.enabled == True  # noqa: E712
        ).first()
        return cred is not None

    @staticmethod
    def issue_mfa_challenge_token(user: User) -> str:
        """Issues a temporary 5-minute pre-auth token for completing MFA verification."""
        return create_access_token(
            subject=user.id,
            role=user.role,
            expires_delta=timedelta(minutes=5),
            extra_claims={"mfa_pending": True, "username": user.username},
        )

    @staticmethod
    def issue_token_for_user(
        db: Session,
        user: User,
        device_id: Optional[str] = None,
        auth_assurance_level: str = "NORMAL",
        mfa_verified_at: Optional[datetime] = None,
        ip_metadata: Optional[str] = None,
        user_agent_metadata: Optional[str] = None,
    ) -> TokenResponse:
        """Issues an authenticated JWT session token and registers a UserSession."""
        session_id = str(uuid.uuid4())
        jti = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        extra_claims: Dict[str, Any] = {
            "username": user.username,
            "email": user.email,
            "jti": jti,
            "session_id": session_id,
            "device_id": device_id,
            "auth_assurance_level": auth_assurance_level,
        }
        if mfa_verified_at:
            extra_claims["mfa_verified_at"] = int(mfa_verified_at.timestamp())

        token = create_access_token(
            subject=user.id,
            role=user.role,
            extra_claims=extra_claims,
        )

        # Register server-side session tracking
        SessionService.create_session(
            db=db,
            user_id=user.id,
            token_jti=jti,
            expires_at=expires_at,
            session_id=session_id,
            device_id=device_id,
            authentication_level=auth_assurance_level,
            mfa_verified_at=mfa_verified_at,
            ip_metadata=ip_metadata,
            user_agent_metadata=user_agent_metadata,
        )

        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            mfa_required=False,
            auth_assurance_level=auth_assurance_level,
            session_id=session_id,
        )

    @staticmethod
    def logout_user(db: Session, token: str, user: User) -> None:
        """Revokes the current JWT session token in both RevokedToken and UserSession."""
        payload = decode_access_token(token)
        if payload and "jti" in payload:
            jti = payload["jti"]
            exp_ts = payload.get("exp")
            if exp_ts:
                expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
            else:
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

            # Store in revoked_tokens table
            revoked = RevokedToken(
                token_jti=jti,
                user_id=user.id,
                expires_at=expires_at,
            )
            db.add(revoked)

            # Mark UserSession as revoked if exists
            session = SessionService.get_by_jti(db, jti)
            if session:
                session.revoked_at = datetime.now(timezone.utc)

            db.commit()

        AuditService.log_event(
            db=db,
            event_type="USER_LOGOUT",
            user_id=user.id,
            metadata={"username": user.username},
        )
