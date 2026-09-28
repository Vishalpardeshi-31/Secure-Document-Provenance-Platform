from typing import Optional, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.revoked_token import RevokedToken
from app.security.password import verify_password
from app.security.tokens import create_access_token, decode_access_token
from app.config.settings import settings
from app.schemas.auth import TokenResponse
from app.services.audit_service import AuditService


class AuthService:
    @staticmethod
    def authenticate_user(
        db: Session,
        username_or_email: str,
        plain_password: str,
    ) -> Tuple[Optional[User], Optional[str]]:
        """Looks up a user by username or email and validates password using Argon2id.
        Returns (user, failure_reason) where failure_reason is None on success."""
        user = db.query(User).filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if not user:
            AuditService.log_event(
                db=db,
                event_type="USER_LOGIN_FAILURE",
                user_id=None,
                metadata={"reason": "user_not_found"},
            )
            return None, "INVALID_CREDENTIALS"

        if not verify_password(plain_password, user.password_hash):
            AuditService.log_event(
                db=db,
                event_type="USER_LOGIN_FAILURE",
                user_id=user.id,
                metadata={"reason": "invalid_password"},
            )
            return None, "INVALID_CREDENTIALS"

        if not user.is_active:
            AuditService.log_event(
                db=db,
                event_type="USER_LOGIN_FAILURE",
                user_id=user.id,
                metadata={"reason": "account_inactive"},
            )
            return user, "ACCOUNT_INACTIVE"

        # Successful authentication
        AuditService.log_event(
            db=db,
            event_type="USER_LOGIN_SUCCESS",
            user_id=user.id,
            metadata={"username": user.username, "role": user.role},
        )
        return user, None

    @staticmethod
    def issue_token_for_user(user: User) -> TokenResponse:
        """Issues an authenticated JWT session token for a valid user."""
        token = create_access_token(
            subject=user.id,
            role=user.role,
            extra_claims={"username": user.username, "email": user.email},
        )
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
        )

    @staticmethod
    def logout_user(db: Session, token: str, user: User) -> None:
        """Revokes the current JWT session token and writes to RevokedToken."""
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
            db.commit()

        AuditService.log_event(
            db=db,
            event_type="USER_LOGOUT",
            user_id=user.id,
            metadata={"username": user.username},
        )
