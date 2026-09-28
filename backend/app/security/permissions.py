from datetime import datetime, timezone
from typing import List, Union, Optional
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.models.revoked_token import RevokedToken
from app.models.session import UserSession
from app.models.device import Device
from app.models.mfa import UserMfaCredential
from app.security.tokens import decode_access_token

security_scheme = HTTPBearer(auto_error=False)


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_query(fn, max_retries=5, retry_on_none=False):
    for i in range(max_retries):
        try:
            res = fn()
            if retry_on_none and res is None and i < max_retries - 1:
                import time
                time.sleep(0.02 * (i + 1))
                continue
            return res
        except Exception:
            if i == max_retries - 1:
                raise
            import time
            time.sleep(0.02 * (i + 1))


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Authenticates the bearer token, verifies signature & expiration, checks revocation status,
    validates server-side session tracking and device status, and retrieves active user."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Disallow temporary MFA pending token from accessing normal endpoints
    if payload.get("mfa_pending"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA verification is required before accessing protected resources.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    now = datetime.now(timezone.utc)

    # Check revoked_tokens blacklist
    if jti:
        is_revoked = _safe_query(lambda: db.query(RevokedToken).filter(RevokedToken.token_jti == jti).first())
        if is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has been revoked or logged out.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check server-side user_sessions table if recorded
        session_record = _safe_query(lambda: db.query(UserSession).filter(UserSession.token_jti == jti).first())
        if session_record:
            if session_record.revoked_at is not None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication session has been revoked.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            exp_utc = _to_utc(session_record.expires_at)
            if exp_utc and exp_utc < now:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication session has expired.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # If bound to a device, check if device was revoked
            if session_record.device_id:
                dev = _safe_query(lambda: db.query(Device).filter(Device.id == session_record.device_id).first())
                if dev and (dev.status == "REVOKED" or dev.registration_status == "REVOKED"):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="The registered device associated with this session has been revoked.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )


    user_id = payload["sub"]
    user = _safe_query(lambda: db.query(User).filter(User.id == user_id).first(), retry_on_none=True)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account associated with this token does not exist.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive.",
        )

    # Attach token payload metadata to user for downstream authorization
    setattr(user, "_auth_payload", payload)
    return user


# Reusable alias for require_authenticated_user()
require_authenticated_user = get_current_user


def require_step_up_assurance(max_age_seconds: int = 900):
    """Dependency ensuring the user possesses valid, unexpired MFA step-up assurance
    for high-value sensitive operations."""
    def step_up_checker(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        # Check if user has MFA enabled
        mfa_cred = _safe_query(lambda: db.query(UserMfaCredential).filter(
            UserMfaCredential.user_id == current_user.id,
            UserMfaCredential.enabled == True  # noqa: E712
        ).first())

        if mfa_cred:
            payload = getattr(current_user, "_auth_payload", {})
            assurance = payload.get("auth_assurance_level")
            mfa_ts = payload.get("mfa_verified_at")

            if assurance != "MFA_VERIFIED" or not mfa_ts:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Step-up MFA authentication required for this sensitive operation.",
                )

            # Check expiration of step-up assurance
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if (now_ts - int(mfa_ts)) > max_age_seconds:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Step-up MFA assurance has expired. Please re-authenticate with MFA.",
                )

        return current_user

    return step_up_checker


def require_role(role: Union[UserRole, str]):
    """Reusable dependency to enforce a single specific role."""
    target_value = role.value if isinstance(role, UserRole) else str(role)

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != target_value:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires role: {target_value}",
            )
        return current_user

    return role_checker


def require_any_role(*roles: Union[UserRole, str]):
    """Reusable dependency to enforce access by any of the specified roles."""
    target_values = [r.value if isinstance(r, UserRole) else str(r) for r in roles]

    def roles_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in target_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {', '.join(target_values)}",
            )
        return current_user

    return roles_checker


def require_roles(allowed_roles: List[Union[UserRole, str]]):
    """Backward-compatible role-based authorization dependency factory."""
    return require_any_role(*allowed_roles)
