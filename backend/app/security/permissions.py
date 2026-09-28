from typing import List, Union
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.models.revoked_token import RevokedToken
from app.security.tokens import decode_access_token

security_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Authenticates the bearer token, verifies signature & expiration, checks revocation status,
    and retrieves the current active user from the database."""
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

    # Check session revocation / token blacklist
    jti = payload.get("jti")
    if jti:
        try:
            is_revoked = db.query(RevokedToken).filter(RevokedToken.token_jti == jti).first()
        except Exception:
            import time
            time.sleep(0.01)
            is_revoked = db.query(RevokedToken).filter(RevokedToken.token_jti == jti).first()

        if is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has been revoked or logged out.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user_id = payload["sub"]
    try:
        user = db.query(User).filter(User.id == user_id).first()
    except Exception:
        import time
        time.sleep(0.01)
        user = db.query(User).filter(User.id == user_id).first()

    if not user:
        import time
        time.sleep(0.02)
        try:
            user = db.query(User).filter(User.id == user_id).first()
        except Exception:
            user = None

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

    return user


# Reusable alias for require_authenticated_user()
require_authenticated_user = get_current_user


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
