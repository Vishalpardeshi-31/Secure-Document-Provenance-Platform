from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserResponse,
    LogoutResponse,
    SessionResponse,
)
from app.schemas.common import MessageResponse
from app.services.auth_service import AuthService
from app.services.session_service import SessionService
from app.security.permissions import get_current_user, security_scheme
from app.security.rate_limiter import auth_rate_limiter, get_client_ip
from app.models.user import User


def _to_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


router = APIRouter()


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT token",
)
def login(
    login_req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Authenticates credentials against Argon2id hash with rate limiting and lockout protection."""
    client_ip = get_client_ip(request)
    auth_rate_limiter.check_rate_limit(f"login_ip:{client_ip}", max_requests=30, window_seconds=60)
    auth_rate_limiter.check_rate_limit(f"login_user:{login_req.username_or_email}", max_requests=10, window_seconds=60)

    user, failure_reason = AuthService.authenticate_user(
        db=db,
        username_or_email=login_req.username_or_email,
        plain_password=login_req.password,
    )

    if failure_reason == "ACCOUNT_LOCKED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to repeated failed login attempts. Please try again later.",
        )

    if failure_reason == "ACCOUNT_INACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive.",
        )

    if not user or failure_reason == "INVALID_CREDENTIALS":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    # Check if MFA is enabled for this user
    if AuthService.is_mfa_enabled(db, user.id):
        mfa_token = AuthService.issue_mfa_challenge_token(user)
        return TokenResponse(
            mfa_required=True,
            mfa_token=mfa_token,
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            auth_assurance_level="NORMAL",
        )

    # Standard login without MFA
    return AuthService.issue_token_for_user(
        db=db,
        user=user,
        device_id=login_req.device_id,
        auth_assurance_level="NORMAL",
        ip_metadata=client_ip,
        user_agent_metadata=request.headers.get("User-Agent", "")[:255],
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Invalidate active session",
)
def logout(
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
):
    """Invalidates the authenticated session token and logs audit event."""
    if credentials and credentials.credentials:
        AuthService.logout_user(db=db, token=credentials.credentials, user=current_user)
    return LogoutResponse(message="Successfully logged out. Session invalidated.")


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current authenticated user profile",
)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns the authenticated user's profile information."""
    mfa_enabled = AuthService.is_mfa_enabled(db, current_user.id)
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        department_id=current_user.department_id,
        department_name=current_user.department.name if current_user.department else None,
        is_active=current_user.is_active,
        mfa_enabled=mfa_enabled,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
    )


@router.get(
    "/sessions",
    response_model=List[SessionResponse],
    summary="List active sessions for current user",
)
def list_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Lists server-tracked authentication sessions for the current user."""
    sessions = SessionService.list_user_sessions(db, current_user.id)
    now = datetime.now(timezone.utc)
    return [
        SessionResponse(
            id=s.id,
            user_id=s.user_id,
            device_id=s.device_id,
            created_at=s.created_at,
            last_activity_at=s.last_activity_at,
            expires_at=s.expires_at,
            revoked_at=s.revoked_at,
            authentication_level=s.authentication_level,
            is_active=(s.revoked_at is None and _to_utc(s.expires_at) > now),
        )
        for s in sessions
    ]


@router.post(
    "/sessions/{session_id}/revoke",
    response_model=MessageResponse,
    summary="Revoke an authenticated user session",
)
def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revokes a specific session by ID, invalidating its token and terminating access."""
    try:
        SessionService.revoke_session(db=db, session_id=session_id, actor=current_user)
        return MessageResponse(message=f"Session '{session_id}' successfully revoked.")
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
