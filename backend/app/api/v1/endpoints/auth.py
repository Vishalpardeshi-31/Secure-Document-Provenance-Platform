from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.schemas.auth import LoginRequest, TokenResponse, UserResponse, LogoutResponse
from app.services.auth_service import AuthService
from app.security.permissions import get_current_user, security_scheme
from app.models.user import User

router = APIRouter()


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT token",
)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """Authenticates credentials against Argon2id hash and issues a short-lived access token."""
    user, failure_reason = AuthService.authenticate_user(
        db=db,
        username_or_email=request.username_or_email,
        plain_password=request.password,
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

    return AuthService.issue_token_for_user(user)


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
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user's profile information."""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        department_id=current_user.department_id,
        department_name=current_user.department.name if current_user.department else None,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
    )
