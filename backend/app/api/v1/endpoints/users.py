from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.schemas.auth import (
    UserResponse,
    AdminCreateUserRequest,
    AdminUpdateUserRequest,
    PasswordResetRequest,
)
from app.schemas.common import MessageResponse
from app.services.user_service import UserService
from app.security.permissions import require_role, get_current_user

router = APIRouter()


def _to_user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        department_id=user.department_id,
        department_name=user.department.name if user.department else None,
        is_active=user.is_active,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.get(
    "",
    response_model=List[UserResponse],
    summary="List all users (Admin only)",
)
def list_users(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    role: Optional[str] = Query(None),
    department_id: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Retrieves users from PostgreSQL. Only accessible by ADMIN."""
    users, _ = UserService.list_users(
        db=db,
        offset=offset,
        limit=limit,
        role=role,
        department_id=department_id,
        is_active=is_active,
    )
    return [_to_user_response(u) for u in users]


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create user account (Admin only)",
)
def create_user(
    request: AdminCreateUserRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Creates a real user account with Argon2id password hash. Only accessible by ADMIN."""
    try:
        user = UserService.create_user(
            db=db,
            username=request.username,
            email=request.email,
            plain_password=request.password,
            role=request.role,
            department_id=request.department_id,
            actor_id=admin_user.id,
        )
        return _to_user_response(user)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user details by ID",
)
def get_user_details(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves user profile. Requires ADMIN role or accessing own profile."""
    if current_user.role != UserRole.ADMIN.value and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only view your own user profile.",
        )

    user = UserService.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return _to_user_response(user)


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user role, department, or active status (Admin only)",
)
def update_user(
    user_id: str,
    request: AdminUpdateUserRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Updates user status, department, or role. Only accessible by ADMIN."""
    try:
        user = UserService.update_user(
            db=db,
            user_id=user_id,
            role=request.role,
            department_id=request.department_id,
            is_active=request.is_active,
            actor_id=admin_user.id,
        )
        return _to_user_response(user)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )


@router.post(
    "/{user_id}/reset-password",
    response_model=MessageResponse,
    summary="Reset a user password (Admin only)",
)
def reset_user_password(
    user_id: str,
    request: PasswordResetRequest,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Resets user's password with Argon2id validation and hashing. Only accessible by ADMIN."""
    try:
        UserService.reset_password(
            db=db,
            user_id=user_id,
            new_plain_password=request.new_password,
            actor_id=admin_user.id,
        )
        return MessageResponse(
            message=f"Password for user '{user_id}' has been securely reset.",
            detail="Argon2id hash updated. Any active sessions should re-authenticate.",
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
