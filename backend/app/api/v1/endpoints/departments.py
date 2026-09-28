from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.schemas.department import DepartmentCreate, DepartmentUpdate, DepartmentResponse
from app.schemas.common import MessageResponse
from app.services.department_service import DepartmentService
from app.security.permissions import require_role, get_current_user

router = APIRouter()


@router.get(
    "",
    response_model=List[DepartmentResponse],
    summary="List all departments",
)
def list_departments(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves all departments from PostgreSQL."""
    dept_pairs = DepartmentService.list_departments(db=db)
    return [
        DepartmentResponse(
            id=d.id,
            name=d.name,
            code=d.code,
            description=d.description,
            is_active=d.is_active,
            user_count=count,
            created_at=d.created_at,
            updated_at=d.updated_at,
        )
        for d, count in dept_pairs
    ]


@router.post(
    "",
    response_model=DepartmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create department (Admin only)",
)
def create_department(
    request: DepartmentCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Creates a new organizational department. Only accessible by ADMIN."""
    try:
        dept = DepartmentService.create_department(
            db=db,
            name=request.name,
            code=request.code,
            description=request.description,
            actor_id=admin_user.id,
        )
        return DepartmentResponse(
            id=dept.id,
            name=dept.name,
            code=dept.code,
            description=dept.description,
            is_active=dept.is_active,
            user_count=0,
            created_at=dept.created_at,
            updated_at=dept.updated_at,
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )


@router.patch(
    "/{department_id}",
    response_model=DepartmentResponse,
    summary="Update or rename department (Admin only)",
)
def update_department(
    department_id: str,
    request: DepartmentUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Updates department name, code, description or active status. Only accessible by ADMIN."""
    try:
        dept = DepartmentService.update_department(
            db=db,
            department_id=department_id,
            name=request.name,
            code=request.code,
            description=request.description,
            is_active=request.is_active,
            actor_id=admin_user.id,
        )
        return DepartmentResponse(
            id=dept.id,
            name=dept.name,
            code=dept.code,
            description=dept.description,
            is_active=dept.is_active,
            user_count=len(dept.users) if dept.users else 0,
            created_at=dept.created_at,
            updated_at=dept.updated_at,
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )


@router.delete(
    "/{department_id}",
    response_model=MessageResponse,
    summary="Delete department (Admin only, referential integrity enforced)",
)
def delete_department(
    department_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Deletes a department only if no users are assigned. Only accessible by ADMIN."""
    try:
        DepartmentService.delete_department(
            db=db,
            department_id=department_id,
            actor_id=admin_user.id,
        )
        return MessageResponse(
            message=f"Department '{department_id}' deleted successfully.",
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(val_err),
        )
