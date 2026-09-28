from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.department import Department
from app.models.user import User
from app.services.audit_service import AuditService


class DepartmentService:
    @staticmethod
    def get_by_id(db: Session, department_id: str) -> Optional[Department]:
        return db.query(Department).filter(Department.id == department_id).first()

    @staticmethod
    def get_by_code(db: Session, code: str) -> Optional[Department]:
        return db.query(Department).filter(Department.code == code).first()

    @staticmethod
    def get_by_name(db: Session, name: str) -> Optional[Department]:
        return db.query(Department).filter(Department.name == name).first()

    @staticmethod
    def list_departments(db: Session, include_inactive: bool = True) -> List[Tuple[Department, int]]:
        """Lists all departments along with the count of assigned users."""
        query = db.query(
            Department,
            func.count(User.id).label("user_count")
        ).outerjoin(User, User.department_id == Department.id)

        if not include_inactive:
            query = query.filter(Department.is_active == True)  # noqa: E712

        results = query.group_by(Department.id).order_by(Department.name).all()
        return [(dept, count) for dept, count in results]

    @staticmethod
    def create_department(
        db: Session,
        name: str,
        code: str,
        description: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> Department:
        """Creates a new department, checking uniqueness and logging an audit event."""
        norm_code = code.strip().upper()
        norm_name = name.strip()

        if DepartmentService.get_by_name(db, norm_name):
            raise ValueError(f"Department with name '{norm_name}' already exists.")

        if DepartmentService.get_by_code(db, norm_code):
            raise ValueError(f"Department with code '{norm_code}' already exists.")

        dept = Department(
            name=norm_name,
            code=norm_code,
            description=description.strip() if description else None,
            is_active=True,
        )
        db.add(dept)
        db.commit()
        db.refresh(dept)

        AuditService.log_event(
            db=db,
            event_type="DEPARTMENT_CREATED",
            user_id=actor_id,
            metadata={
                "department_id": dept.id,
                "name": dept.name,
                "code": dept.code,
            },
        )
        return dept

    @staticmethod
    def update_department(
        db: Session,
        department_id: str,
        name: Optional[str] = None,
        code: Optional[str] = None,
        description: Optional[str] = None,
        is_active: Optional[bool] = None,
        actor_id: Optional[str] = None,
    ) -> Department:
        """Updates department details, preserving uniqueness and logging an audit event."""
        dept = DepartmentService.get_by_id(db, department_id)
        if not dept:
            raise ValueError(f"Department with ID '{department_id}' does not exist.")

        if name is not None:
            norm_name = name.strip()
            existing = DepartmentService.get_by_name(db, norm_name)
            if existing and existing.id != dept.id:
                raise ValueError(f"Department with name '{norm_name}' already exists.")
            dept.name = norm_name

        if code is not None:
            norm_code = code.strip().upper()
            existing = DepartmentService.get_by_code(db, norm_code)
            if existing and existing.id != dept.id:
                raise ValueError(f"Department with code '{norm_code}' already exists.")
            dept.code = norm_code

        if description is not None:
            dept.description = description.strip() if description else None

        if is_active is not None:
            dept.is_active = is_active

        db.commit()
        db.refresh(dept)

        AuditService.log_event(
            db=db,
            event_type="DEPARTMENT_UPDATED",
            user_id=actor_id,
            metadata={
                "department_id": dept.id,
                "name": dept.name,
                "code": dept.code,
                "is_active": dept.is_active,
            },
        )
        return dept

    @staticmethod
    def delete_department(db: Session, department_id: str, actor_id: Optional[str] = None) -> None:
        """Deletes department if and only if no users are assigned (referential integrity protection)."""
        dept = DepartmentService.get_by_id(db, department_id)
        if not dept:
            raise ValueError(f"Department with ID '{department_id}' does not exist.")

        # Enforce referential integrity
        user_count = db.query(User).filter(User.department_id == department_id).count()
        if user_count > 0:
            raise ValueError(
                f"Cannot delete department '{dept.name}': {user_count} user(s) are currently assigned to it. "
                "Reassign or remove users first, or deactivate the department."
            )

        name = dept.name
        code = dept.code
        db.delete(dept)
        db.commit()

        AuditService.log_event(
            db=db,
            event_type="DEPARTMENT_DELETED",
            user_id=actor_id,
            metadata={
                "department_id": department_id,
                "name": name,
                "code": code,
            },
        )
