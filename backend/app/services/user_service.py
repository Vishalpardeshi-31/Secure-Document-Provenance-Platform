from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.user import User
from app.models.role import UserRole, Role
from app.models.department import Department
from app.models.revoked_token import RevokedToken
from app.security.password import hash_password, validate_password_strength
from app.services.audit_service import AuditService
from datetime import datetime, timezone, timedelta


class UserService:
    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def get_user_by_username(db: Session, username: str) -> Optional[User]:
        return db.query(User).filter(User.username == username).first()

    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def list_users(
        db: Session,
        offset: int = 0,
        limit: int = 100,
        role: Optional[str] = None,
        department_id: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> Tuple[List[User], int]:
        """Lists users with optional filtering and pagination."""
        query = db.query(User)
        if role:
            query = query.filter(User.role == role)
        if department_id:
            query = query.filter(User.department_id == department_id)
        if is_active is not None:
            query = query.filter(User.is_active == is_active)

        total = query.count()
        users = query.order_by(desc(User.created_at)).offset(offset).limit(limit).all()
        return users, total

    @staticmethod
    def create_user(
        db: Session,
        username: str,
        email: str,
        plain_password: str,
        role: str = UserRole.RECIPIENT.value,
        department_id: Optional[str] = None,
        actor_id: Optional[str] = None,
    ) -> User:
        """Validates strength, checks uniqueness, hashes password with Argon2id, persists user,
        and logs genuine audit event."""
        # Validate password strength
        valid, error_msg = validate_password_strength(plain_password)
        if not valid:
            raise ValueError(error_msg)

        # Validate role
        role_val = role.value if isinstance(role, UserRole) else str(role).upper()
        valid_roles = [r.value for r in UserRole]
        if role_val not in valid_roles:
            raise ValueError(f"Invalid role '{role}'. Allowed roles: {', '.join(valid_roles)}")

        # Check existing username
        if UserService.get_user_by_username(db, username):
            raise ValueError(f"Username '{username}' is already in use.")

        # Check existing email
        if UserService.get_user_by_email(db, email):
            raise ValueError(f"Email '{email}' is already in use.")

        # Check department if provided
        if department_id:
            dept = db.query(Department).filter(Department.id == department_id).first()
            if not dept:
                raise ValueError(f"Department with ID '{department_id}' does not exist.")

        # Resolve role_id from roles table if it exists
        role_record = db.query(Role).filter(Role.name == role_val).first()
        role_id = role_record.id if role_record else None

        # Hash with Argon2id
        pw_hash = hash_password(plain_password)

        new_user = User(
            username=username,
            email=email,
            password_hash=pw_hash,
            role=role_val,
            role_id=role_id,
            department_id=department_id,
            is_active=True,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Record real audit event
        AuditService.log_event(
            db=db,
            event_type="USER_CREATED",
            user_id=actor_id or new_user.id,
            metadata={
                "created_user_id": new_user.id,
                "username": new_user.username,
                "role": new_user.role,
                "department_id": new_user.department_id,
            },
        )

        return new_user

    @staticmethod
    def update_user(
        db: Session,
        user_id: str,
        role: Optional[str] = None,
        department_id: Optional[str] = None,
        is_active: Optional[bool] = None,
        actor_id: Optional[str] = None,
    ) -> User:
        """Updates user role, department assignment, or active status and logs audit events."""
        user = UserService.get_user_by_id(db, user_id)
        if not user:
            raise ValueError(f"User with ID '{user_id}' does not exist.")

        # Role change
        if role is not None:
            role_val = role.value if isinstance(role, UserRole) else str(role).upper()
            valid_roles = [r.value for r in UserRole]
            if role_val not in valid_roles:
                raise ValueError(f"Invalid role '{role}'. Allowed roles: {', '.join(valid_roles)}")
            
            if user.role != role_val:
                old_role = user.role
                user.role = role_val
                role_record = db.query(Role).filter(Role.name == role_val).first()
                if role_record:
                    user.role_id = role_record.id

                AuditService.log_event(
                    db=db,
                    event_type="ROLE_CHANGED",
                    user_id=actor_id or user.id,
                    metadata={
                        "target_user_id": user.id,
                        "old_role": old_role,
                        "new_role": role_val,
                    },
                )

        # Department change
        if department_id is not None:
            if department_id != "":
                dept = db.query(Department).filter(Department.id == department_id).first()
                if not dept:
                    raise ValueError(f"Department with ID '{department_id}' does not exist.")
                user.department_id = department_id
            else:
                user.department_id = None

        # Active status change
        if is_active is not None and is_active != user.is_active:
            user.is_active = is_active
            event_type = "USER_ACTIVATED" if is_active else "USER_DEACTIVATED"
            AuditService.log_event(
                db=db,
                event_type=event_type,
                user_id=actor_id or user.id,
                metadata={
                    "target_user_id": user.id,
                    "target_username": user.username,
                    "is_active": is_active,
                },
            )

        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def reset_password(
        db: Session,
        user_id: str,
        new_plain_password: str,
        actor_id: Optional[str] = None,
    ) -> User:
        """Resets user's password after validating strength, updates Argon2id hash,
        and logs PASSWORD_RESET audit event."""
        user = UserService.get_user_by_id(db, user_id)
        if not user:
            raise ValueError(f"User with ID '{user_id}' does not exist.")

        valid, error_msg = validate_password_strength(new_plain_password)
        if not valid:
            raise ValueError(error_msg)

        user.password_hash = hash_password(new_plain_password)
        db.commit()
        db.refresh(user)

        AuditService.log_event(
            db=db,
            event_type="PASSWORD_RESET",
            user_id=actor_id or user.id,
            metadata={
                "target_user_id": user.id,
                "target_username": user.username,
            },
        )
        return user
