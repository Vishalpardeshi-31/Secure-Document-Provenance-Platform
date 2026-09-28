"""Policy Service managing access policy lifecycle, immutable versioning, and atomic allowance consumption."""
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.access_policy import AccessPolicy
from app.models.document import Document
from app.models.user import User
from app.models.role import UserRole
from app.policies.models import PolicyStatus, DocumentLifecycleStatus, PolicyReasonCode
from app.policies.exceptions import PolicyConfigurationException, PolicyDeniedException
from app.services.audit_service import AuditService

logger = logging.getLogger("secure_document_platform.policy_service")


class PolicyService:
    """Manages document access policies with strict versioning, RBAC, and concurrency-safe consumption."""

    @staticmethod
    def _validate_dates(valid_from: Optional[datetime], valid_until: Optional[datetime]) -> None:
        if valid_from and valid_until and valid_until <= valid_from:
            raise PolicyConfigurationException("Access window 'valid_until' must be strictly after 'valid_from'.")

    @staticmethod
    def _check_management_permission(document: Document, actor: User) -> None:
        """Ensures actor is the document owner or an authorized ADMIN/OFFICER."""
        if actor.role == UserRole.ADMIN.value:
            return
        if document.owner_id == actor.id and actor.role == UserRole.OFFICER.value:
            return
        raise PermissionError("User is not authorized to configure or manage access policy for this document.")

    @classmethod
    def get_active_policy(cls, db: Session, document_id: str) -> Optional[AccessPolicy]:
        """Retrieves the currently ACTIVE access policy for a document."""
        return (
            db.query(AccessPolicy)
            .filter(
                AccessPolicy.document_id == document_id,
                AccessPolicy.status == PolicyStatus.ACTIVE.value,
                AccessPolicy.enabled == True,  # noqa: E712
            )
            .order_by(desc(AccessPolicy.policy_version))
            .first()
        )

    @classmethod
    def list_policy_versions(cls, db: Session, document_id: str) -> List[AccessPolicy]:
        """Returns the full historical sequence of policy versions for a document."""
        return (
            db.query(AccessPolicy)
            .filter(AccessPolicy.document_id == document_id)
            .order_by(desc(AccessPolicy.policy_version))
            .all()
        )

    @classmethod
    def create_policy(
        cls,
        db: Session,
        document_id: str,
        actor: User,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        max_decryptions: Optional[int] = None,
        require_registered_device: bool = False,
        require_approval: bool = False,
        require_multi_party_approval: Optional[bool] = None,
        required_approvals: int = 1,
        eligible_approver_roles: Optional[Any] = None,
        allow_emergency_access: bool = False,
        eligible_emergency_roles: Optional[Any] = None,
        eligible_emergency_permission: Optional[str] = "EMERGENCY_DECRYPT",
        emergency_approval_required: bool = True,
        maximum_emergency_duration: int = 15,
        allowed_roles: Optional[Any] = None,
    ) -> AccessPolicy:
        """Creates a new policy version for a document, preserving historical policy records."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError(f"Document with ID '{document_id}' not found.")

        cls._check_management_permission(doc, actor)
        cls._validate_dates(valid_from, valid_until)

        if max_decryptions is not None and max_decryptions < 1:
            raise PolicyConfigurationException("max_decryptions must be at least 1.")

        if required_approvals is not None and required_approvals < 1:
            raise PolicyConfigurationException("required_approvals must be at least 1.")

        if maximum_emergency_duration is not None and (maximum_emergency_duration < 1 or maximum_emergency_duration > 120):
            raise PolicyConfigurationException("maximum_emergency_duration must be between 1 and 120 minutes.")

        # Determine next policy version
        latest_policy = (
            db.query(AccessPolicy)
            .filter(AccessPolicy.document_id == document_id)
            .order_by(desc(AccessPolicy.policy_version))
            .first()
        )
        next_version = (latest_policy.policy_version + 1) if latest_policy else 1

        # Deactivate any previous active policy version without overwriting historical state
        if latest_policy and latest_policy.status == PolicyStatus.ACTIVE.value:
            latest_policy.status = PolicyStatus.EXPIRED.value
            latest_policy.enabled = False
            db.add(latest_policy)

        def _format_roles(r):
            if not r:
                return None
            if isinstance(r, list):
                return ",".join([item.strip().upper() for item in r if item and item.strip()])
            return ",".join([item.strip().upper() for item in str(r).split(",") if item and item.strip()])

        roles_str = _format_roles(allowed_roles)
        approver_roles_str = _format_roles(eligible_approver_roles)
        emergency_roles_str = _format_roles(eligible_emergency_roles)

        eff_approval = require_multi_party_approval if require_multi_party_approval is not None else require_approval

        policy = AccessPolicy(
            document_id=doc.id,
            policy_version=next_version,
            status=PolicyStatus.ACTIVE.value,
            enabled=True,
            valid_from=valid_from,
            valid_until=valid_until,
            expiration_time=valid_until,
            max_decryptions=max_decryptions,
            maximum_sessions=max_decryptions,
            one_time_decryption=(max_decryptions == 1),
            require_registered_device=require_registered_device,
            device_restriction=require_registered_device,
            require_approval=eff_approval,
            approval_requirement=eff_approval,
            require_multi_party_approval=eff_approval,
            required_approvals=required_approvals if required_approvals is not None else 1,
            eligible_approver_roles=approver_roles_str,
            allow_emergency_access=allow_emergency_access,
            eligible_emergency_roles=emergency_roles_str,
            eligible_emergency_permission=eligible_emergency_permission or "EMERGENCY_DECRYPT",
            emergency_approval_required=emergency_approval_required,
            maximum_emergency_duration=maximum_emergency_duration or 15,
            allowed_roles=roles_str,
            consumed_decryptions=0,
            created_by=actor.id,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)

        AuditService.log_event(
            db=db,
            event_type="POLICY_CREATED",
            user_id=actor.id,
            document_id=doc.id,
            metadata={
                "policy_id": policy.id,
                "policy_version": policy.policy_version,
                "valid_from": valid_from.isoformat() if valid_from else None,
                "valid_until": valid_until.isoformat() if valid_until else None,
                "max_decryptions": max_decryptions,
                "require_registered_device": require_registered_device,
                "require_multi_party_approval": eff_approval,
                "required_approvals": policy.required_approvals,
                "allow_emergency_access": allow_emergency_access,
                "allowed_roles": roles_str,
            },
        )
        return policy

    @classmethod
    def update_policy(
        cls,
        db: Session,
        document_id: str,
        actor: User,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        max_decryptions: Optional[int] = None,
        require_registered_device: Optional[bool] = None,
        require_approval: Optional[bool] = None,
        require_multi_party_approval: Optional[bool] = None,
        required_approvals: Optional[int] = None,
        eligible_approver_roles: Optional[Any] = None,
        allow_emergency_access: Optional[bool] = None,
        eligible_emergency_roles: Optional[Any] = None,
        eligible_emergency_permission: Optional[str] = None,
        emergency_approval_required: Optional[bool] = None,
        maximum_emergency_duration: Optional[int] = None,
        allowed_roles: Optional[Any] = None,
        enabled: Optional[bool] = None,
    ) -> AccessPolicy:
        """Updates access policy by versioning: archives previous version and creates new active version."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError(f"Document with ID '{document_id}' not found.")

        cls._check_management_permission(doc, actor)

        current = cls.get_active_policy(db, document_id)
        if not current:
            return cls.create_policy(
                db=db,
                document_id=document_id,
                actor=actor,
                valid_from=valid_from,
                valid_until=valid_until,
                max_decryptions=max_decryptions,
                require_registered_device=bool(require_registered_device),
                require_approval=bool(require_approval),
                require_multi_party_approval=require_multi_party_approval,
                required_approvals=required_approvals or 1,
                eligible_approver_roles=eligible_approver_roles,
                allow_emergency_access=bool(allow_emergency_access),
                eligible_emergency_roles=eligible_emergency_roles,
                eligible_emergency_permission=eligible_emergency_permission,
                emergency_approval_required=emergency_approval_required if emergency_approval_required is not None else True,
                maximum_emergency_duration=maximum_emergency_duration or 15,
                allowed_roles=allowed_roles,
            )

        eff_from = valid_from if valid_from is not None else current.valid_from
        eff_until = valid_until if valid_until is not None else current.valid_until
        cls._validate_dates(eff_from, eff_until)

        eff_max = max_decryptions if max_decryptions is not None else current.max_decryptions
        if eff_max is not None and eff_max < 1:
            raise PolicyConfigurationException("max_decryptions must be at least 1.")

        eff_dev = require_registered_device if require_registered_device is not None else current.require_registered_device

        eff_app_arg = require_multi_party_approval if require_multi_party_approval is not None else require_approval
        eff_app = eff_app_arg if eff_app_arg is not None else (current.require_multi_party_approval or current.require_approval)

        eff_req_app = required_approvals if required_approvals is not None else current.required_approvals
        if eff_req_app is not None and eff_req_app < 1:
            raise PolicyConfigurationException("required_approvals must be at least 1.")

        def _format_roles(r):
            if r is None:
                return None
            if isinstance(r, list):
                return ",".join([item.strip().upper() for item in r if item and item.strip()])
            return ",".join([item.strip().upper() for item in str(r).split(",") if item and item.strip()])

        eff_app_roles = _format_roles(eligible_approver_roles) if eligible_approver_roles is not None else current.eligible_approver_roles
        eff_emerg_access = allow_emergency_access if allow_emergency_access is not None else current.allow_emergency_access
        eff_emerg_roles = _format_roles(eligible_emergency_roles) if eligible_emergency_roles is not None else current.eligible_emergency_roles
        eff_emerg_perm = eligible_emergency_permission if eligible_emergency_permission is not None else current.eligible_emergency_permission
        eff_emerg_req = emergency_approval_required if emergency_approval_required is not None else current.emergency_approval_required
        eff_emerg_dur = maximum_emergency_duration if maximum_emergency_duration is not None else current.maximum_emergency_duration
        if eff_emerg_dur is not None and (eff_emerg_dur < 1 or eff_emerg_dur > 120):
            raise PolicyConfigurationException("maximum_emergency_duration must be between 1 and 120 minutes.")

        eff_enabled = enabled if enabled is not None else True
        roles_str = _format_roles(allowed_roles) if allowed_roles is not None else current.allowed_roles

        # Archive old version
        current.status = PolicyStatus.EXPIRED.value
        current.enabled = False
        db.add(current)

        # Create incremented version
        new_version = current.policy_version + 1
        new_policy = AccessPolicy(
            document_id=doc.id,
            policy_version=new_version,
            status=PolicyStatus.ACTIVE.value if eff_enabled else PolicyStatus.EXPIRED.value,
            enabled=eff_enabled,
            valid_from=eff_from,
            valid_until=eff_until,
            expiration_time=eff_until,
            max_decryptions=eff_max,
            maximum_sessions=eff_max,
            one_time_decryption=(eff_max == 1),
            require_registered_device=eff_dev,
            device_restriction=eff_dev,
            require_approval=eff_app,
            approval_requirement=eff_app,
            require_multi_party_approval=eff_app,
            required_approvals=eff_req_app or 1,
            eligible_approver_roles=eff_app_roles,
            allow_emergency_access=eff_emerg_access,
            eligible_emergency_roles=eff_emerg_roles,
            eligible_emergency_permission=eff_emerg_perm or "EMERGENCY_DECRYPT",
            emergency_approval_required=eff_emerg_req,
            maximum_emergency_duration=eff_emerg_dur or 15,
            allowed_roles=roles_str,
            consumed_decryptions=0,
            created_by=actor.id,
        )
        db.add(new_policy)
        db.commit()
        db.refresh(new_policy)

        AuditService.log_event(
            db=db,
            event_type="POLICY_UPDATED",
            user_id=actor.id,
            document_id=doc.id,
            metadata={
                "previous_policy_id": current.id,
                "previous_version": current.policy_version,
                "new_policy_id": new_policy.id,
                "new_version": new_policy.policy_version,
                "require_multi_party_approval": eff_app,
                "required_approvals": new_policy.required_approvals,
                "allow_emergency_access": eff_emerg_access,
            },
        )
        return new_policy


    @classmethod
    def revoke_policy(cls, db: Session, document_id: str, actor: User) -> AccessPolicy:
        """Revokes the active policy for a document."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError(f"Document with ID '{document_id}' not found.")

        cls._check_management_permission(doc, actor)

        active = cls.get_active_policy(db, document_id)
        if not active:
            raise ValueError("No active access policy found for this document.")

        active.status = PolicyStatus.REVOKED.value
        active.enabled = False
        db.commit()
        db.refresh(active)

        AuditService.log_event(
            db=db,
            event_type="POLICY_REVOKED",
            user_id=actor.id,
            document_id=doc.id,
            metadata={
                "policy_id": active.id,
                "policy_version": active.policy_version,
            },
        )
        return active

    @classmethod
    def reserve_and_consume_decryption(
        cls,
        db: Session,
        policy_id: Optional[str],
        user_id: str,
        document_id: str,
    ) -> None:
        """Atomically checks and consumes a decryption allowance with row-level locking.
        
        Concurrency guarantee:
        Two simultaneous requests cannot both succeed if only one remaining decryption is available.
        """
        if not policy_id:
            return

        # Acquire row lock for atomic counter increment
        policy = (
            db.query(AccessPolicy)
            .filter(AccessPolicy.id == policy_id)
            .with_for_update()
            .first()
        )
        if not policy:
            return

        effective_max = policy.max_decryptions
        if effective_max is None and policy.one_time_decryption:
            effective_max = 1

        if effective_max is not None and effective_max >= 1:
            if policy.consumed_decryptions >= effective_max:
                raise PolicyDeniedException(
                    reason_code=PolicyReasonCode.DECRYPTION_LIMIT_REACHED.value,
                    message=f"Maximum permitted decryptions ({effective_max}) reached for this document.",
                    policy_id=policy.id,
                    policy_version=policy.policy_version,
                )
            # Atomically increment consumed counter
            policy.consumed_decryptions += 1
            db.flush()

    @classmethod
    def revoke_document(cls, db: Session, document_id: str, actor: User) -> Document:
        """Administratively revokes a document, immediately preventing any decryption."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError(f"Document with ID '{document_id}' not found.")

        cls._check_management_permission(doc, actor)

        doc.status = DocumentLifecycleStatus.REVOKED.value
        db.commit()
        db.refresh(doc)

        AuditService.log_event(
            db=db,
            event_type="DOCUMENT_REVOKED",
            user_id=actor.id,
            document_id=doc.id,
            metadata={
                "previous_status": "ACTIVE",
                "new_status": "REVOKED",
            },
        )
        return doc

    @classmethod
    def reactivate_document(cls, db: Session, document_id: str, actor: User) -> Document:
        """Reactivates a revoked document."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError(f"Document with ID '{document_id}' not found.")

        cls._check_management_permission(doc, actor)

        doc.status = DocumentLifecycleStatus.ACTIVE.value
        db.commit()
        db.refresh(doc)

        AuditService.log_event(
            db=db,
            event_type="DOCUMENT_REACTIVATED",
            user_id=actor.id,
            document_id=doc.id,
            metadata={
                "previous_status": "REVOKED",
                "new_status": "ACTIVE",
            },
        )
        return doc
