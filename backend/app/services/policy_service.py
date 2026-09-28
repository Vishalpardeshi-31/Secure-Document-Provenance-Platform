import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.models.document import Document
from app.models.access_policy import AccessPolicy
from app.models.user import User
from app.models.role import UserRole
from app.schemas.policy import AccessPolicyCreate, AccessPolicyUpdate
from app.policies.service import PolicyService as EnginePolicyService
from app.policies.exceptions import PolicyConfigurationException

logger = logging.getLogger("secure_document_platform.policy_service")


class PolicyService:
    """Manages creation, retrieval, and updating of document access policies.
    
    Delegates to the authoritative Phase 7 Policy Engine while maintaining
    full backward compatibility for existing callers.
    """

    @staticmethod
    def get_policy(db: Session, document_id: str, user: User) -> Optional[AccessPolicy]:
        """Retrieves active policy for a document if user is authorized."""
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError(f"Document with ID '{document_id}' not found.")

        # Check user can view document
        is_owner = doc.owner_id == user.id
        is_admin = user.role == UserRole.ADMIN.value
        is_recipient = any(r.user_id == user.id and r.status == "ACTIVE" for r in doc.recipients)

        if not (is_admin or is_owner or is_recipient):
            raise PermissionError("Access denied to document policy.")

        policy = EnginePolicyService.get_active_policy(db, document_id)
        if not policy:
            # Fall back to latest version if none active
            policy = (
                db.query(AccessPolicy)
                .filter(AccessPolicy.document_id == document_id)
                .order_by(AccessPolicy.policy_version.desc())
                .first()
            )
        return policy

    @staticmethod
    def create_or_update_policy(
        db: Session,
        document_id: str,
        user: User,
        data: AccessPolicyCreate | AccessPolicyUpdate,
    ) -> AccessPolicy:
        """Creates or updates document access policy using immutable versioning.
        
        Only ADMIN or document owner OFFICER can modify policies.
        Validates date ranges and positive constraints strictly.
        """
        try:
            allowed_roles = getattr(data, "allowed_roles", None)
            if isinstance(allowed_roles, str):
                allowed_roles = [r.strip() for r in allowed_roles.split(",") if r.strip()]

            return EnginePolicyService.update_policy(
                db=db,
                document_id=document_id,
                actor=user,
                valid_from=data.valid_from,
                valid_until=data.valid_until,
                max_decryptions=data.max_decryptions,
                require_registered_device=data.require_registered_device,
                require_approval=data.require_approval,
                require_multi_party_approval=getattr(data, "require_multi_party_approval", None),
                required_approvals=getattr(data, "required_approvals", None),
                eligible_approver_roles=getattr(data, "eligible_approver_roles", None),
                allow_emergency_access=getattr(data, "allow_emergency_access", None),
                eligible_emergency_roles=getattr(data, "eligible_emergency_roles", None),
                eligible_emergency_permission=getattr(data, "eligible_emergency_permission", None),
                emergency_approval_required=getattr(data, "emergency_approval_required", None),
                maximum_emergency_duration=getattr(data, "maximum_emergency_duration", None),
                allowed_roles=allowed_roles,
                enabled=data.enabled,
            )

        except PolicyConfigurationException as cfg_err:
            raise ValueError(str(cfg_err))
