"""Policy Evaluator executing sequential and atomic policy evaluations."""
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.access_policy import AccessPolicy
from app.policies.models import PolicyDecision
from app.policies.conditions import (
    PolicyCondition,
    UserStateCondition,
    DocumentStateCondition,
    PolicyStateCondition,
    RecipientAuthorizationCondition,
    RoleAuthorizationCondition,
    TimeWindowCondition,
    RegisteredDeviceCondition,
    MultiPartyApprovalCondition,
    DecryptionLimitCondition,
)


class PolicyEvaluator:
    """Production policy evaluator enforcing all configured access conditions.
    
    Rule: ALL conditions must pass.
    """

    DEFAULT_CONDITIONS: List[PolicyCondition] = [
        UserStateCondition(),
        DocumentStateCondition(),
        PolicyStateCondition(),
        RecipientAuthorizationCondition(),
        RoleAuthorizationCondition(),
        TimeWindowCondition(),
        RegisteredDeviceCondition(),
        MultiPartyApprovalCondition(),
        DecryptionLimitCondition(),
    ]


    def __init__(self, conditions: Optional[List[PolicyCondition]] = None):
        self.conditions = conditions if conditions is not None else self.DEFAULT_CONDITIONS

    def evaluate(
        self,
        db: Session,
        user: User,
        document: Document,
        recipient: Optional[DocumentRecipient],
        policy: Optional[AccessPolicy],
        device_id: Optional[str] = None,
        current_time: Optional[datetime] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """Evaluates all policy conditions.
        
        Returns:
            PolicyDecision with allowed=True if all pass, or allowed=False with reason_code.
        """
        now = current_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        for condition in self.conditions:
            decision = condition.evaluate(
                db=db,
                user=user,
                document=document,
                recipient=recipient,
                policy=policy,
                device_id=device_id,
                current_time=now,
                context=context,
            )
            if decision is not None and not decision.allowed:
                return decision

        return PolicyDecision.allow(
            policy_id=policy.id if policy else None,
            policy_version=policy.policy_version if policy else None,
            checked_at=now,
        )

    def evaluate_checks(
        self,
        db: Session,
        user: User,
        document: Document,
        recipient: Optional[DocumentRecipient],
        policy: Optional[AccessPolicy],
        device_id: Optional[str] = None,
        current_time: Optional[datetime] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluates each condition independently to provide granular check status for UI verification."""
        now = current_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        condition_map = {
            "identity_verified": UserStateCondition(),
            "document_active": DocumentStateCondition(),
            "policy_active": PolicyStateCondition(),
            "recipient_authorized": RecipientAuthorizationCondition(),
            "role_authorized": RoleAuthorizationCondition(),
            "time_window_valid": TimeWindowCondition(),
            "device_verified": RegisteredDeviceCondition(),
            "approval_verified": MultiPartyApprovalCondition(),
            "decryption_allowance_available": DecryptionLimitCondition(),
        }

        checks = {}
        for check_key, condition in condition_map.items():
            result = condition.evaluate(
                db=db,
                user=user,
                document=document,
                recipient=recipient,
                policy=policy,
                device_id=device_id,
                current_time=now,
                context=context,
            )
            # Check passes if condition returns None (allow) or decision.allowed is True
            checks[check_key] = result is None or result.allowed

        overall = self.evaluate(
            db=db,
            user=user,
            document=document,
            recipient=recipient,
            policy=policy,
            device_id=device_id,
            current_time=now,
            context=context,
        )


        return {
            "allowed": overall.allowed,
            "policy_id": overall.policy_id,
            "policy_version": overall.policy_version,
            "reason_code": overall.reason_code,
            "message": overall.message,
            "checked_at": now.isoformat(),
            "checks": checks,
        }


# Default singleton instance
default_evaluator = PolicyEvaluator()
