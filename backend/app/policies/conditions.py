"""Individual policy conditions evaluated by the policy engine.

All conditions evaluate strictly on the backend using server-controlled state.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.recipient_key import RecipientKey
from app.models.device import Device
from app.models.access_policy import AccessPolicy
from app.models.decryption_session import DecryptionSession
from app.models.approval import ApprovalRequest, ApprovalRecord
from app.policies.models import PolicyDecision, PolicyReasonCode



class PolicyCondition(ABC):
    """Abstract base class for all policy conditions."""

    name: str = "BaseCondition"

    @abstractmethod
    def evaluate(
        self,
        db: Session,
        user: User,
        document: Document,
        recipient: Optional[DocumentRecipient],
        policy: Optional[AccessPolicy],
        device_id: Optional[str],
        current_time: datetime,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[PolicyDecision]:
        """Evaluates the condition. Returns None if passed, or PolicyDecision if denied."""
        pass


class UserStateCondition(PolicyCondition):
    """Ensures requesting user account is active."""
    name = "UserState"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        if not user or not user.is_active:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.USER_INACTIVE.value,
                message="User account is inactive or disabled.",
                failed_condition=self.name,
                policy_id=policy.id if policy else None,
                policy_version=policy.policy_version if policy else None,
            )
        return None


class DocumentStateCondition(PolicyCondition):
    """Ensures document is active and has not been revoked or archived."""
    name = "DocumentState"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        doc_status = (document.status or "").upper()
        if doc_status == "REVOKED":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.DOCUMENT_REVOKED.value,
                message="Document has been administratively revoked.",
                failed_condition=self.name,
                policy_id=policy.id if policy else None,
                policy_version=policy.policy_version if policy else None,
            )
        if doc_status in ("ARCHIVED", "FAILED", "PENDING", "ENCRYPTING"):
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.DOCUMENT_NOT_AVAILABLE.value,
                message=f"Document is not available for decryption (status: {doc_status}).",
                failed_condition=self.name,
                policy_id=policy.id if policy else None,
                policy_version=policy.policy_version if policy else None,
            )
        return None


class RecipientAuthorizationCondition(PolicyCondition):
    """Enforces explicit recipient assignment and active ML-KEM key status.
    
    CRITICAL: Role-only access (even ADMIN) cannot bypass recipient assignment.
    """
    name = "RecipientAuthorization"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        if not recipient or recipient.user_id != user.id or recipient.status != "ACTIVE":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.RECIPIENT_NOT_AUTHORIZED.value,
                message="User is not an authorized active recipient for this document.",
                failed_condition=self.name,
                policy_id=policy.id if policy else None,
                policy_version=policy.policy_version if policy else None,
            )

        # Check recipient has an active ML-KEM key matching the version
        key_record = (
            db.query(RecipientKey)
            .filter(
                RecipientKey.user_id == user.id,
                RecipientKey.key_version == recipient.recipient_key_version,
            )
            .first()
        )
        if not key_record or key_record.status == "REVOKED":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.RECIPIENT_KEY_REVOKED.value,
                message="Recipient cryptographic key is revoked or unavailable.",
                failed_condition=self.name,
                policy_id=policy.id if policy else None,
                policy_version=policy.policy_version if policy else None,
            )
        return None


class RoleAuthorizationCondition(PolicyCondition):
    """Enforces role-based constraints. Auditors are strictly blocked from decrypting."""
    name = "RoleAuthorization"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        # Strict rule: Auditor role cannot decrypt
        if user.role == UserRole.AUDITOR.value:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_DENIED.value,
                message="Auditor role is not authorized to decrypt documents.",
                failed_condition=self.name,
                policy_id=policy.id if policy else None,
                policy_version=policy.policy_version if policy else None,
            )

        # If policy specifies allowed roles, check inclusion
        if policy and policy.allowed_roles:
            allowed = [r.strip().upper() for r in policy.allowed_roles.split(",") if r.strip()]
            user_role = (user.role or "").upper()
            if allowed and user_role not in allowed:
                return PolicyDecision.deny(
                    reason_code=PolicyReasonCode.ROLE_NOT_AUTHORIZED.value,
                    message=f"User role '{user.role}' is not in policy permitted roles: {', '.join(allowed)}.",
                    failed_condition=self.name,
                    policy_id=policy.id,
                    policy_version=policy.policy_version,
                )
        return None


class PolicyStateCondition(PolicyCondition):
    """Verifies that the policy itself is currently ACTIVE and not revoked."""
    name = "PolicyState"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        if not policy:
            return None

        policy_status = (getattr(policy, "status", None) or "ACTIVE").upper()
        if policy_status == "REVOKED":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_NOT_ACTIVE.value,
                message="Document access policy has been revoked.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )
        if not policy.enabled or policy_status != "ACTIVE":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_NOT_ACTIVE.value,
                message="Document access policy is not currently active.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )
        return None



class TimeWindowCondition(PolicyCondition):
    """Enforces server-side UTC time restrictions (not_before and expires_at)."""
    name = "TimeWindow"

    @staticmethod
    def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        if not policy:
            return None

        now = self._to_utc(current_time)

        # Check start window
        valid_from = self._to_utc(policy.valid_from)
        if valid_from and now < valid_from:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_NOT_YET_ACTIVE.value,
                message=f"Access window not active yet (not started yet, starts at {valid_from.isoformat()}).",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        # Check expiry window
        expires_at = self._to_utc(policy.valid_until or policy.expiration_time)
        if expires_at and now > expires_at:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_EXPIRED.value,
                message=f"Access window has expired (expired at {expires_at.isoformat()}).",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )
        return None


class RegisteredDeviceCondition(PolicyCondition):
    """Enforces hardware device registration, ownership, and active status."""
    name = "RegisteredDevice"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        if not policy:
            return None

        require_dev = policy.require_registered_device or policy.device_restriction
        if not require_dev:
            return None

        if not device_id:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.DEVICE_REQUIRED.value,
                message="Policy requires an authorized registered device.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.DEVICE_NOT_REGISTERED.value,
                message="Device is not registered in the platform.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        if device.user_id != user.id:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.DEVICE_NOT_AUTHORIZED.value,
                message="Device is not registered to the authenticated user.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        dev_status = (getattr(device, "status", None) or device.registration_status or "").upper()
        if dev_status == "REVOKED" or getattr(device, "revoked_at", None) is not None:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.DEVICE_REVOKED.value,
                message="Device registration has been revoked.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        if dev_status != "ACTIVE":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.DEVICE_NOT_AUTHORIZED.value,
                message=f"Device registration is {dev_status.lower()}, not active.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        return None


class DecryptionLimitCondition(PolicyCondition):
    """Enforces maximum allowed decryptions per policy (e.g. single-use or N-use)."""
    name = "DecryptionLimit"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        if not policy:
            return None

        effective_max = policy.max_decryptions
        if effective_max is None and policy.one_time_decryption:
            effective_max = 1

        if effective_max is not None and effective_max >= 1:
            # Check atomic consumed_decryptions on the policy if tracked, or count completed sessions
            consumed = getattr(policy, "consumed_decryptions", 0)
            if consumed >= effective_max:
                return PolicyDecision.deny(
                    reason_code=PolicyReasonCode.DECRYPTION_LIMIT_REACHED.value,
                    message=f"Maximum permitted decryptions ({effective_max}) reached for this document.",
                    failed_condition=self.name,
                    policy_id=policy.id,
                    policy_version=policy.policy_version,
                )

            # Also verify database session count for defense-in-depth
            completed_count = (
                db.query(DecryptionSession)
                .filter(
                    DecryptionSession.document_id == document.id,
                    DecryptionSession.user_id == user.id,
                    DecryptionSession.status == "COMPLETED",
                )
                .count()
            )
            if completed_count >= effective_max:
                return PolicyDecision.deny(
                    reason_code=PolicyReasonCode.DECRYPTION_LIMIT_REACHED.value,
                    message=f"Maximum permitted decryptions ({effective_max}) reached for this document.",
                    failed_condition=self.name,
                    policy_id=policy.id,
                    policy_version=policy.policy_version,
                )

        return None


class MultiPartyApprovalCondition(PolicyCondition):
    """Enforces multi-party approval requirements, independent approvers, and thresholds."""
    name = "MultiPartyApproval"

    def evaluate(self, db, user, document, recipient, policy, device_id, current_time, context=None):
        if not policy:
            return None

        requires_app = (
            getattr(policy, "require_multi_party_approval", False)
            or policy.require_approval
            or policy.approval_requirement
        )
        if not requires_app:
            return None

        # Look for approval request in context or query database
        approval_request_id = context.get("approval_request_id") if context else None
        if approval_request_id:
            req = db.query(ApprovalRequest).filter(ApprovalRequest.id == approval_request_id).first()
        else:
            req = (
                db.query(ApprovalRequest)
                .filter(
                    ApprovalRequest.document_id == document.id,
                    ApprovalRequest.requesting_user_id == user.id,
                    ApprovalRequest.policy_id == policy.id,
                    ApprovalRequest.policy_version == policy.policy_version,
                )
                .order_by(ApprovalRequest.created_at.desc())
                .first()
            )

        if not req:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_REQUIRES_APPROVAL.value,
                message="Access policy requires multi-party approval prior to decryption.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        # 1. Document / User / Policy version binding check
        if (
            req.document_id != document.id
            or req.requesting_user_id != user.id
            or req.policy_id != policy.id
            or req.policy_version != policy.policy_version
        ):
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_DENIED.value,
                message="Approval request does not match current document, user, or active policy version.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        # Check session binding: cannot be reused across different decryption sessions
        bound_session_id = context.get("session_id") if context else None
        if req.decryption_session_id and bound_session_id and req.decryption_session_id != bound_session_id:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_DENIED.value,
                message="Approval request has already been consumed by another decryption session.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )


        # 2. Expiration check
        utc_now = current_time if current_time.tzinfo else current_time.replace(tzinfo=timezone.utc)
        req_expires = req.expires_at if req.expires_at.tzinfo else req.expires_at.replace(tzinfo=timezone.utc)
        if utc_now > req_expires:
            if req.status == "PENDING":
                req.status = "EXPIRED"
                try:
                    db.commit()
                except Exception:
                    db.rollback()
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.APPROVAL_EXPIRED.value,
                message="Approval request has expired.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        # 3. Status checks
        if req.status == "REJECTED":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.APPROVAL_REJECTED.value,
                message="Approval request was rejected.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )
        if req.status == "CANCELLED":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_DENIED.value,
                message="Approval request was cancelled.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )
        if req.status == "EXPIRED":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.APPROVAL_EXPIRED.value,
                message="Approval request has expired.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )
        if req.status == "PENDING":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.APPROVAL_PENDING.value,
                message="Approval request is pending required approvals.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )
        if req.status != "APPROVED":
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_REQUIRES_APPROVAL.value,
                message=f"Approval request is in state '{req.status}', not approved.",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        # 4. Threshold & independence verification
        approved_records = (
            db.query(ApprovalRecord)
            .filter(
                ApprovalRecord.approval_request_id == req.id,
                ApprovalRecord.decision == "APPROVED",
            )
            .all()
        )
        distinct_approver_ids = set()
        for r in approved_records:
            if r.approver_user_id == req.requesting_user_id:
                return PolicyDecision.deny(
                    reason_code=PolicyReasonCode.POLICY_DENIED.value,
                    message="Approval request contains forbidden self-approval by requester.",
                    failed_condition=self.name,
                    policy_id=policy.id,
                    policy_version=policy.policy_version,
                )
            distinct_approver_ids.add(r.approver_user_id)

        if len(distinct_approver_ids) < req.required_approvals:
            return PolicyDecision.deny(
                reason_code=PolicyReasonCode.POLICY_REQUIRES_APPROVAL.value,
                message=f"Approval threshold not met ({len(distinct_approver_ids)}/{req.required_approvals}).",
                failed_condition=self.name,
                policy_id=policy.id,
                policy_version=policy.policy_version,
            )

        return None

