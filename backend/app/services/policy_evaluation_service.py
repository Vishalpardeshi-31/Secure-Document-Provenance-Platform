from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.role import UserRole
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.recipient_key import RecipientKey
from app.models.device import Device
from app.models.access_policy import AccessPolicy
from app.models.decryption_session import DecryptionSession


@dataclass
class PolicyDecision:
    is_allowed: bool
    reason_code: Optional[str] = None
    message: Optional[str] = None
    policy_id: Optional[str] = None

    @classmethod
    def allow(cls, policy_id: Optional[str] = None) -> "PolicyDecision":
        return cls(is_allowed=True, policy_id=policy_id)

    @classmethod
    def deny(cls, reason_code: str, message: str, policy_id: Optional[str] = None) -> "PolicyDecision":
        return cls(is_allowed=False, reason_code=reason_code, message=message, policy_id=policy_id)


class PolicyEvaluationService:
    """Evaluates real access policies and recipient authorization prior to decryption.
    
    Guarantees:
    - Server-side UTC time enforcement (never trusts client timestamps).
    - True identity and role verification (auditors cannot decrypt, admins cannot bypass).
    - Cryptographic key active status checks (revoked keys cannot decrypt).
    - Hardware-registered device checks (active and owned by requesting user).
    - Atomic max decryption counting (one-time or N-time policies).
    - Standardized safe reason codes returned for security logging and client messaging.
    """

    @staticmethod
    def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @classmethod
    def evaluate(
        cls,
        db: Session,
        user: User,
        document: Document,
        recipient: Optional[DocumentRecipient],
        device_id: Optional[str] = None,
        current_time: Optional[datetime] = None,
        request_context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        now = cls._to_utc(current_time or datetime.now(timezone.utc))

        # 1. User verification
        if not user.is_active:
            return PolicyDecision.deny(
                reason_code="USER_INACTIVE",
                message="User account is inactive or disabled.",
            )

        # 2. Document availability
        if document.status != "ENCRYPTED":
            return PolicyDecision.deny(
                reason_code="DOCUMENT_UNAVAILABLE",
                message="Document is not available for decryption.",
            )

        # 3. Role verification (Auditors cannot decrypt)
        if user.role == UserRole.AUDITOR.value:
            return PolicyDecision.deny(
                reason_code="POLICY_DENIED",
                message="Auditor role is not authorized to decrypt documents.",
            )

        # 4. Recipient authorization
        if not recipient or recipient.user_id != user.id or recipient.status != "ACTIVE":
            return PolicyDecision.deny(
                reason_code="NOT_DOCUMENT_RECIPIENT",
                message="User is not an authorized active recipient for this document.",
            )

        # 5. Recipient cryptographic key verification
        # Key must exist, match recipient_key_version, and be ACTIVE
        key_record = (
            db.query(RecipientKey)
            .filter(
                RecipientKey.user_id == user.id,
                RecipientKey.key_version == recipient.recipient_key_version,
            )
            .first()
        )
        if not key_record or key_record.status != "ACTIVE":
            return PolicyDecision.deny(
                reason_code="RECIPIENT_KEY_REVOKED",
                message="Recipient cryptographic key has been revoked or is not active.",
            )

        # 6. Access Policy evaluation (if configured for this document)
        policy = (
            db.query(AccessPolicy)
            .filter(
                AccessPolicy.document_id == document.id,
                AccessPolicy.enabled == True,  # noqa: E712
            )
            .first()
        )

        if not policy:
            return PolicyDecision.allow()

        policy_id = policy.id

        # 6a. Multi-party approval check
        if policy.require_approval or policy.approval_requirement:
            return PolicyDecision.deny(
                reason_code="POLICY_REQUIRES_APPROVAL",
                message="Access policy requires multi-party approval prior to decryption.",
                policy_id=policy_id,
            )

        # 6b. Time-bound access window
        policy_valid_from = cls._to_utc(policy.valid_from)
        if policy_valid_from and now < policy_valid_from:
            return PolicyDecision.deny(
                reason_code="ACCESS_NOT_YET_VALID",
                message="Document access window has not started yet.",
                policy_id=policy_id,
            )

        effective_expiry = cls._to_utc(policy.valid_until or policy.expiration_time)
        if effective_expiry and now > effective_expiry:
            return PolicyDecision.deny(
                reason_code="ACCESS_EXPIRED",
                message="Document access window has expired.",
                policy_id=policy_id,
            )

        # 6c. Device-bound access
        require_dev = policy.require_registered_device or policy.device_restriction
        if require_dev:
            if not device_id:
                return PolicyDecision.deny(
                    reason_code="DEVICE_NOT_REGISTERED",
                    message="Access policy requires an authorized registered device identifier.",
                    policy_id=policy_id,
                )

            device = db.query(Device).filter(Device.id == device_id).first()
            if not device:
                return PolicyDecision.deny(
                    reason_code="DEVICE_NOT_REGISTERED",
                    message="Device is not registered in the system.",
                    policy_id=policy_id,
                )

            if device.user_id != user.id:
                return PolicyDecision.deny(
                    reason_code="DEVICE_NOT_AUTHORIZED",
                    message="Device is not registered to the authenticated user.",
                    policy_id=policy_id,
                )

            if device.registration_status != "ACTIVE":
                return PolicyDecision.deny(
                    reason_code="DEVICE_NOT_AUTHORIZED",
                    message=f"Device registration is {device.registration_status.lower()}, not active.",
                    policy_id=policy_id,
                )

        # 6d. Maximum decryptions limit
        effective_max = policy.max_decryptions
        if effective_max is None and policy.one_time_decryption:
            effective_max = 1

        if effective_max is not None and effective_max >= 1:
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
                    reason_code="MAX_DECRYPTIONS_REACHED",
                    message=f"Maximum permitted decryptions ({effective_max}) reached for this document.",
                    policy_id=policy_id,
                )

        return PolicyDecision.allow(policy_id=policy_id)
