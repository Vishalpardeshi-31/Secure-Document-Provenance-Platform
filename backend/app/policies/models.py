"""Policy data models and evaluation result representations."""
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from app.models.access_policy import AccessPolicy


class PolicyStatus(str, Enum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class DeviceStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    PENDING = "PENDING"


class DocumentLifecycleStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ENCRYPTED = "ENCRYPTED"
    REVOKED = "REVOKED"
    ARCHIVED = "ARCHIVED"


class PolicyReasonCode(str, Enum):
    RECIPIENT_NOT_AUTHORIZED = "RECIPIENT_NOT_AUTHORIZED"
    ROLE_NOT_AUTHORIZED = "ROLE_NOT_AUTHORIZED"
    DEVICE_REQUIRED = "DEVICE_REQUIRED"
    DEVICE_NOT_REGISTERED = "DEVICE_NOT_REGISTERED"
    DEVICE_NOT_AUTHORIZED = "DEVICE_NOT_AUTHORIZED"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    POLICY_NOT_ACTIVE = "POLICY_NOT_ACTIVE"
    POLICY_NOT_YET_ACTIVE = "POLICY_NOT_YET_ACTIVE"
    POLICY_EXPIRED = "POLICY_EXPIRED"
    DECRYPTION_LIMIT_REACHED = "DECRYPTION_LIMIT_REACHED"
    DOCUMENT_REVOKED = "DOCUMENT_REVOKED"
    DOCUMENT_NOT_AVAILABLE = "DOCUMENT_NOT_AVAILABLE"
    USER_INACTIVE = "USER_INACTIVE"
    RECIPIENT_KEY_REVOKED = "RECIPIENT_KEY_REVOKED"
    POLICY_REQUIRES_APPROVAL = "POLICY_REQUIRES_APPROVAL"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    EMERGENCY_ACCESS_DENIED = "EMERGENCY_ACCESS_DENIED"
    EMERGENCY_NOT_PERMITTED = "EMERGENCY_NOT_PERMITTED"
    EMERGENCY_REQUIRES_APPROVAL = "EMERGENCY_REQUIRES_APPROVAL"
    EMERGENCY_REQUEST_EXPIRED = "EMERGENCY_REQUEST_EXPIRED"
    POLICY_DENIED = "POLICY_DENIED"



@dataclass
class PolicyDecision:
    """Structured decision output of the policy evaluation engine."""
    allowed: bool
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    checked_at: datetime = datetime.now(timezone.utc)
    failed_condition: Optional[str] = None
    reason_code: Optional[str] = None
    message: Optional[str] = None

    @property
    def is_allowed(self) -> bool:
        """Compatibility property matching Phase 5."""
        return self.allowed

    @classmethod
    def allow(
        cls,
        policy_id: Optional[str] = None,
        policy_version: Optional[int] = None,
        checked_at: Optional[datetime] = None,
    ) -> "PolicyDecision":
        return cls(
            allowed=True,
            policy_id=policy_id,
            policy_version=policy_version,
            checked_at=checked_at or datetime.now(timezone.utc),
        )

    @classmethod
    def deny(
        cls,
        reason_code: str,
        message: str,
        failed_condition: Optional[str] = None,
        policy_id: Optional[str] = None,
        policy_version: Optional[int] = None,
        checked_at: Optional[datetime] = None,
    ) -> "PolicyDecision":
        return cls(
            allowed=False,
            reason_code=reason_code,
            message=message,
            failed_condition=failed_condition,
            policy_id=policy_id,
            policy_version=policy_version,
            checked_at=checked_at or datetime.now(timezone.utc),
        )
