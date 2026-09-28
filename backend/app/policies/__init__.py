"""Policy Engine package providing real, backend-authoritative policy enforcement."""
from app.policies.models import (
    PolicyStatus,
    DeviceStatus,
    DocumentLifecycleStatus,
    PolicyReasonCode,
    PolicyDecision,
)
from app.policies.exceptions import (
    PolicyEngineException,
    PolicyDeniedException,
    PolicyConfigurationException,
    DeviceValidationException,
)
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

from app.policies.evaluator import PolicyEvaluator, default_evaluator
from app.policies.service import PolicyService
from app.policies.schemas import (
    PolicyCreateRequest,
    PolicyUpdateRequest,
    PolicyResponse,
    PolicyDecisionResponse,
    DeviceRegisterRequest,
    DeviceResponse,
)

__all__ = [
    "PolicyStatus",
    "DeviceStatus",
    "DocumentLifecycleStatus",
    "PolicyReasonCode",
    "PolicyDecision",
    "PolicyEngineException",
    "PolicyDeniedException",
    "PolicyConfigurationException",
    "DeviceValidationException",
    "PolicyCondition",
    "UserStateCondition",
    "DocumentStateCondition",
    "PolicyStateCondition",
    "RecipientAuthorizationCondition",
    "RoleAuthorizationCondition",
    "TimeWindowCondition",
    "RegisteredDeviceCondition",
    "MultiPartyApprovalCondition",
    "DecryptionLimitCondition",
    "PolicyEvaluator",

    "default_evaluator",
    "PolicyService",
    "PolicyCreateRequest",
    "PolicyUpdateRequest",
    "PolicyResponse",
    "PolicyDecisionResponse",
    "DeviceRegisterRequest",
    "DeviceResponse",
]
