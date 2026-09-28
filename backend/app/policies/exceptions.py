"""Custom exceptions for the policy evaluation engine."""
from typing import Optional


class PolicyEngineException(Exception):
    """Base exception for policy engine operations."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class PolicyDeniedException(PolicyEngineException):
    """Raised when policy evaluation explicitly denies access."""
    def __init__(
        self,
        reason_code: str,
        message: str,
        policy_id: Optional[str] = None,
        policy_version: Optional[int] = None,
    ):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.policy_id = policy_id
        self.policy_version = policy_version


class PolicyConfigurationException(PolicyEngineException):
    """Raised when invalid or dangerous policy configuration is attempted."""
    pass


class DeviceValidationException(PolicyEngineException):
    """Raised when device validation fails."""
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
