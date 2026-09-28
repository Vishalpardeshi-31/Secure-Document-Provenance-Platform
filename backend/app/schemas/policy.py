from datetime import datetime
from typing import Optional, List, Union
from pydantic import BaseModel, Field, ConfigDict, model_validator


class AccessPolicyCreate(BaseModel):
    enabled: bool = True
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    max_decryptions: Optional[int] = Field(None, ge=1, description="Maximum permitted successful decryptions per recipient")
    require_registered_device: bool = Field(False, description="Require recipient to use an active registered device")
    require_approval: bool = Field(False, description="Require multi-party approval before decryption")
    require_multi_party_approval: Optional[bool] = Field(None, description="Alias for require_approval")
    required_approvals: Optional[int] = Field(1, ge=1, description="Number of distinct approvals required (e.g. 2)")
    eligible_approver_roles: Optional[Union[List[str], str]] = Field(None, description="Roles eligible to approve (e.g. ['OFFICER', 'ADMIN'])")
    allow_emergency_access: bool = Field(False, description="Whether emergency break-glass access is enabled")
    eligible_emergency_roles: Optional[Union[List[str], str]] = Field(None, description="Roles eligible to request emergency access")
    eligible_emergency_permission: Optional[str] = Field("EMERGENCY_DECRYPT", description="Explicit permission for emergency access")
    emergency_approval_required: bool = Field(True, description="Whether independent emergency approval is required")
    maximum_emergency_duration: int = Field(15, ge=1, le=120, description="Maximum duration in minutes for emergency access window")
    allowed_roles: Optional[Union[List[str], str]] = Field(None, description="List of authorized roles")

    @model_validator(mode="after")
    def validate_time_window(self):
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("Access policy valid_until must be strictly after valid_from.")
        return self


class AccessPolicyUpdate(BaseModel):
    enabled: Optional[bool] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    max_decryptions: Optional[int] = Field(None, ge=1)
    require_registered_device: Optional[bool] = None
    require_approval: Optional[bool] = None
    require_multi_party_approval: Optional[bool] = None
    required_approvals: Optional[int] = Field(None, ge=1)
    eligible_approver_roles: Optional[Union[List[str], str]] = None
    allow_emergency_access: Optional[bool] = None
    eligible_emergency_roles: Optional[Union[List[str], str]] = None
    eligible_emergency_permission: Optional[str] = None
    emergency_approval_required: Optional[bool] = None
    maximum_emergency_duration: Optional[int] = Field(None, ge=1, le=120)
    allowed_roles: Optional[Union[List[str], str]] = Field(None, description="List of authorized roles")

    @model_validator(mode="after")
    def validate_time_window(self):
        if self.valid_from and self.valid_until and self.valid_until <= self.valid_from:
            raise ValueError("Access policy valid_until must be strictly after valid_from.")
        return self


class AccessPolicyResponse(BaseModel):
    id: str
    document_id: str
    policy_version: int = 1
    status: str = "ACTIVE"
    enabled: bool
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    max_decryptions: Optional[int] = None
    consumed_decryptions: int = 0
    require_registered_device: bool = False
    require_approval: bool = False
    require_multi_party_approval: bool = False
    required_approvals: int = 1
    eligible_approver_roles: Optional[str] = None
    allow_emergency_access: bool = False
    eligible_emergency_roles: Optional[str] = None
    eligible_emergency_permission: Optional[str] = "EMERGENCY_DECRYPT"
    emergency_approval_required: bool = True
    maximum_emergency_duration: int = 15
    allowed_roles: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
