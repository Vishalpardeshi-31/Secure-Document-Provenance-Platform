"""Pydantic schemas for policy engine API interactions."""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field


class PolicyCreateRequest(BaseModel):
    valid_from: Optional[datetime] = Field(None, description="Start of access window (UTC)")
    valid_until: Optional[datetime] = Field(None, description="End of access window (UTC)")
    max_decryptions: Optional[int] = Field(None, ge=1, description="Maximum permitted decryptions count")
    require_registered_device: bool = Field(False, description="Require active registered device")
    require_approval: bool = Field(False, description="Require multi-party approval")
    allowed_roles: Optional[List[str]] = Field(None, description="List of authorized roles (e.g. OFFICER, RECIPIENT)")


class PolicyUpdateRequest(BaseModel):
    valid_from: Optional[datetime] = Field(None, description="Start of access window (UTC)")
    valid_until: Optional[datetime] = Field(None, description="End of access window (UTC)")
    max_decryptions: Optional[int] = Field(None, ge=1, description="Maximum permitted decryptions count")
    require_registered_device: Optional[bool] = Field(None, description="Require active registered device")
    require_approval: Optional[bool] = Field(None, description="Require multi-party approval")
    allowed_roles: Optional[List[str]] = Field(None, description="List of authorized roles")
    enabled: Optional[bool] = Field(None, description="Whether policy is enabled")


class PolicyResponse(BaseModel):
    id: str
    document_id: str
    policy_version: int
    status: str
    enabled: bool
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    max_decryptions: Optional[int] = None
    consumed_decryptions: int = 0
    require_registered_device: bool = False
    require_approval: bool = False
    allowed_roles: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyDecisionResponse(BaseModel):
    allowed: bool
    policy_id: Optional[str] = None
    policy_version: Optional[int] = None
    reason_code: Optional[str] = None
    message: Optional[str] = None
    checked_at: datetime


class DeviceRegisterRequest(BaseModel):
    device_name: str = Field(..., min_length=2, max_length=128)
    device_fingerprint: str = Field(..., min_length=8, max_length=255)


class DeviceResponse(BaseModel):
    id: str
    user_id: str
    device_name: str
    device_identifier_hash: Optional[str] = None
    status: str
    registered_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
