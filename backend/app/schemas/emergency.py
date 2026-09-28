from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class EmergencyAccessCreateRequest(BaseModel):
    reason: str = Field(..., min_length=15, description="Explicit incident response reason (minimum 15 characters required)")
    requested_duration_minutes: Optional[int] = Field(None, ge=1, le=60, description="Requested session duration in minutes (bounded by policy maximum)")


class EmergencyDecisionRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Reason for the authorization or rejection decision (mandatory for rejection)")


class EmergencyAccessResponse(BaseModel):
    id: str
    document_id: str
    requester_user_id: str
    requester_role: str
    reason: str
    status: str
    created_at: datetime
    expires_at: datetime
    approved_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    approver_user_id: Optional[str] = None
    rejection_reason: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
