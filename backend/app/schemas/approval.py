from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field


class ApprovalDecisionRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Reason for the approval decision (mandatory for rejection)")


class ApprovalRecordResponse(BaseModel):
    id: str
    approval_request_id: str
    approver_user_id: str
    approver_role: str
    decision: str
    reason: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApprovalRequestResponse(BaseModel):
    id: str
    document_id: str
    requesting_user_id: str
    decryption_session_id: Optional[str] = None
    policy_id: str
    policy_version: int
    required_approvals: int
    current_approvals: int = 0
    status: str
    created_at: datetime
    expires_at: datetime
    completed_at: Optional[datetime] = None
    records: List[ApprovalRecordResponse] = []

    model_config = ConfigDict(from_attributes=True)
