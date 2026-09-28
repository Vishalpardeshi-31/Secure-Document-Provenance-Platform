from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.policy import AccessPolicyResponse


class DocumentRecipientSummary(BaseModel):
    recipient_id: str
    username: Optional[str] = None
    recipient_key_id: Optional[str] = None
    recipient_key_version: int
    key_algorithm: str
    status: str
    granted_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DocumentResponse(BaseModel):
    id: str
    title: str
    original_filename: str
    mime_type: str
    original_size_bytes: int
    encrypted_size_bytes: int
    plaintext_sha256: str
    ciphertext_sha256: str
    encryption_algorithm: str
    key_management_version: int = 2
    protocol_version: str = "SDP-CRYPTO-V2"
    classification: str
    status: str
    owner_id: str
    recipients: List[DocumentRecipientSummary] = Field(default_factory=list)
    recipient_count: int = 0
    policy: Optional["AccessPolicyResponse"] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DocumentListResponse(BaseModel):
    documents: List[DocumentResponse]
    total: int
