from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class RecipientKeyStatusResponse(BaseModel):
    user_id: str
    username: str
    has_active_key: bool
    active_key_version: Optional[int] = None
    active_key_id: Optional[str] = None
    algorithm: Optional[str] = None
    created_at: Optional[datetime] = None
    status: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RecipientUserSummary(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool
    has_active_key: bool
    active_key_version: Optional[int] = None
    active_key_id: Optional[str] = None
    key_algorithm: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RecipientKeyDetailResponse(BaseModel):
    id: str
    user_id: str
    key_version: int
    algorithm: str
    status: str
    created_at: datetime
    revoked_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
