from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class DepartmentCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    code: str = Field(..., min_length=2, max_length=32, pattern=r"^[A-Z0-9_-]+$")
    description: Optional[str] = Field(None, max_length=1000)


class DepartmentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    code: Optional[str] = Field(None, min_length=2, max_length=32, pattern=r"^[A-Z0-9_-]+$")
    description: Optional[str] = Field(None, max_length=1000)
    is_active: Optional[bool] = None


class DepartmentResponse(BaseModel):
    id: str
    name: str
    code: str
    description: Optional[str] = None
    is_active: bool
    user_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
