from datetime import datetime
from typing import Dict, Any
from pydantic import BaseModel


class ComponentHealth(BaseModel):
    status: str
    latency_ms: float
    details: Dict[str, Any] = {}


class HealthResponse(BaseModel):
    status: str
    project: str
    environment: str
    timestamp: datetime
    database: ComponentHealth


class ReadinessResponse(BaseModel):
    status: str  # READY or NOT_READY
    project: str
    environment: str
    timestamp: datetime
    database: ComponentHealth
    storage: ComponentHealth
    crypto: ComponentHealth
    ledger: ComponentHealth
