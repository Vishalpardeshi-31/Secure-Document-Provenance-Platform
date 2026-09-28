import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.config.settings import settings
from app.schemas.health import HealthResponse, ComponentHealth

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="System Health and Database Connectivity")
def check_health(db: Session = Depends(get_db)):
    """Verifies live database connectivity and platform status."""
    start_time = time.perf_counter()
    db_status = "UP"
    db_details = {}

    try:
        # Parameterized/raw ping against PostgreSQL
        db.execute(text("SELECT 1"))
        latency_ms = (time.perf_counter() - start_time) * 1000
        db_details["connection"] = "active"
    except Exception as exc:
        latency_ms = (time.perf_counter() - start_time) * 1000
        db_status = "DOWN"
        db_details["error"] = "Database connection failed"

    overall_status = "HEALTHY" if db_status == "UP" else "DEGRADED"
    status_code = status.HTTP_200_OK if overall_status == "HEALTHY" else status.HTTP_503_SERVICE_UNAVAILABLE

    payload = HealthResponse(
        status=overall_status,
        project=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
        database=ComponentHealth(
            status=db_status,
            latency_ms=round(latency_ms, 2),
            details=db_details,
        ),
    )

    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))
