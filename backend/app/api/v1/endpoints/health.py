import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.config.settings import settings
from app.schemas.health import HealthResponse, ComponentHealth, ReadinessResponse

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


@router.get("/ready", response_model=ReadinessResponse, summary="Component Readiness Checks")
@router.get("/health/ready", response_model=ReadinessResponse, include_in_schema=False)
def check_readiness(db: Session = Depends(get_db)):
    """Verifies readiness across database, storage, crypto configuration, and ledger dependency."""
    import os
    from app.ledger.service import LedgerService

    start_time = time.perf_counter()

    # 1. Database
    db_status = "UP"
    db_details = {}
    try:
        db.execute(text("SELECT 1"))
        db_details["connection"] = "active"
    except Exception as exc:
        db_status = "DOWN"
        db_details["error"] = "Database check failed"

    # 2. Storage
    storage_start = time.perf_counter()
    storage_status = "UP"
    storage_details = {}
    try:
        os.makedirs(settings.STORAGE_PATH, exist_ok=True)
        test_file = os.path.join(settings.STORAGE_PATH, ".ready_check")
        with open(test_file, "w") as f:
            f.write("ready")
        os.remove(test_file)
        storage_details["path"] = settings.STORAGE_PATH
        storage_details["writable"] = True
    except Exception as exc:
        storage_status = "DOWN"
        storage_details["error"] = "Storage path unwritable"
    storage_latency = (time.perf_counter() - storage_start) * 1000

    # 3. Crypto Configuration
    crypto_start = time.perf_counter()
    crypto_status = "UP"
    crypto_details = {}
    try:
        settings.get_kek_bytes()
        settings.get_recipient_kek_bytes()
        settings.get_provenance_kek_bytes()
        settings.get_forensic_master_key_bytes()
        settings.get_mfa_encryption_key_bytes()
        crypto_details["algorithms"] = ["AES-256-GCM", "ML-KEM-768", "ML-DSA-65", "HKDF-SHA-256", "Argon2id"]
        crypto_details["keys_configured"] = True
    except Exception as exc:
        crypto_status = "DOWN"
        crypto_details["error"] = "Key configuration invalid"
    crypto_latency = (time.perf_counter() - crypto_start) * 1000

    # 4. Ledger
    ledger_start = time.perf_counter()
    ledger_status = "UP"
    ledger_details = {}
    try:
        adapter = LedgerService.get_adapter()
        ledger_details["adapter"] = type(adapter).__name__
        ledger_details["ready"] = True
    except Exception as exc:
        ledger_status = "DOWN"
        ledger_details["error"] = "Ledger dependency check failed"
    ledger_latency = (time.perf_counter() - ledger_start) * 1000

    all_up = (db_status == "UP" and storage_status == "UP" and crypto_status == "UP" and ledger_status == "UP")
    overall_status = "READY" if all_up else "NOT_READY"
    status_code = status.HTTP_200_OK if all_up else status.HTTP_503_SERVICE_UNAVAILABLE

    total_latency = (time.perf_counter() - start_time) * 1000

    payload = ReadinessResponse(
        status=overall_status,
        project=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
        database=ComponentHealth(
            status=db_status,
            latency_ms=round((time.perf_counter() - start_time) * 1000, 2),
            details=db_details,
        ),
        storage=ComponentHealth(
            status=storage_status,
            latency_ms=round(storage_latency, 2),
            details=storage_details,
        ),
        crypto=ComponentHealth(
            status=crypto_status,
            latency_ms=round(crypto_latency, 2),
            details=crypto_details,
        ),
        ledger=ComponentHealth(
            status=ledger_status,
            latency_ms=round(ledger_latency, 2),
            details=ledger_details,
        ),
    )

    return JSONResponse(status_code=status_code, content=payload.model_dump(mode="json"))
