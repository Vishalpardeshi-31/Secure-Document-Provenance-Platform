from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config.settings import settings
from app.api.v1.router import api_router
from app.schemas.common import ErrorResponse, ErrorBody, ErrorDetail

# Configure structured logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("secure_document_platform")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager validating cryptographic primitives on application startup."""
    from app.crypto import verify_crypto_primitives
    try:
        check_result = verify_crypto_primitives()
        logger.info("Cryptographic self-check successfully validated primitives: %s", check_result.verified_algorithms)
    except Exception as exc:
        logger.critical(f"FATAL: Cryptographic self-check failed during startup: {exc}", exc_info=True)
        raise RuntimeError(f"Startup aborted: cryptographic verification failed: {exc}") from exc
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0-foundation",
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    openapi_url="/openapi.json" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan,
)

# Explicit CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


import uuid


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Enforces request correlation ID tracking across every backend operation."""
    correlation_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    request.state.request_id = correlation_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = correlation_id
    response.headers["X-Correlation-ID"] = correlation_id
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforces standard HTTP security response headers."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if hasattr(request.state, "request_id"):
        response.headers["X-Request-ID"] = request.state.request_id
    if "Content-Security-Policy" not in response.headers:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' http://localhost:* ws://localhost:* http://127.0.0.1:* ws://127.0.0.1:*; "
            "frame-ancestors 'none'; "
            "object-src 'none';"
        )
    return response


# Centralized exception handlers ensuring consistent error JSON contract
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handles request body/param validation errors without leaking sensitive internals."""
    details = []
    for err in exc.errors():
        loc = " -> ".join([str(item) for item in err.get("loc", []) if item != "body"])
        details.append(
            ErrorDetail(
                field=loc or None,
                message=err.get("msg", "Invalid value"),
            )
        )

    error_response = ErrorResponse(
        error=ErrorBody(
            code="VALIDATION_ERROR",
            message="The request parameters failed validation.",
            details=details,
        )
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=error_response.model_dump(),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handles standard HTTP exceptions consistently."""
    code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_SERVER_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }
    error_code = code_map.get(exc.status_code, "HTTP_ERROR")

    error_response = ErrorResponse(
        error=ErrorBody(
            code=error_code,
            message=str(exc.detail),
            details=[],
        )
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response.model_dump(),
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Catches all unhandled exceptions and prevents raw stack traces from reaching clients."""
    logger.error(f"Unhandled server error on {request.method} {request.url.path}: {exc}", exc_info=True)
    error_response = ErrorResponse(
        error=ErrorBody(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected server error occurred. Please contact the system administrator.",
            details=[],
        )
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(),
    )


# Include API router (both /api/v1 and alias /api for endpoint compatibility)
app.include_router(api_router, prefix=settings.API_V1_STR)
app.include_router(api_router, prefix="/api")


@app.get("/", tags=["Root"])
def root():
    return {
        "service": settings.PROJECT_NAME,
        "status": "OPERATIONAL",
        "api_documentation": f"{settings.API_V1_STR}/docs" if settings.ENVIRONMENT != "production" else None,
        "health_endpoint": f"{settings.API_V1_STR}/health",
        "readiness_endpoint": f"{settings.API_V1_STR}/health/ready",
    }
