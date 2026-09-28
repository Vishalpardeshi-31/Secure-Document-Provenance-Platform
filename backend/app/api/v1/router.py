from fastapi import APIRouter
from app.api.v1.endpoints import (

    health,
    auth,
    users,
    departments,
    devices,
    audit,
    documents,
    recipients,
    approvals,
    emergency,
    provenance,
    viewer,
    forensics,
    investigations,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["User Management"])
api_router.include_router(departments.router, prefix="/departments", tags=["Department Management"])
api_router.include_router(devices.router, prefix="/devices", tags=["Device Registration"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Events"])
api_router.include_router(documents.router, prefix="/documents", tags=["Document Encryption & Management"])
api_router.include_router(recipients.router, tags=["Recipient Key Management"])
api_router.include_router(approvals.router, tags=["Multi-Party Approval"])
api_router.include_router(emergency.router, tags=["Emergency Break-Glass Access"])
api_router.include_router(provenance.router, tags=["Cryptographic Provenance"])
api_router.include_router(viewer.router, tags=["Secure Document Viewer"])
api_router.include_router(forensics.router, tags=["Forensic Leak Detection"])
api_router.include_router(investigations.router, tags=["Forensic Investigations"])



