import base64
import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query, Header, Body
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.models.role import UserRole
from app.schemas.document import DocumentResponse, DocumentListResponse, DocumentRecipientSummary
from app.schemas.policy import AccessPolicyResponse, AccessPolicyCreate, AccessPolicyUpdate
from app.schemas.decryption import DecryptionRequest, DecryptionResultResponse
from app.schemas.common import MessageResponse
from app.services.document_service import DocumentService
from app.services.decryption_service import DecryptionService
from app.services.policy_service import PolicyService
from app.policies.service import PolicyService as EnginePolicyService
from app.policies.exceptions import PolicyConfigurationException
from app.security.permissions import get_current_user, require_any_role

router = APIRouter()


def _to_document_response(doc) -> DocumentResponse:
    recipients_summary = [
        DocumentRecipientSummary(
            recipient_id=r.user_id,
            username=r.user.username if r.user else None,
            recipient_key_id=r.recipient_key_id,
            recipient_key_version=r.recipient_key_version,
            key_algorithm=r.key_algorithm,
            status=r.status,
            granted_at=r.granted_at,
        )
        for r in (doc.recipients or [])
    ]

    policy_summary = None
    if getattr(doc, "access_policies", None):
        p = next((ap for ap in doc.access_policies if ap.enabled and getattr(ap, "status", "ACTIVE") == "ACTIVE"), doc.access_policies[0] if doc.access_policies else None)
        if p:
            policy_summary = AccessPolicyResponse(
                id=p.id,
                document_id=p.document_id,
                policy_version=getattr(p, "policy_version", 1),
                status=getattr(p, "status", "ACTIVE"),
                enabled=p.enabled,
                valid_from=p.valid_from,
                valid_until=p.valid_until,
                max_decryptions=p.max_decryptions,
                consumed_decryptions=getattr(p, "consumed_decryptions", 0),
                require_registered_device=p.require_registered_device,
                require_approval=p.require_approval,
                require_multi_party_approval=getattr(p, "require_multi_party_approval", p.require_approval),
                required_approvals=getattr(p, "required_approvals", 1),
                eligible_approver_roles=getattr(p, "eligible_approver_roles", None),
                allow_emergency_access=getattr(p, "allow_emergency_access", False),
                eligible_emergency_roles=getattr(p, "eligible_emergency_roles", None),
                eligible_emergency_permission=getattr(p, "eligible_emergency_permission", "EMERGENCY_DECRYPT"),
                emergency_approval_required=getattr(p, "emergency_approval_required", True),
                maximum_emergency_duration=getattr(p, "maximum_emergency_duration", 15),
                allowed_roles=getattr(p, "allowed_roles", None),
                created_by=p.created_by,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )


    return DocumentResponse(
        id=doc.id,
        title=doc.title,
        original_filename=doc.original_filename,
        mime_type=doc.mime_type,
        original_size_bytes=doc.original_size_bytes,
        encrypted_size_bytes=doc.encrypted_size_bytes,
        plaintext_sha256=doc.plaintext_sha256,
        ciphertext_sha256=doc.ciphertext_sha256,
        encryption_algorithm=doc.encryption_algorithm,
        key_management_version=getattr(doc, "key_management_version", 2),
        protocol_version=getattr(doc, "protocol_version", "SDP-CRYPTO-V2"),
        classification=doc.classification,
        status=doc.status,
        owner_id=doc.owner_id,
        recipients=recipients_summary,
        recipient_count=len(recipients_summary),
        policy=policy_summary,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
    )


@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and encrypt document with optional multi-recipient key wrapping and access policy",
)
async def upload_document(
    file: UploadFile = File(..., description="Document file to encrypt"),
    title: Optional[str] = Form(None, description="Optional document display title"),
    classification: str = Form("RESTRICTED", description="Classification level"),
    recipient_ids: Optional[str] = Form(None, description="Comma-separated or JSON list of recipient IDs"),
    policy_valid_from: Optional[str] = Form(None, description="ISO datetime string for access start window"),
    policy_valid_until: Optional[str] = Form(None, description="ISO datetime string for access expiry window"),
    policy_max_decryptions: Optional[int] = Form(None, description="Maximum permitted decryptions (e.g. 1)"),
    policy_require_registered_device: bool = Form(False, description="Require registered active device"),
    policy_allowed_roles: Optional[str] = Form(None, description="Comma-separated allowed roles (e.g. OFFICER, RECIPIENT)"),
    policy_require_multi_party_approval: bool = Form(False, description="Require multi-party approval before decryption"),
    policy_required_approvals: Optional[int] = Form(None, description="Number of required independent approvals"),
    policy_eligible_approver_roles: Optional[str] = Form(None, description="Comma-separated eligible approver roles"),
    policy_allow_emergency_access: bool = Form(False, description="Allow emergency break-glass access"),
    policy_eligible_emergency_roles: Optional[str] = Form(None, description="Comma-separated eligible emergency roles"),
    policy_maximum_emergency_duration: Optional[int] = Form(None, description="Max duration in minutes for emergency session"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
):
    """Executes real AES-256-GCM encryption on the uploaded file, generates a fresh DEK,
    protects the DEK via server KEK envelope, wraps DEK for each recipient using their
    active ML-KEM-768 public key, persists ciphertext in isolated storage, attaches policy, and records audit trail."""
    parsed_recipient_ids: Optional[List[str]] = None
    if recipient_ids and recipient_ids.strip():
        raw = recipient_ids.strip()
        if raw.startswith("["):
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    parsed_recipient_ids = [str(x).strip() for x in parsed if str(x).strip()]
            except Exception:
                parsed_recipient_ids = [x.strip() for x in raw.split(",") if x.strip()]
        else:
            parsed_recipient_ids = [x.strip() for x in raw.split(",") if x.strip()]

    # Parse policy data if configured
    policy_data = None
    if (
        policy_valid_from
        or policy_valid_until
        or policy_max_decryptions is not None
        or policy_require_registered_device
        or policy_allowed_roles
        or policy_require_multi_party_approval
        or policy_allow_emergency_access
    ):
        p_from = None
        if policy_valid_from and policy_valid_from.strip():
            try:
                p_from = datetime.fromisoformat(policy_valid_from.strip().replace("Z", "+00:00"))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid ISO format for policy_valid_from.")

        p_until = None
        if policy_valid_until and policy_valid_until.strip():
            try:
                p_until = datetime.fromisoformat(policy_valid_until.strip().replace("Z", "+00:00"))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid ISO format for policy_valid_until.")

        parsed_roles = None
        if policy_allowed_roles and policy_allowed_roles.strip():
            parsed_roles = [r.strip() for r in policy_allowed_roles.split(",") if r.strip()]

        parsed_approver_roles = None
        if policy_eligible_approver_roles and policy_eligible_approver_roles.strip():
            parsed_approver_roles = [r.strip() for r in policy_eligible_approver_roles.split(",") if r.strip()]

        parsed_emergency_roles = None
        if policy_eligible_emergency_roles and policy_eligible_emergency_roles.strip():
            parsed_emergency_roles = [r.strip() for r in policy_eligible_emergency_roles.split(",") if r.strip()]

        policy_data = {
            "valid_from": p_from,
            "valid_until": p_until,
            "max_decryptions": policy_max_decryptions,
            "require_registered_device": policy_require_registered_device,
            "allowed_roles": parsed_roles,
            "require_multi_party_approval": policy_require_multi_party_approval,
            "required_approvals": policy_required_approvals or 1,
            "eligible_approver_roles": parsed_approver_roles,
            "allow_emergency_access": policy_allow_emergency_access,
            "eligible_emergency_roles": parsed_emergency_roles,
            "maximum_emergency_duration": policy_maximum_emergency_duration or 15,
        }

    try:
        content = await file.read()
        doc = DocumentService.upload_and_encrypt_document(
            db=db,
            owner=current_user,
            original_filename=file.filename or "unnamed_document.bin",
            content=content,
            mime_type=file.content_type,
            title=title,
            classification=classification,
            recipient_ids=parsed_recipient_ids,
            policy_data=policy_data,
        )
        return _to_document_response(doc)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    finally:
        await file.close()


@router.get(
    "",
    response_model=List[DocumentResponse],
    summary="List encrypted document metadata",
)
def list_documents(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists safe metadata for encrypted documents.
    ADMIN sees all documents. OFFICER sees documents they uploaded. RECIPIENT sees assigned documents."""
    docs, _ = DocumentService.list_documents(
        db=db,
        user=current_user,
        offset=offset,
        limit=limit,
    )
    return [_to_document_response(d) for d in docs]


@router.get(
    "/{document_id}",
    response_model=DocumentResponse,
    summary="Get document metadata by ID",
)
def get_document(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves document metadata. Accessible by ADMIN, document owner, or assigned RECIPIENT."""
    doc = DocumentService.get_document(db, document_id, current_user)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found or access denied.",
        )
    return _to_document_response(doc)


@router.delete(
    "/{document_id}",
    response_model=MessageResponse,
    summary="Delete encrypted document",
)
def delete_document(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
):
    """Permanently deletes the encrypted storage artifact and database record.
    Accessible by ADMIN or document owner."""
    success = DocumentService.delete_document(db, document_id, current_user)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found or access denied.",
        )
    return MessageResponse(
        message=f"Document '{document_id}' and its encrypted storage artifact were deleted.",
    )


@router.post(
    "/{document_id}/decrypt",
    response_model=DecryptionResultResponse,
    summary="Request and execute policy-controlled document decryption",
)
def decrypt_document(
    document_id: str,
    request: Optional[DecryptionRequest] = Body(None),
    x_device_id: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Evaluates recipient authorization and document access policy, decapsulates
    the recipient's wrapped DEK via ML-KEM-768, verifies ciphertext integrity, authenticates
    and decrypts AES-256-GCM, validates plaintext hash, records audit events, and returns
    ephemeral decrypted content for the controlled viewer."""
    effective_device_id = (request.device_id if request and request.device_id else None) or x_device_id

    try:
        session, plaintext = DecryptionService.request_and_decrypt(
            db=db,
            document_id=document_id,
            user=current_user,
            device_id=effective_device_id,
            approval_request_id=request.approval_request_id if request else None,
            emergency_request_id=request.emergency_request_id if request else None,
        )


        doc = session.document

        return DecryptionResultResponse(
            session_id=session.id,
            document_id=doc.id,
            status=session.status,
            original_filename=doc.original_filename,
            mime_type=doc.mime_type,
            original_size_bytes=len(plaintext),
            plaintext_sha256=doc.plaintext_sha256,
            plaintext_base64=base64.b64encode(plaintext).decode("ascii"),
            completed_at=session.completed_at or datetime.now(timezone.utc),
        )

    except PermissionError as perm_err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(perm_err),
        )
    except ValueError as val_err:
        err_msg = str(val_err)
        if "not found" in err_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=err_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err_msg,
        )


@router.get(
    "/{document_id}/access-check",
    summary="Evaluate authoritative backend policy access checks for current user and device",
)
def check_document_access(
    document_id: str,
    x_device_id: Optional[str] = Header(None),
    device_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Evaluates all backend policy conditions for the user without consuming decryption count."""
    from app.models.document import Document
    from app.models.document_recipient import DocumentRecipient
    from app.policies.evaluator import default_evaluator

    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

    recipient = (
        db.query(DocumentRecipient)
        .filter(
            DocumentRecipient.document_id == doc.id,
            DocumentRecipient.user_id == current_user.id,
        )
        .first()
    )

    effective_device_id = device_id or x_device_id
    active_policy = EnginePolicyService.get_active_policy(db, doc.id)

    return default_evaluator.evaluate_checks(
        db=db,
        user=current_user,
        document=doc,
        recipient=recipient,
        policy=active_policy,
        device_id=effective_device_id,
    )


@router.get(
    "/{document_id}/policy",
    response_model=Optional[AccessPolicyResponse],
    summary="Get document access policy",
)
def get_document_policy(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves access policy configured for this document."""
    try:
        policy = PolicyService.get_policy(db, document_id, current_user)
        if not policy:
            return None
        return AccessPolicyResponse.model_validate(policy)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.post(
    "/{document_id}/policy",
    response_model=AccessPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create document access policy",
)
def create_document_policy(
    document_id: str,
    policy_data: AccessPolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
):
    """Creates a new access policy version for a document (owner/admin only)."""
    try:
        allowed_roles = policy_data.allowed_roles
        policy = EnginePolicyService.create_policy(
            db=db,
            document_id=document_id,
            actor=current_user,
            valid_from=policy_data.valid_from,
            valid_until=policy_data.valid_until,
            max_decryptions=policy_data.max_decryptions,
            require_registered_device=policy_data.require_registered_device,
            require_approval=policy_data.require_approval,
            require_multi_party_approval=policy_data.require_multi_party_approval,
            required_approvals=policy_data.required_approvals or 1,
            eligible_approver_roles=policy_data.eligible_approver_roles,
            allow_emergency_access=policy_data.allow_emergency_access,
            eligible_emergency_roles=policy_data.eligible_emergency_roles,
            eligible_emergency_permission=policy_data.eligible_emergency_permission,
            emergency_approval_required=policy_data.emergency_approval_required,
            maximum_emergency_duration=policy_data.maximum_emergency_duration,
            allowed_roles=allowed_roles,
        )

        return AccessPolicyResponse.model_validate(policy)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except (ValueError, PolicyConfigurationException) as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.put(
    "/{document_id}/policy",
    response_model=AccessPolicyResponse,
    summary="Create or update document access policy (creates new policy version)",
)
def update_document_policy(
    document_id: str,
    policy_data: AccessPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
):
    """Configures or updates access policy conditions for a document by versioning (owner/admin only)."""
    try:
        policy = PolicyService.create_or_update_policy(
            db=db,
            document_id=document_id,
            user=current_user,
            data=policy_data,
        )
        return AccessPolicyResponse.model_validate(policy)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except (ValueError, PolicyConfigurationException) as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/{document_id}/policy/revoke",
    response_model=AccessPolicyResponse,
    summary="Revoke document access policy",
)
def revoke_document_policy(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
):
    """Revokes the active policy for a document, preventing further policy-authorized decryptions."""
    try:
        policy = EnginePolicyService.revoke_policy(
            db=db,
            document_id=document_id,
            actor=current_user,
        )
        return AccessPolicyResponse.model_validate(policy)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))


@router.post(
    "/{document_id}/revoke",
    response_model=DocumentResponse,
    summary="Administratively revoke document access",
)
def revoke_document(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
):
    """Administratively revokes a document. All subsequent decryption requests will be denied."""
    try:
        doc = EnginePolicyService.revoke_document(
            db=db,
            document_id=document_id,
            actor=current_user,
        )
        return _to_document_response(doc)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))


@router.post(
    "/{document_id}/reactivate",
    response_model=DocumentResponse,
    summary="Reactivate administratively revoked document",
)
def reactivate_document(
    document_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.OFFICER)),
):
    """Reactivates an administratively revoked document, restoring policy-controlled access."""
    try:
        doc = EnginePolicyService.reactivate_document(
            db=db,
            document_id=document_id,
            actor=current_user,
        )
        return _to_document_response(doc)
    except PermissionError as perm_err:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(perm_err))
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(val_err))
