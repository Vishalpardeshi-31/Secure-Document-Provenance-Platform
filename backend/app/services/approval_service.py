"""Multi-Party Approval Service enforcing independent authorization thresholds and lifecycle."""
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from app.models.approval import ApprovalRequest, ApprovalRecord
from app.models.document import Document
from app.models.document_recipient import DocumentRecipient
from app.models.access_policy import AccessPolicy
from app.models.user import User
from app.models.role import UserRole
from app.policies.service import PolicyService as EnginePolicyService
from app.policies.models import PolicyStatus, DocumentLifecycleStatus
from app.services.audit_service import AuditService

logger = logging.getLogger("secure_document_platform.approval_service")


class ApprovalService:
    """Manages multi-party approval requests with server-enforced thresholds and independence."""

    APPROVAL_LIFETIME_MINUTES = 30

    @staticmethod
    def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    @classmethod
    def create_request(

        cls,
        db: Session,
        document_id: str,
        user: User,
        device_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """Creates a short-lived multi-party approval request for document decryption."""
        now = datetime.now(timezone.utc)

        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            raise ValueError("Document not found.")

        if (doc.status or "").upper() == DocumentLifecycleStatus.REVOKED.value:
            raise PermissionError("Document has been administratively revoked.")

        if not user.is_active:
            raise PermissionError("Requesting user account is inactive.")

        if user.role == UserRole.AUDITOR.value:
            raise PermissionError("Auditor role is not authorized to request decryption.")

        # Check recipient assignment
        recipient = (
            db.query(DocumentRecipient)
            .filter(
                DocumentRecipient.document_id == doc.id,
                DocumentRecipient.user_id == user.id,
                DocumentRecipient.status == "ACTIVE",
            )
            .first()
        )
        if not recipient:
            raise PermissionError("User is not an authorized active recipient for this document.")

        policy = EnginePolicyService.get_active_policy(db, doc.id)
        if not policy:
            raise ValueError("No active access policy found for this document.")

        requires_app = getattr(policy, "require_multi_party_approval", False) or policy.require_approval or policy.approval_requirement
        if not requires_app:
            raise ValueError("This document policy does not require multi-party approval.")

        # Check if an existing valid PENDING request exists for this user and policy version
        existing = (
            db.query(ApprovalRequest)
            .filter(
                ApprovalRequest.document_id == doc.id,
                ApprovalRequest.requesting_user_id == user.id,
                ApprovalRequest.policy_id == policy.id,
                ApprovalRequest.policy_version == policy.policy_version,
                ApprovalRequest.status == "PENDING",
            )
            .order_by(ApprovalRequest.created_at.desc())
            .first()
        )
        if existing:
            if cls._to_utc(existing.expires_at) > now:
                return existing
            # If expired, mark EXPIRED
            existing.status = "EXPIRED"
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="DECRYPTION_APPROVAL_EXPIRED",
                user_id=user.id,
                document_id=doc.id,
                metadata={"approval_request_id": existing.id},
            )

        req_approvals = policy.required_approvals or 2
        expires_at = now + timedelta(minutes=cls.APPROVAL_LIFETIME_MINUTES)

        request = ApprovalRequest(
            document_id=doc.id,
            requesting_user_id=user.id,
            policy_id=policy.id,
            policy_version=policy.policy_version,
            required_approvals=req_approvals,
            status="PENDING",
            created_at=now,
            expires_at=expires_at,
        )
        db.add(request)
        db.commit()
        db.refresh(request)

        AuditService.log_event(
            db=db,
            event_type="DECRYPTION_APPROVAL_REQUESTED",
            user_id=user.id,
            document_id=doc.id,
            metadata={
                "approval_request_id": request.id,
                "policy_id": policy.id,
                "policy_version": policy.policy_version,
                "required_approvals": req_approvals,
                "expires_at": expires_at.isoformat(),
            },
        )
        return request

    @classmethod
    def approve_request(
        cls,
        db: Session,
        request_id: str,
        approver: User,
        reason: Optional[str] = None,
    ) -> ApprovalRequest:
        """Records an approval decision. Enforces approver independence, role eligibility, and threshold."""
        now = datetime.now(timezone.utc)

        request = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
        if not request:
            raise ValueError("Approval request not found.")

        # Lazy expiration check
        if request.status == "PENDING" and now > cls._to_utc(request.expires_at):
            request.status = "EXPIRED"
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="DECRYPTION_APPROVAL_EXPIRED",
                user_id=request.requesting_user_id,
                document_id=request.document_id,
                metadata={"approval_request_id": request.id},
            )
            raise ValueError("Approval request has expired and cannot be approved.")


        if request.status != "PENDING":
            raise ValueError(f"Approval request cannot be approved (current status: {request.status}).")

        # 1. APPROVER INDEPENDENCE: Requester cannot approve their own request
        if approver.id == request.requesting_user_id:
            raise PermissionError("Requester cannot approve their own request.")

        # 2. Approver must be active
        if not approver.is_active:
            raise PermissionError("Approver user account is inactive or disabled.")

        # 3. Document must still be active
        if request.document.status == DocumentLifecycleStatus.REVOKED.value:
            raise PermissionError("Document has been administratively revoked.")

        # 4. Policy must still be active
        if request.policy.status != PolicyStatus.ACTIVE.value or not request.policy.enabled:
            raise PermissionError("Associated access policy is no longer active.")

        # 5. Approver role eligibility check
        policy = request.policy
        if policy.eligible_approver_roles:
            eligible = [r.strip().upper() for r in policy.eligible_approver_roles.split(",") if r.strip()]
            if eligible and approver.role.upper() not in eligible:
                raise PermissionError(f"Approver role '{approver.role}' is not eligible to approve (eligible roles: {', '.join(eligible)}).")
        else:
            if approver.role.upper() not in [UserRole.ADMIN.value, UserRole.OFFICER.value]:
                raise PermissionError("Approver role is not authorized to approve decryption requests.")

        # 6. Duplicate approver check
        existing_record = (
            db.query(ApprovalRecord)
            .filter(
                ApprovalRecord.approval_request_id == request.id,
                ApprovalRecord.approver_user_id == approver.id,
            )
            .first()
        )
        if existing_record:
            raise ValueError("Approver has already recorded a decision for this approval request.")

        # 7. Record approval
        record = ApprovalRecord(
            approval_request_id=request.id,
            approver_user_id=approver.id,
            approver_role=approver.role,
            decision="APPROVED",
            reason=reason,
            created_at=now,
        )
        db.add(record)
        db.flush()

        # 8. Check threshold (count distinct approvals)
        approved_count = (
            db.query(ApprovalRecord)
            .filter(
                ApprovalRecord.approval_request_id == request.id,
                ApprovalRecord.decision == "APPROVED",
            )
            .count()
        )

        if approved_count >= request.required_approvals:
            request.status = "APPROVED"
            request.completed_at = now

        db.commit()
        db.refresh(request)

        AuditService.log_event(
            db=db,
            event_type="DECRYPTION_APPROVED",
            user_id=approver.id,
            document_id=request.document_id,
            metadata={
                "approval_request_id": request.id,
                "approver_id": approver.id,
                "approver_role": approver.role,
                "current_approvals": approved_count,
                "required_approvals": request.required_approvals,
                "request_status": request.status,
            },
        )
        return request

    @classmethod
    def reject_request(
        cls,
        db: Session,
        request_id: str,
        approver: User,
        reason: str,
    ) -> ApprovalRequest:
        """Records a rejection decision. Any eligible approver rejection immediately rejects the request."""
        now = datetime.now(timezone.utc)

        if not reason or not reason.strip():
            raise ValueError("A rejection reason is required.")

        request = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
        if not request:
            raise ValueError("Approval request not found.")

        # Lazy expiration check
        if request.status == "PENDING" and now > cls._to_utc(request.expires_at):
            request.status = "EXPIRED"
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="DECRYPTION_APPROVAL_EXPIRED",
                user_id=request.requesting_user_id,
                document_id=request.document_id,
                metadata={"approval_request_id": request.id},
            )
            raise ValueError("Approval request has expired.")


        if request.status != "PENDING":
            raise ValueError(f"Approval request cannot be rejected (current status: {request.status}).")

        # Requester cannot reject/approve own request
        if approver.id == request.requesting_user_id:
            raise PermissionError("Requester cannot reject/approve their own request.")

        if not approver.is_active:
            raise PermissionError("Approver user account is inactive or disabled.")

        policy = request.policy
        if policy.eligible_approver_roles:
            eligible = [r.strip().upper() for r in policy.eligible_approver_roles.split(",") if r.strip()]
            if eligible and approver.role.upper() not in eligible:
                raise PermissionError(f"Approver role '{approver.role}' is not eligible to decide (eligible roles: {', '.join(eligible)}).")
        else:
            if approver.role.upper() not in [UserRole.ADMIN.value, UserRole.OFFICER.value]:
                raise PermissionError("Approver role is not authorized to reject decryption requests.")

        existing_record = (
            db.query(ApprovalRecord)
            .filter(
                ApprovalRecord.approval_request_id == request.id,
                ApprovalRecord.approver_user_id == approver.id,
            )
            .first()
        )
        if existing_record:
            raise ValueError("Approver has already recorded a decision for this approval request.")

        record = ApprovalRecord(
            approval_request_id=request.id,
            approver_user_id=approver.id,
            approver_role=approver.role,
            decision="REJECTED",
            reason=reason.strip(),
            created_at=now,
        )
        db.add(record)
        request.status = "REJECTED"
        request.completed_at = now

        db.commit()
        db.refresh(request)

        AuditService.log_event(
            db=db,
            event_type="DECRYPTION_REJECTED",
            user_id=approver.id,
            document_id=request.document_id,
            metadata={
                "approval_request_id": request.id,
                "approver_id": approver.id,
                "approver_role": approver.role,
                "reason": reason.strip(),
                "request_status": "REJECTED",
            },
        )
        return request

    @classmethod
    def cancel_request(cls, db: Session, request_id: str, user: User) -> ApprovalRequest:
        """Cancels a pending approval request. Only the requester or admin can cancel."""
        now = datetime.now(timezone.utc)

        request = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
        if not request:
            raise ValueError("Approval request not found.")

        if user.id != request.requesting_user_id and user.role != UserRole.ADMIN.value:
            raise PermissionError("Only the requesting user or an administrator can cancel this approval request.")

        if request.status != "PENDING":
            raise ValueError(f"Only PENDING requests can be cancelled (current status: {request.status}).")

        request.status = "CANCELLED"
        request.completed_at = now
        db.commit()
        db.refresh(request)

        AuditService.log_event(
            db=db,
            event_type="DECRYPTION_APPROVAL_CANCELLED",
            user_id=user.id,
            document_id=request.document_id,
            metadata={"approval_request_id": request.id},
        )
        return request

    @classmethod
    def get_request(cls, db: Session, request_id: str, user: User) -> ApprovalRequest:
        """Retrieves an approval request and validates access."""
        now = datetime.now(timezone.utc)

        request = db.query(ApprovalRequest).filter(ApprovalRequest.id == request_id).first()
        if not request:
            raise ValueError("Approval request not found.")

        # Check and update lazy expiration
        if request.status == "PENDING" and now > cls._to_utc(request.expires_at):
            request.status = "EXPIRED"
            db.commit()
            AuditService.log_event(
                db=db,
                event_type="DECRYPTION_APPROVAL_EXPIRED",
                user_id=request.requesting_user_id,
                document_id=request.document_id,
                metadata={"approval_request_id": request.id},
            )


        # Access check: requester, document owner, or eligible approvers (ADMIN/OFFICER)
        is_requester = user.id == request.requesting_user_id
        is_owner = request.document.owner_id == user.id
        is_officer_or_admin = user.role in [UserRole.ADMIN.value, UserRole.OFFICER.value]

        if not (is_requester or is_owner or is_officer_or_admin):
            raise PermissionError("Access denied to this approval request.")

        return request

    @classmethod
    def list_requests_for_user(
        cls,
        db: Session,
        user: User,
        document_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[ApprovalRequest]:
        """Lists approval requests relevant to the user."""
        query = db.query(ApprovalRequest)
        if document_id:
            query = query.filter(ApprovalRequest.document_id == document_id)
        if status:
            query = query.filter(ApprovalRequest.status == status)

        if user.role not in [UserRole.ADMIN.value, UserRole.OFFICER.value]:
            query = query.filter(ApprovalRequest.requesting_user_id == user.id)

        return query.order_by(ApprovalRequest.created_at.desc()).all()
