import React, { useState, useEffect, useCallback } from 'react';
import {
  EncryptedDocument,
  RecipientUserSummary,
  DecryptionResult,
  DocumentAccessCheckResult,
  Device,
  ApprovalRequest,
  EmergencyAccessRequest,
  ProvenanceRecord,
  ProvenanceVerificationResult,
  ProvenanceChainHead,
  ProvenanceChainVerificationResult,
  LedgerAnchorVerificationResult,
} from '../types/auth';
import { documentService } from '../services/documents';
import { adminService } from '../services/admin';
import { useAuth } from '../hooks/useAuth';
import { ErrorBanner } from '../components/ErrorBanner';
import { formatDate } from '../lib/utils';
import { DecryptedDocumentViewer } from '../components/DecryptedDocumentViewer';
import {
  FileUp,
  Trash2,
  Lock,
  Unlock,
  Hash,
  Users,
  ShieldCheck,
  Clock,
  Smartphone,
  Settings2,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  FileCheck,
  Link2,
  Anchor,
} from 'lucide-react';

export const DocumentsSection: React.FC = () => {
  const { token, user } = useAuth();
  const [documents, setDocuments] = useState<EncryptedDocument[]>([]);
  const [availableRecipients, setAvailableRecipients] = useState<RecipientUserSummary[]>([]);
  const [userDevices, setUserDevices] = useState<Device[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Upload Form State
  const [showUpload, setShowUpload] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [customTitle, setCustomTitle] = useState<string>('');
  const [classification, setClassification] = useState<string>('RESTRICTED');
  const [selectedRecipientIds, setSelectedRecipientIds] = useState<string[]>([]);
  const [policyValidFrom, setPolicyValidFrom] = useState<string>('');
  const [policyValidUntil, setPolicyValidUntil] = useState<string>('');
  const [policyMaxDecryptions, setPolicyMaxDecryptions] = useState<string>('');
  const [policyRequireDevice, setPolicyRequireDevice] = useState<boolean>(false);
  const [policyAllowedRoles, setPolicyAllowedRoles] = useState<string>('');
  const [policyRequireMultiParty, setPolicyRequireMultiParty] = useState<boolean>(false);
  const [policyRequiredApprovals, setPolicyRequiredApprovals] = useState<string>('2');
  const [policyEligibleApprovers, setPolicyEligibleApprovers] = useState<string>('OFFICER, ADMIN');
  const [policyAllowEmergency, setPolicyAllowEmergency] = useState<boolean>(false);
  const [policyEligibleEmergencyRoles, setPolicyEligibleEmergencyRoles] = useState<string>('ADMIN, OFFICER');
  const [policyEmergencyDuration, setPolicyEmergencyDuration] = useState<string>('15');
  const [uploadStatus, setUploadStatus] = useState<'IDLE' | 'ENCRYPTING' | 'ENCRYPTED' | 'FAILED'>('IDLE');

  // Document Inspection State
  const [inspectDoc, setInspectDoc] = useState<EncryptedDocument | null>(null);

  // Policy Edit State
  const [policyModalDoc, setPolicyModalDoc] = useState<EncryptedDocument | null>(null);
  const [editPolicyFrom, setEditPolicyFrom] = useState<string>('');
  const [editPolicyUntil, setEditPolicyUntil] = useState<string>('');
  const [editPolicyMaxDecryptions, setEditPolicyMaxDecryptions] = useState<string>('');
  const [editPolicyRequireDevice, setEditPolicyRequireDevice] = useState<boolean>(false);
  const [editPolicyAllowedRoles, setEditPolicyAllowedRoles] = useState<string>('');
  const [editPolicyRequireMultiParty, setEditPolicyRequireMultiParty] = useState<boolean>(false);
  const [editPolicyRequiredApprovals, setEditPolicyRequiredApprovals] = useState<string>('2');
  const [editPolicyEligibleApprovers, setEditPolicyEligibleApprovers] = useState<string>('OFFICER, ADMIN');
  const [editPolicyAllowEmergency, setEditPolicyAllowEmergency] = useState<boolean>(false);
  const [editPolicyEligibleEmergencyRoles, setEditPolicyEligibleEmergencyRoles] = useState<string>('ADMIN, OFFICER');
  const [editPolicyEmergencyDuration, setEditPolicyEmergencyDuration] = useState<string>('15');
  const [isSavingPolicy, setIsSavingPolicy] = useState<boolean>(false);

  // Decryption State
  const [decryptingDocId, setDecryptingDocId] = useState<string | null>(null);
  const [decryptedResult, setDecryptedResult] = useState<DecryptionResult | null>(null);
  const [isEmergencySession, setIsEmergencySession] = useState<boolean>(false);

  // Access Authorization Check State (Phase 7 Real Backend Verification)
  const [accessCheckDoc, setAccessCheckDoc] = useState<EncryptedDocument | null>(null);
  const [accessCheckResult, setAccessCheckResult] = useState<DocumentAccessCheckResult | null>(null);
  const [accessCheckLoading, setAccessCheckLoading] = useState<boolean>(false);

  // Phase 8 Multi-Party Approval State
  const [approvalRequests, setApprovalRequests] = useState<ApprovalRequest[]>([]);
  const [approvalRejectionReasons, setApprovalRejectionReasons] = useState<{ [id: string]: string }>({});
  const [isApprovingRequestId, setIsApprovingRequestId] = useState<string | null>(null);
  const [isRejectingRequestId, setIsRejectingRequestId] = useState<string | null>(null);
  const [isRequestingApprovalDocId, setIsRequestingApprovalDocId] = useState<string | null>(null);
  const [cancellingRequestId, setCancellingRequestId] = useState<string | null>(null);

  // Phase 8 Emergency Break-Glass Access State
  const [emergencyRequests, setEmergencyRequests] = useState<EmergencyAccessRequest[]>([]);
  const [emergencyModalDoc, setEmergencyModalDoc] = useState<EncryptedDocument | null>(null);
  const [emergencyReason, setEmergencyReason] = useState<string>('');
  const [emergencyDurationMinutes, setEmergencyDurationMinutes] = useState<string>('15');
  const [isSubmittingEmergency, setIsSubmittingEmergency] = useState<boolean>(false);
  const [emergencyRejectionReasons, setEmergencyRejectionReasons] = useState<{ [id: string]: string }>({});
  const [isApprovingEmergencyId, setIsApprovingEmergencyId] = useState<string | null>(null);
  const [isRejectingEmergencyId, setIsRejectingEmergencyId] = useState<string | null>(null);
  const [isExecutingEmergencyDocId, setIsExecutingEmergencyDocId] = useState<string | null>(null);

  // Phase 9 Cryptographic Provenance State
  const [provenanceModalDoc, setProvenanceModalDoc] = useState<EncryptedDocument | null>(null);
  const [provenanceRecords, setProvenanceRecords] = useState<ProvenanceRecord[]>([]);
  const [isLoadingProvenance, setIsLoadingProvenance] = useState<boolean>(false);
  const [verificationResults, setVerificationResults] = useState<{ [eventId: string]: ProvenanceVerificationResult }>({});
  const [verifyingEventId, setVerifyingEventId] = useState<string | null>(null);

  // Phase 10 Provenance Hash Chain & Ledger State
  const [chainHead, setChainHead] = useState<ProvenanceChainHead | null>(null);
  const [chainVerificationResult, setChainVerificationResult] = useState<ProvenanceChainVerificationResult | null>(null);
  const [isVerifyingChain, setIsVerifyingChain] = useState<boolean>(false);
  const [anchorResults, setAnchorResults] = useState<{ [eventId: string]: LedgerAnchorVerificationResult }>({});
  const [verifyingAnchorId, setVerifyingAnchorId] = useState<string | null>(null);

  const canUpload = user?.role === 'ADMIN' || user?.role === 'OFFICER';
  const canApprove = user?.role === 'ADMIN' || user?.role === 'OFFICER';
  const canEmergencyAccess = Boolean(user?.can_emergency_decrypt);

  const fetchDocuments = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await documentService.listDocuments(token);
      setDocuments(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to query encrypted documents.');
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  const fetchApprovalRequests = useCallback(async () => {
    if (!token) return;
    try {
      const data = await documentService.listApprovalRequests(token);
      setApprovalRequests(data);
    } catch {
      // non-critical
    }
  }, [token]);

  const fetchEmergencyRequests = useCallback(async () => {
    if (!token) return;
    try {
      const data = await documentService.listEmergencyRequests(token);
      setEmergencyRequests(data);
    } catch {
      // non-critical
    }
  }, [token]);

  const fetchRecipients = useCallback(async () => {
    if (!token || !canUpload) return;
    try {
      const data = await documentService.listRecipients(token);
      setAvailableRecipients(data);
    } catch {
      // Non-critical if fails, will show empty recipient list
    }
  }, [token, canUpload]);

  const fetchDevices = useCallback(async () => {
    if (!token) return;
    try {
      const devs = await adminService.getDevices(token);
      const myDevs = devs.filter((d) => d.user_id === user?.id && d.registration_status === 'ACTIVE');
      setUserDevices(myDevs);
      if (myDevs.length > 0 && !selectedDeviceId) {
        setSelectedDeviceId(myDevs[0].id);
      }
    } catch {
      // Devices call might be restricted for pure recipients if admin endpoint; fail silently
    }
  }, [token, user?.id, selectedDeviceId]);

  useEffect(() => {
    fetchDocuments();
    fetchApprovalRequests();
    fetchEmergencyRequests();
    if (canUpload) {
      fetchRecipients();
    }
    fetchDevices();
  }, [fetchDocuments, fetchApprovalRequests, fetchEmergencyRequests, fetchRecipients, fetchDevices, canUpload]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleToggleRecipient = (recipientId: string) => {
    setSelectedRecipientIds((prev) =>
      prev.includes(recipientId) ? prev.filter((id) => id !== recipientId) : [...prev, recipientId]
    );
  };

  const handleUploadAndEncrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !selectedFile) return;

    setError(null);
    setSuccessMsg(null);
    setUploadStatus('ENCRYPTING');

    try {
      const policyPayload =
        policyValidFrom ||
        policyValidUntil ||
        policyMaxDecryptions ||
        policyRequireDevice ||
        policyAllowedRoles ||
        policyRequireMultiParty ||
        policyAllowEmergency
          ? {
              valid_from: policyValidFrom ? new Date(policyValidFrom).toISOString() : undefined,
              valid_until: policyValidUntil ? new Date(policyValidUntil).toISOString() : undefined,
              max_decryptions: policyMaxDecryptions ? parseInt(policyMaxDecryptions, 10) : undefined,
              require_registered_device: policyRequireDevice,
              allowed_roles: policyAllowedRoles.trim() || undefined,
              require_multi_party_approval: policyRequireMultiParty,
              required_approvals: policyRequireMultiParty ? parseInt(policyRequiredApprovals, 10) || 2 : 1,
              eligible_approver_roles:
                policyRequireMultiParty && policyEligibleApprovers.trim()
                  ? policyEligibleApprovers.trim()
                  : undefined,
              allow_emergency_access: policyAllowEmergency,
              eligible_emergency_roles:
                policyAllowEmergency && policyEligibleEmergencyRoles.trim()
                  ? policyEligibleEmergencyRoles.trim()
                  : undefined,
              maximum_emergency_duration: policyAllowEmergency
                ? parseInt(policyEmergencyDuration, 10) || 15
                : undefined,
            }
          : undefined;

      const doc = await documentService.uploadDocument(
        token,
        selectedFile,
        customTitle.trim() || undefined,
        classification,
        selectedRecipientIds,
        policyPayload
      );

      setUploadStatus('ENCRYPTED');
      setSuccessMsg(
        `Document '${doc.original_filename}' encrypted once with AES-256-GCM and DEK wrapped for ${
          doc.recipient_count || selectedRecipientIds.length
        } recipient(s).`
      );
      setSelectedFile(null);
      setCustomTitle('');
      setSelectedRecipientIds([]);
      setPolicyValidFrom('');
      setPolicyValidUntil('');
      setPolicyMaxDecryptions('');
      setPolicyRequireDevice(false);
      setPolicyAllowedRoles('');
      setPolicyRequireMultiParty(false);
      setPolicyRequiredApprovals('2');
      setPolicyEligibleApprovers('OFFICER, ADMIN');
      setPolicyAllowEmergency(false);
      setPolicyEligibleEmergencyRoles('ADMIN, OFFICER');
      setPolicyEmergencyDuration('15');
      setShowUpload(false);
      fetchDocuments();
    } catch (err: unknown) {
      setUploadStatus('FAILED');
      setError(err instanceof Error ? err.message : 'Encryption failed.');
    }
  };

  const handleDelete = async (doc: EncryptedDocument) => {
    if (!token) return;
    if (!confirm(`Permanently delete encrypted document '${doc.original_filename}' and purge ciphertext?`)) {
      return;
    }

    try {
      await documentService.deleteDocument(token, doc.id);
      setSuccessMsg(`Document '${doc.original_filename}' deleted from storage and catalog.`);
      fetchDocuments();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete document.');
    }
  };

  // Phase 7 Access Authorization Check Modal Handler
  const handleOpenAccessCheck = async (doc: EncryptedDocument) => {
    if (!token) return;
    setAccessCheckDoc(doc);
    setAccessCheckLoading(true);
    setAccessCheckResult(null);
    setError(null);

    try {
      const result = await documentService.checkDocumentAccess(
        token,
        doc.id,
        selectedDeviceId || undefined
      );
      setAccessCheckResult(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Access authorization check failed.');
    } finally {
      setAccessCheckLoading(false);
    }
  };

  // Execute Decryption after backend authorization verified (supports multi-party approval)
  const handleExecuteDecrypt = async (doc: EncryptedDocument, approvalRequestId?: string) => {
    if (!token) return;

    setError(null);
    setSuccessMsg(null);
    setDecryptingDocId(doc.id);
    setIsEmergencySession(false);

    try {
      const result = await documentService.decryptDocument(
        token,
        doc.id,
        selectedDeviceId || undefined,
        approvalRequestId || undefined
      );
      setDecryptedResult(result);
      setAccessCheckDoc(null);
      setAccessCheckResult(null);
      fetchDocuments();
      fetchApprovalRequests();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Decryption access denied by backend policy.');
    } finally {
      setDecryptingDocId(null);
    }
  };

  const handleCloseViewer = () => {
    setDecryptedResult(null);
    setIsEmergencySession(false);
  };

  // Policy Management Handler
  const handleOpenPolicyModal = (doc: EncryptedDocument) => {
    setPolicyModalDoc(doc);
    const pol = doc.policy;
    setEditPolicyFrom(pol?.valid_from ? pol.valid_from.slice(0, 16) : '');
    setEditPolicyUntil(pol?.valid_until ? pol.valid_until.slice(0, 16) : '');
    setEditPolicyMaxDecryptions(pol?.max_decryptions ? pol.max_decryptions.toString() : '');
    setEditPolicyRequireDevice(pol?.require_registered_device ?? false);
    setEditPolicyAllowedRoles(
      Array.isArray(pol?.allowed_roles) ? pol.allowed_roles.join(', ') : (pol?.allowed_roles || '')
    );
    setEditPolicyRequireMultiParty(Boolean(pol?.require_multi_party_approval || pol?.require_approval));
    setEditPolicyRequiredApprovals(pol?.required_approvals ? pol.required_approvals.toString() : '2');
    setEditPolicyEligibleApprovers(
      Array.isArray(pol?.eligible_approver_roles)
        ? pol.eligible_approver_roles.join(', ')
        : (pol?.eligible_approver_roles || 'OFFICER, ADMIN')
    );
    setEditPolicyAllowEmergency(Boolean(pol?.allow_emergency_access));
    setEditPolicyEligibleEmergencyRoles(
      Array.isArray(pol?.eligible_emergency_roles)
        ? pol.eligible_emergency_roles.join(', ')
        : (pol?.eligible_emergency_roles || 'ADMIN, OFFICER')
    );
    setEditPolicyEmergencyDuration(
      pol?.maximum_emergency_duration ? pol.maximum_emergency_duration.toString() : '15'
    );
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !policyModalDoc) return;

    setIsSavingPolicy(true);
    setError(null);

    try {
      const roles = editPolicyAllowedRoles
        ? editPolicyAllowedRoles.split(',').map((r) => r.trim()).filter(Boolean)
        : undefined;
      const approverRoles = editPolicyEligibleApprovers
        ? editPolicyEligibleApprovers.split(',').map((r) => r.trim()).filter(Boolean)
        : undefined;
      const emergencyRoles = editPolicyEligibleEmergencyRoles
        ? editPolicyEligibleEmergencyRoles.split(',').map((r) => r.trim()).filter(Boolean)
        : undefined;

      await documentService.updateDocumentPolicy(token, policyModalDoc.id, {
        valid_from: editPolicyFrom ? new Date(editPolicyFrom).toISOString() : null,
        valid_until: editPolicyUntil ? new Date(editPolicyUntil).toISOString() : null,
        max_decryptions: editPolicyMaxDecryptions ? parseInt(editPolicyMaxDecryptions, 10) : null,
        require_registered_device: editPolicyRequireDevice,
        allowed_roles: roles,
        require_multi_party_approval: editPolicyRequireMultiParty,
        required_approvals: editPolicyRequireMultiParty ? parseInt(editPolicyRequiredApprovals, 10) || 2 : 1,
        eligible_approver_roles: approverRoles,
        allow_emergency_access: editPolicyAllowEmergency,
        eligible_emergency_roles: emergencyRoles,
        maximum_emergency_duration: editPolicyAllowEmergency ? parseInt(editPolicyEmergencyDuration, 10) || 15 : 15,
      });

      setSuccessMsg(`New access policy version created for '${policyModalDoc.original_filename}'.`);
      setPolicyModalDoc(null);
      fetchDocuments();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update access policy.');
    } finally {
      setIsSavingPolicy(false);
    }
  };

  // Phase 8 Multi-Party Approval Handlers
  const handleRequestApproval = async (doc: EncryptedDocument) => {
    if (!token) return;
    setIsRequestingApprovalDocId(doc.id);
    setError(null);
    try {
      await documentService.createApprovalRequest(token, doc.id, selectedDeviceId || undefined);
      setSuccessMsg(`Approval request created for '${doc.original_filename}'. Waiting for authorized approvers.`);
      fetchApprovalRequests();
      // Re-run access check if open
      if (accessCheckDoc?.id === doc.id) {
        handleOpenAccessCheck(doc);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to submit approval request.');
    } finally {
      setIsRequestingApprovalDocId(null);
    }
  };

  const handleApproveRequest = async (requestId: string) => {
    if (!token) return;
    setIsApprovingRequestId(requestId);
    setError(null);
    try {
      await documentService.approveRequest(token, requestId);
      setSuccessMsg('Decryption approval recorded.');
      fetchApprovalRequests();
      if (accessCheckDoc) {
        handleOpenAccessCheck(accessCheckDoc);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Approval failed.');
    } finally {
      setIsApprovingRequestId(null);
    }
  };

  const handleRejectRequest = async (requestId: string) => {
    if (!token) return;
    const reason = (approvalRejectionReasons[requestId] || '').trim();
    if (!reason) {
      setError('Rejection requires an explicit reason.');
      return;
    }
    setIsRejectingRequestId(requestId);
    setError(null);
    try {
      await documentService.rejectRequest(token, requestId, reason);
      setSuccessMsg('Decryption request rejected.');
      setApprovalRejectionReasons((prev) => ({ ...prev, [requestId]: '' }));
      fetchApprovalRequests();
      if (accessCheckDoc) {
        handleOpenAccessCheck(accessCheckDoc);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Rejection failed.');
    } finally {
      setIsRejectingRequestId(null);
    }
  };

  const handleCancelApprovalRequest = async (requestId: string) => {
    if (!token) return;
    setCancellingRequestId(requestId);
    setError(null);
    try {
      await documentService.cancelRequest(token, requestId);
      setSuccessMsg('Approval request cancelled.');
      fetchApprovalRequests();
      if (accessCheckDoc) {
        handleOpenAccessCheck(accessCheckDoc);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Cancellation failed.');
    } finally {
      setCancellingRequestId(null);
    }
  };

  // Phase 8 Emergency Break-Glass Access Handlers
  const handleOpenEmergencyModal = (doc: EncryptedDocument) => {
    setEmergencyModalDoc(doc);
    setEmergencyReason('');
    setEmergencyDurationMinutes(
      doc.policy?.maximum_emergency_duration ? doc.policy.maximum_emergency_duration.toString() : '15'
    );
    setError(null);
    setSuccessMsg(null);
  };

  const handleSubmitEmergencyRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !emergencyModalDoc) return;
    if (emergencyReason.trim().length < 15) {
      setError('Emergency reason must be at least 15 characters describing operational necessity.');
      return;
    }

    setIsSubmittingEmergency(true);
    setError(null);
    try {
      const dur = parseInt(emergencyDurationMinutes, 10) || 15;
      await documentService.createEmergencyRequest(token, emergencyModalDoc.id, emergencyReason.trim(), dur);
      setSuccessMsg('Emergency break-glass access requested. Awaiting independent emergency authorization.');
      setEmergencyReason('');
      fetchEmergencyRequests();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to request emergency break-glass access.');
    } finally {
      setIsSubmittingEmergency(false);
    }
  };

  const handleApproveEmergency = async (requestId: string) => {
    if (!token) return;
    setIsApprovingEmergencyId(requestId);
    setError(null);
    try {
      await documentService.approveEmergencyRequest(token, requestId);
      setSuccessMsg('Emergency access request authorized. Time-limited authorization active.');
      fetchEmergencyRequests();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to authorize emergency request.');
    } finally {
      setIsApprovingEmergencyId(null);
    }
  };

  const handleRejectEmergency = async (requestId: string) => {
    if (!token) return;
    const reason = (emergencyRejectionReasons[requestId] || '').trim();
    if (!reason) {
      setError('Rejection requires an explicit reason.');
      return;
    }
    setIsRejectingEmergencyId(requestId);
    setError(null);
    try {
      await documentService.rejectEmergencyRequest(token, requestId, reason);
      setSuccessMsg('Emergency request rejected.');
      setEmergencyRejectionReasons((prev) => ({ ...prev, [requestId]: '' }));
      fetchEmergencyRequests();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reject emergency request.');
    } finally {
      setIsRejectingEmergencyId(null);
    }
  };

  const handleExecuteEmergencyDecrypt = async (doc: EncryptedDocument, emergencyRequestId: string) => {
    if (!token) return;
    setIsExecutingEmergencyDocId(doc.id);
    setError(null);
    try {
      const result = await documentService.executeEmergencyDecrypt(
        token,
        doc.id,
        emergencyRequestId,
        selectedDeviceId || undefined
      );
      setDecryptedResult(result);
      setIsEmergencySession(true);
      setEmergencyModalDoc(null);
      fetchDocuments();
      fetchEmergencyRequests();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Emergency decryption failed.');
    } finally {
      setIsExecutingEmergencyDocId(null);
    }
  };

  const fetchChainHead = async () => {
    if (!token) return;
    try {
      const head = await documentService.getChainHead(token);
      setChainHead(head);
    } catch {
      // non-critical
    }
  };

  const handleOpenProvenanceModal = async (doc: EncryptedDocument) => {
    if (!token) return;
    setProvenanceModalDoc(doc);
    setIsLoadingProvenance(true);
    setError(null);
    setVerificationResults({});
    setAnchorResults({});
    setChainVerificationResult(null);
    fetchChainHead();
    try {
      const records = await documentService.getDocumentProvenance(token, doc.id);
      setProvenanceRecords(records);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve provenance records.');
      setProvenanceRecords([]);
    } finally {
      setIsLoadingProvenance(false);
    }
  };

  const handleVerifyProvenance = async (eventId: string) => {
    if (!token) return;
    setVerifyingEventId(eventId);
    setError(null);
    try {
      const res = await documentService.verifyProvenanceRecord(token, eventId);
      setVerificationResults((prev) => ({ ...prev, [eventId]: res }));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Provenance verification request failed.');
    } finally {
      setVerifyingEventId(null);
    }
  };

  const handleVerifyFullChain = async () => {
    if (!token) return;
    setIsVerifyingChain(true);
    setError(null);
    try {
      const res = await documentService.verifyFullChain(token);
      setChainVerificationResult(res);
      await fetchChainHead();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Full chain verification failed.');
    } finally {
      setIsVerifyingChain(false);
    }
  };

  const handleVerifyAnchor = async (eventId: string) => {
    if (!token) return;
    setVerifyingAnchorId(eventId);
    setError(null);
    try {
      const res = await documentService.verifyLedgerAnchor(token, eventId);
      setAnchorResults((prev) => ({ ...prev, [eventId]: res }));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Ledger anchor verification failed.');
    } finally {
      setVerifyingAnchorId(null);
    }
  };

  const handleRevokePolicy = async () => {
    if (!token || !policyModalDoc) return;
    if (!confirm(`Revoke active access policy for '${policyModalDoc.original_filename}'?`)) {
      return;
    }

    setIsSavingPolicy(true);
    setError(null);

    try {
      await documentService.revokePolicy(token, policyModalDoc.id);
      setSuccessMsg(`Access policy revoked for '${policyModalDoc.original_filename}'.`);
      setPolicyModalDoc(null);
      fetchDocuments();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke policy.');
    } finally {
      setIsSavingPolicy(false);
    }
  };

  const handleRevokeDocument = async (doc: EncryptedDocument) => {
    if (!token) return;
    if (!confirm(`Administratively revoke document '${doc.original_filename}'? All decryptions will be immediately blocked.`)) {
      return;
    }

    try {
      await documentService.revokeDocument(token, doc.id);
      setSuccessMsg(`Document '${doc.original_filename}' administratively revoked.`);
      fetchDocuments();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke document.');
    }
  };

  const handleReactivateDocument = async (doc: EncryptedDocument) => {
    if (!token) return;

    try {
      await documentService.reactivateDocument(token, doc.id);
      setSuccessMsg(`Document '${doc.original_filename}' reactivated.`);
      fetchDocuments();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reactivate document.');
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
  };


  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Lock className="w-5 h-5 text-blue-500" />
            {canUpload ? 'Encrypted Documents & Key Wrapping' : 'Assigned Encrypted Documents'}
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            AES-256-GCM authenticated document encryption with post-quantum ML-KEM-768 recipient key encapsulation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {userDevices.length > 0 && (
            <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 bg-slate-900 border border-slate-800 px-2 py-1 rounded">
              <Smartphone className="w-3.5 h-3.5 text-blue-400" />
              <span>Device:</span>
              <select
                value={selectedDeviceId}
                onChange={(e) => setSelectedDeviceId(e.target.value)}
                className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded px-1 py-0.5"
              >
                {userDevices.map((dev) => (
                  <option key={dev.id} value={dev.id}>
                    {dev.device_name}
                  </option>
                ))}
              </select>
            </div>
          )}

          {canUpload && (
            <button
              onClick={() => setShowUpload(!showUpload)}
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded bg-blue-600 hover:bg-blue-500 text-white transition-colors"
            >
              <FileUp className="w-4 h-4" />
              {showUpload ? 'Close Form' : '+ Upload & Encrypt'}
            </button>
          )}
        </div>
      </div>

      {error && <ErrorBanner error={error} onDismiss={() => setError(null)} />}
      {successMsg && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded text-xs text-emerald-300 font-mono">
          {successMsg}
        </div>
      )}

      {/* Upload & Multi-Recipient Form */}
      {showUpload && canUpload && (
        <div className="bg-surface border border-border rounded p-4 space-y-4">
          <div className="border-b border-border pb-2">
            <h3 className="text-xs font-semibold text-slate-200 uppercase font-mono">
              Upload, Encrypt & Configure Policy
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Generates a random 256-bit DEK, encrypts the document once with AES-256-GCM, wraps DEK per recipient,
              and attaches access conditions.
            </p>
          </div>

          <form onSubmit={handleUploadAndEncrypt} className="space-y-4">
            <div>
              <label className="block text-[11px] uppercase text-slate-400 mb-1">
                Select File (PDF, DOCX, XLSX, TXT, CSV, JSON, PNG, JPG, ZIP)
              </label>
              <input
                type="file"
                onChange={handleFileChange}
                disabled={uploadStatus === 'ENCRYPTING'}
                required
                className="block w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-slate-200 hover:file:bg-slate-700 cursor-pointer border border-slate-700 rounded p-1 bg-slate-950"
              />
              {selectedFile && (
                <div className="mt-1 text-[11px] text-slate-400">
                  Selected: <span className="text-slate-200">{selectedFile.name}</span> ({formatFileSize(selectedFile.size)})
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-[11px] uppercase text-slate-400">Display Title (Optional)</label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  placeholder="Defaults to original filename"
                  disabled={uploadStatus === 'ENCRYPTING'}
                  className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
                />
              </div>

              <div>
                <label className="block text-[11px] uppercase text-slate-400">Classification Level</label>
                <select
                  value={classification}
                  onChange={(e) => setClassification(e.target.value)}
                  disabled={uploadStatus === 'ENCRYPTING'}
                  className="mt-1 block w-full px-3 py-1.5 text-xs bg-slate-950 border border-slate-700 rounded text-slate-100 font-mono"
                >
                  <option value="UNCLASSIFIED">UNCLASSIFIED</option>
                  <option value="RESTRICTED">RESTRICTED</option>
                  <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                  <option value="SECRET">SECRET</option>
                  <option value="TOP_SECRET">TOP_SECRET</option>
                </select>
              </div>
            </div>

            {/* Recipient Selection */}
            <div>
              <label className="block text-[11px] uppercase text-slate-400 mb-1 flex items-center gap-1.5">
                <Users className="w-3.5 h-3.5 text-blue-400" />
                Select Authorized Recipients (ML-KEM-768 Key Encapsulation)
              </label>
              {availableRecipients.length === 0 ? (
                <div className="p-3 border border-dashed border-border rounded text-[11px] text-slate-400">
                  No recipient users found. Recipients must be provisioned with an active ML-KEM-768 key by Admin.
                </div>
              ) : (
                <div className="max-h-36 overflow-y-auto border border-slate-800 rounded bg-slate-950 p-2 space-y-1.5 divide-y divide-slate-900">
                  {availableRecipients.map((rec) => (
                    <label
                      key={rec.id}
                      className={`flex items-center justify-between p-1.5 rounded cursor-pointer ${
                        rec.has_active_key ? 'hover:bg-slate-900/60' : 'opacity-50 cursor-not-allowed'
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={selectedRecipientIds.includes(rec.id)}
                          onChange={() => handleToggleRecipient(rec.id)}
                          disabled={!rec.has_active_key || uploadStatus === 'ENCRYPTING'}
                          className="rounded border-slate-700 text-blue-600 focus:ring-0"
                        />
                        <span className="text-slate-200 font-medium">{rec.username}</span>
                        <span className="text-[10px] text-slate-500">({rec.email})</span>
                      </div>
                      <span className="text-[10px]">
                        {rec.has_active_key ? (
                          <span className="text-emerald-400 flex items-center gap-1">
                            <ShieldCheck className="w-3 h-3" /> Key v{rec.active_key_version}
                          </span>
                        ) : (
                          <span className="text-amber-500 italic">No Key Provisioned</span>
                        )}
                      </span>
                    </label>
                  ))}
                </div>
              )}
              {selectedRecipientIds.length > 0 && (
                <div className="mt-1 text-[11px] text-blue-400">
                  {selectedRecipientIds.length} recipient(s) selected for key encapsulation.
                </div>
              )}
            </div>

            {/* Access Policy Configuration (Phase 5) */}
            <div className="border border-slate-800 rounded bg-slate-950/60 p-3 space-y-3">
              <span className="text-[11px] font-semibold text-slate-300 uppercase block flex items-center gap-1.5">
                <Settings2 className="w-3.5 h-3.5 text-blue-400" />
                Access Policy Conditions (Optional)
              </span>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="block text-[11px] text-slate-400">Valid From (UTC)</label>
                  <input
                    type="datetime-local"
                    value={policyValidFrom}
                    onChange={(e) => setPolicyValidFrom(e.target.value)}
                    className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400">Valid Until / Expiration (UTC)</label>
                  <input
                    type="datetime-local"
                    value={policyValidUntil}
                    onChange={(e) => setPolicyValidUntil(e.target.value)}
                    className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400">Max Permitted Decryptions</label>
                  <input
                    type="number"
                    min="1"
                    placeholder="e.g. 1 for One-Time Access"
                    value={policyMaxDecryptions}
                    onChange={(e) => setPolicyMaxDecryptions(e.target.value)}
                    className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400">Role Restriction (optional)</label>
                  <input
                    type="text"
                    placeholder="e.g. OFFICER, RECIPIENT"
                    value={policyAllowedRoles}
                    onChange={(e) => setPolicyAllowedRoles(e.target.value)}
                    className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                  />
                </div>
                <div className="flex items-center pt-5">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={policyRequireDevice}
                      onChange={(e) => setPolicyRequireDevice(e.target.checked)}
                      className="rounded border-slate-700 text-blue-600 focus:ring-0"
                    />
                    <span>Require Registered Device</span>
                  </label>
                </div>

                <div className="sm:col-span-2 pt-2 border-t border-slate-800 space-y-2">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={policyRequireMultiParty}
                      onChange={(e) => setPolicyRequireMultiParty(e.target.checked)}
                      className="rounded border-slate-700 text-purple-600 focus:ring-0"
                    />
                    <span>Require Multi-Party Decryption Approval</span>
                  </label>
                  {policyRequireMultiParty && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pl-4">
                      <div>
                        <label className="block text-[10px] text-slate-400">Required Approvals Threshold</label>
                        <input
                          type="number"
                          min="2"
                          value={policyRequiredApprovals}
                          onChange={(e) => setPolicyRequiredApprovals(e.target.value)}
                          className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                        />
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-400">Eligible Approver Roles</label>
                        <input
                          type="text"
                          placeholder="OFFICER, ADMIN"
                          value={policyEligibleApprovers}
                          onChange={(e) => setPolicyEligibleApprovers(e.target.value)}
                          className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <div className="sm:col-span-2 pt-2 border-t border-slate-800 space-y-2">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={policyAllowEmergency}
                      onChange={(e) => setPolicyAllowEmergency(e.target.checked)}
                      className="rounded border-slate-700 text-amber-500 focus:ring-0"
                    />
                    <span>Allow Emergency Break-Glass Access</span>
                  </label>
                  {policyAllowEmergency && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pl-4">
                      <div>
                        <label className="block text-[10px] text-slate-400">Eligible Emergency Roles</label>
                        <input
                          type="text"
                          placeholder="ADMIN, OFFICER"
                          value={policyEligibleEmergencyRoles}
                          onChange={(e) => setPolicyEligibleEmergencyRoles(e.target.value)}
                          className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                        />
                      </div>
                      <div>
                        <label className="block text-[10px] text-slate-400">Max Emergency Duration (mins)</label>
                        <input
                          type="number"
                          min="1"
                          max="120"
                          value={policyEmergencyDuration}
                          onChange={(e) => setPolicyEmergencyDuration(e.target.value)}
                          className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
              <button
                type="button"
                onClick={() => setShowUpload(false)}
                disabled={uploadStatus === 'ENCRYPTING'}
                className="px-3 py-1.5 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!selectedFile || uploadStatus === 'ENCRYPTING'}
                className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded font-medium disabled:opacity-50 transition-colors"
              >
                {uploadStatus === 'ENCRYPTING' ? 'Encrypting…' : 'Encrypt & Distribute'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Inspect Document Metadata Drawer */}
      {inspectDoc && (
        <div className="bg-surface border border-slate-700 p-5 rounded space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="font-semibold text-slate-200 uppercase flex items-center gap-2">
              <Hash className="w-4 h-4 text-blue-400" />
              Cryptographic Metadata: {inspectDoc.original_filename}
            </span>
            <button onClick={() => setInspectDoc(null)} className="text-slate-400 hover:text-slate-200 text-sm">
              &times;
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
            <div>
              <span className="text-slate-500 block uppercase">Document ID</span>
              <span className="text-slate-200 select-all">{inspectDoc.id}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase">Encryption Algorithm</span>
              <span className="text-slate-200">{inspectDoc.encryption_algorithm}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase">Original Size</span>
              <span className="text-slate-200">{formatFileSize(inspectDoc.original_size_bytes)}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase">Encrypted Size</span>
              <span className="text-slate-200">{formatFileSize(inspectDoc.encrypted_size_bytes)}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-500 block uppercase">Plaintext SHA-256 Digest</span>
              <span className="text-slate-300 break-all select-all font-mono text-[10px]">
                {inspectDoc.plaintext_sha256}
              </span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-500 block uppercase">Ciphertext SHA-256 Digest</span>
              <span className="text-slate-300 break-all select-all font-mono text-[10px]">
                {inspectDoc.ciphertext_sha256}
              </span>
            </div>

            {/* Access Policy Info */}
            {inspectDoc.policy && (
              <div className="sm:col-span-2 border-t border-slate-800 pt-3">
                <span className="text-slate-400 block uppercase font-semibold mb-1 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
                  Active Access Policy
                </span>
                <div className="p-2 bg-slate-950/60 rounded border border-slate-800 text-[10px] space-y-1">
                  <div>
                    Max Decryptions:{' '}
                    <span className="text-slate-200">
                      {inspectDoc.policy.max_decryptions ? inspectDoc.policy.max_decryptions : 'Unlimited'}
                    </span>
                  </div>
                  <div>
                    Device Bound:{' '}
                    <span className="text-slate-200">
                      {inspectDoc.policy.require_registered_device ? 'Required (Active Registered Device)' : 'No'}
                    </span>
                  </div>
                  {inspectDoc.policy.valid_from && (
                    <div>
                      Valid From: <span className="text-slate-200">{formatDate(inspectDoc.policy.valid_from)}</span>
                    </div>
                  )}
                  {inspectDoc.policy.valid_until && (
                    <div>
                      Valid Until: <span className="text-slate-200">{formatDate(inspectDoc.policy.valid_until)}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Recipient Distribution Metadata */}
            {inspectDoc.recipients && inspectDoc.recipients.length > 0 && (
              <div className="sm:col-span-2 border-t border-slate-800 pt-3">
                <span className="text-slate-400 block uppercase font-semibold mb-1 flex items-center gap-1.5">
                  <Users className="w-3.5 h-3.5 text-blue-400" />
                  Key Encapsulation Recipients ({inspectDoc.recipients.length})
                </span>
                <div className="space-y-1">
                  {inspectDoc.recipients.map((rec) => (
                    <div
                      key={rec.recipient_id}
                      className="flex items-center justify-between p-1.5 bg-slate-950/60 rounded border border-slate-800 text-[10px]"
                    >
                      <span className="text-slate-200 font-semibold">{rec.username || rec.recipient_id}</span>
                      <span className="text-slate-400">
                        {rec.key_algorithm} (v{rec.recipient_key_version})
                      </span>
                      <span className="text-emerald-400 font-mono">{rec.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Cryptographic Provenance & Tamper-Evident Ledger Modal (Phase 10) */}
      {provenanceModalDoc && (
        <div className="fixed inset-0 z-50 bg-black/85 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-surface border border-slate-700 rounded-lg max-w-4xl w-full p-5 space-y-4 font-mono text-xs shadow-2xl my-8">
            <div className="flex flex-wrap items-center justify-between border-b border-border pb-3 gap-2">
              <div>
                <h3 className="font-bold text-slate-100 text-sm flex items-center gap-2">
                  <FileCheck className="w-4 h-4 text-emerald-400" />
                  Provenance Chain & Permissioned Ledger
                </h3>
                <p className="text-[11px] text-slate-400 truncate max-w-lg mt-0.5">
                  Document: <span className="text-slate-200 font-semibold">{provenanceModalDoc.title}</span> ({provenanceModalDoc.original_filename})
                </p>
              </div>

              <div className="flex items-center gap-2">
                {chainHead && (
                  <span className="text-[10px] bg-slate-900 border border-slate-700 text-slate-300 px-2 py-1 rounded flex items-center gap-1 font-mono">
                    <Link2 className="w-3 h-3 text-blue-400" />
                    Chain Tip: Seq #{chainHead.latest_sequence}
                  </span>
                )}

                <button
                  type="button"
                  onClick={handleVerifyFullChain}
                  disabled={isVerifyingChain}
                  className="px-2.5 py-1 bg-emerald-600/90 hover:bg-emerald-500 text-white rounded font-medium text-[11px] flex items-center gap-1.5 transition-colors disabled:opacity-50"
                  title="Audits all records from Genesis (0) to Head, validating sequence continuity, hash linkages, signatures, and ledger anchors"
                >
                  <Link2 className="w-3.5 h-3.5" />
                  {isVerifyingChain ? 'Auditing Full Chain…' : 'Verify Full Chain'}
                </button>

                <button
                  onClick={() => {
                    setProvenanceModalDoc(null);
                    setProvenanceRecords([]);
                    setVerificationResults({});
                    setAnchorResults({});
                    setChainVerificationResult(null);
                  }}
                  className="text-slate-400 hover:text-slate-200 text-sm p-1 ml-1"
                >
                  &times;
                </button>
              </div>
            </div>

            {/* Full Chain Verification Banner */}
            {chainVerificationResult && (
              <div
                className={`p-3.5 rounded border text-[11px] space-y-2 ${
                  chainVerificationResult.chain_valid
                    ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
                    : 'bg-rose-950/40 border-rose-800 text-rose-200'
                }`}
              >
                <div className="flex items-center justify-between font-semibold">
                  <span className="flex items-center gap-2">
                    {chainVerificationResult.chain_valid ? (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        PROVENANCE CHAIN AUDIT PASSED: HASH CHAIN & LEDGER VALID
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="w-4 h-4 text-rose-400" />
                        PROVENANCE CHAIN INTEGRITY BREACH DETECTED
                      </>
                    )}
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    Audited at {formatDate(chainVerificationResult.verified_at)}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] text-slate-300 pt-1 font-mono">
                  <div>
                    Records Checked:{' '}
                    <span className="text-white font-bold">{chainVerificationResult.records_checked}</span>
                  </div>
                  <div>
                    Signatures Verified:{' '}
                    <span className="text-emerald-400 font-bold">{chainVerificationResult.signatures_verified}</span>
                  </div>
                  <div>
                    Ledger Anchors:{' '}
                    <span className="text-emerald-400 font-bold">{chainVerificationResult.ledger_anchors_verified}</span>
                  </div>
                  <div>
                    Chain ID:{' '}
                    <span className="text-slate-200">{chainVerificationResult.chain_id}</span>
                  </div>
                </div>

                {!chainVerificationResult.chain_valid && (
                  <div className="p-2 bg-rose-950/80 border border-rose-900 rounded text-rose-300 text-[10px] space-y-1">
                    <div>
                      Failure Type:{' '}
                      <span className="font-bold underline">{chainVerificationResult.failure_type}</span> at Sequence #{chainVerificationResult.first_invalid_sequence}
                    </div>
                    <div>Reason: {chainVerificationResult.failure_reason}</div>
                  </div>
                )}
              </div>
            )}

            {isLoadingProvenance ? (
              <div className="py-8 text-center text-slate-400 animate-pulse">
                Loading cryptographically signed provenance chain records…
              </div>
            ) : provenanceRecords.length === 0 ? (
              <div className="py-8 text-center text-slate-400 bg-slate-950/60 rounded border border-slate-800">
                <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="font-semibold text-slate-300">No Decryption Provenance Recorded Yet</p>
                <p className="text-[11px] text-slate-500 mt-1 max-w-md mx-auto">
                  A verifiable ML-DSA-65 signed provenance record is automatically chained and anchored in the permissioned ledger when an authorized recipient successfully decrypts this document.
                </p>
              </div>
            ) : (
              <div className="space-y-4 max-h-[65vh] overflow-y-auto pr-1">
                {provenanceRecords.map((record) => {
                  const verResult = verificationResults[record.event_id];
                  const isVerifying = verifyingEventId === record.event_id;
                  const anchorRes = anchorResults[record.event_id];
                  const isVerifyingAnchor = verifyingAnchorId === record.event_id;

                  return (
                    <div
                      key={record.event_id}
                      className="p-4 bg-slate-950/90 border border-slate-800 rounded space-y-3"
                    >
                      {/* Header & Status */}
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-indigo-950 border border-indigo-800 text-indigo-300 font-mono">
                            Seq #{record.chain_sequence ?? 'N/A'}
                          </span>

                          <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-blue-950 border border-blue-800 text-blue-300">
                            {record.signature_algorithm}
                          </span>

                          <span className="text-[10px] text-slate-400">
                            Key v{record.signature_key_version}
                          </span>

                          <span
                            className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                              record.access_type === 'EMERGENCY'
                                ? 'bg-rose-950/60 border-rose-800 text-rose-300'
                                : record.access_type === 'MULTI_PARTY_APPROVED'
                                ? 'bg-purple-950/60 border-purple-800 text-purple-300'
                                : 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                            }`}
                          >
                            Access: {record.access_type}
                          </span>

                          <span
                            className={`text-[10px] font-semibold px-2 py-0.5 rounded border flex items-center gap-1 ${
                              record.ledger_status === 'CONFIRMED'
                                ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                                : record.ledger_status === 'SIGNED_BUT_NOT_ANCHORED'
                                ? 'bg-amber-950/60 border-amber-800 text-amber-300'
                                : 'bg-slate-900 border-slate-800 text-slate-400'
                            }`}
                          >
                            <Anchor className="w-2.5 h-2.5" />
                            Ledger: {record.ledger_status || 'PENDING'}
                          </span>
                        </div>

                        <span className="text-[11px] text-slate-400">
                          {formatDate(record.event_timestamp)}
                        </span>
                      </div>

                      {/* Bound Provenance Metadata */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                        <div>
                          <span className="text-slate-500 block uppercase text-[10px]">Event ID</span>
                          <span className="text-slate-300 select-all font-mono">{record.event_id}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block uppercase text-[10px]">Recipient User ID</span>
                          <span className="text-slate-300 select-all font-mono">{record.user_id}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block uppercase text-[10px]">Document Version</span>
                          <span className="text-slate-300 font-mono">Version {record.document_version_id}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block uppercase text-[10px]">Device / Session</span>
                          <span className="text-slate-300 font-mono">
                            {record.device_id || 'N/A'} / {record.decryption_session_id.slice(0, 8)}…
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500 block uppercase text-[10px]">Policy Bound</span>
                          <span className="text-slate-300 font-mono">
                            Policy v{record.policy_version} ({record.policy_id.slice(0, 13)}…)
                          </span>
                        </div>
                        {record.approval_request_id && (
                          <div>
                            <span className="text-slate-500 block uppercase text-[10px]">Approval Request ID</span>
                            <span className="text-purple-300 select-all font-mono">{record.approval_request_id}</span>
                          </div>
                        )}
                        {record.emergency_access_request_id && (
                          <div>
                            <span className="text-slate-500 block uppercase text-[10px]">Emergency Request ID</span>
                            <span className="text-rose-300 select-all font-mono">{record.emergency_access_request_id}</span>
                          </div>
                        )}

                        <div className="sm:col-span-2">
                          <span className="text-slate-500 block uppercase text-[10px]">Canonical Record Hash</span>
                          <span className="text-emerald-400/90 break-all select-all font-mono text-[10px]">
                            {record.canonical_record_hash}
                          </span>
                        </div>

                        {/* Hash Chain Cryptographic Linkage Fields */}
                        <div className="sm:col-span-2 pt-1 border-t border-slate-900">
                          <span className="text-blue-400 block uppercase text-[10px] font-semibold flex items-center gap-1">
                            <Link2 className="w-3 h-3" />
                            Previous Record Hash (Chain Linkage)
                          </span>
                          <span className="text-slate-400 break-all select-all font-mono text-[10px]">
                            {record.previous_record_hash || '0'.repeat(64)}
                          </span>
                        </div>

                        <div className="sm:col-span-2">
                          <span className="text-blue-400 block uppercase text-[10px] font-semibold flex items-center gap-1">
                            <Link2 className="w-3 h-3" />
                            Current Chain Hash
                          </span>
                          <span className="text-blue-300 break-all select-all font-mono text-[10px]">
                            {record.chain_hash || 'Pending Calculation'}
                          </span>
                        </div>

                        {/* Ledger Transaction Reference */}
                        <div className="sm:col-span-2">
                          <span className="text-amber-400 block uppercase text-[10px] font-semibold flex items-center gap-1">
                            <Anchor className="w-3 h-3" />
                            Ledger Transaction Reference
                          </span>
                          <span className="text-amber-200 select-all font-mono text-[10px]">
                            {record.ledger_transaction_id || 'Pending Ledger Submission'}
                          </span>
                        </div>
                      </div>

                      {/* Live ML-DSA Cryptographic Verification Box */}
                      {verResult && (
                        <div
                          className={`p-3 rounded border text-[11px] space-y-1.5 ${
                            verResult.verified
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
                              : 'bg-rose-950/30 border-rose-800/80 text-rose-200'
                          }`}
                        >
                          <div className="flex items-center justify-between font-semibold">
                            <span className="flex items-center gap-1.5">
                              {verResult.verified ? (
                                <>
                                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                                  ML-DSA SIGNATURE VERIFIED (AUTHENTIC & IMMUTABLE)
                                </>
                              ) : (
                                <>
                                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                                  SIGNATURE VERIFICATION FAILED
                                </>
                              )}
                            </span>
                            <span className="text-[10px] text-slate-400">
                              Verified at {formatDate(verResult.verified_at)}
                            </span>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-[10px] text-slate-300 pt-1">
                            <div>
                              Hash Verification:{' '}
                              <span className={verResult.hash_valid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                                {verResult.hash_valid ? 'VALID' : 'INVALID (TAMPER DETECTED)'}
                              </span>
                            </div>
                            <div>
                              ML-DSA-65 Signature:{' '}
                              <span className={verResult.signature_valid ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                                {verResult.signature_valid ? 'VALID' : 'INVALID (SIGNATURE MISMATCH)'}
                              </span>
                            </div>
                            <div>
                              Signing Key Version:{' '}
                              <span className="text-slate-200">v{verResult.signature_key_version}</span>
                            </div>
                            <div>
                              Signing Key Status:{' '}
                              <span className="text-slate-200">{verResult.signing_key_status}</span>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Live Ledger Anchor Verification Box */}
                      {anchorRes && (
                        <div
                          className={`p-3 rounded border text-[11px] space-y-1.5 ${
                            anchorRes.is_anchored && anchorRes.hash_matched
                              ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-200'
                              : 'bg-rose-950/30 border-rose-800/80 text-rose-200'
                          }`}
                        >
                          <div className="flex items-center justify-between font-semibold">
                            <span className="flex items-center gap-1.5">
                              {anchorRes.is_anchored && anchorRes.hash_matched ? (
                                <>
                                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                                  LEDGER ANCHOR VERIFIED (INDEPENDENT EVIDENCE MATCHED)
                                </>
                              ) : (
                                <>
                                  <AlertTriangle className="w-4 h-4 text-rose-400" />
                                  LEDGER ANCHOR MISMATCH OR UNANCHORED
                                </>
                              )}
                            </span>
                            <span className="text-[10px] text-slate-400">
                              Audited at {formatDate(anchorRes.verified_at || anchorRes.anchored_at)}
                            </span>
                          </div>
                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[10px] text-slate-300 pt-1">
                            <div>
                              Ledger Status:{' '}
                              <span className="text-white font-bold">{anchorRes.status}</span>
                            </div>
                            <div>
                              Hash Match:{' '}
                              <span className={anchorRes.hash_matched ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                                {anchorRes.hash_matched ? 'MATCHED' : 'HASH MISMATCH'}
                              </span>
                            </div>
                            <div>
                              Ledger Tx:{' '}
                              <span className="text-amber-300 font-mono">{anchorRes.transaction_id || anchorRes.ledger_transaction_id || 'N/A'}</span>
                            </div>
                          </div>
                          {(anchorRes.details || anchorRes.message) && (
                            <p className="text-[10px] text-slate-400 pt-0.5">{anchorRes.details || anchorRes.message}</p>
                          )}
                        </div>
                      )}

                      {/* Actions */}
                      <div className="flex flex-wrap justify-end gap-2 pt-1 border-t border-slate-800/80">
                        <button
                          type="button"
                          onClick={() => handleVerifyProvenance(record.event_id)}
                          disabled={isVerifying}
                          className="px-3 py-1.5 bg-blue-600/90 hover:bg-blue-500 text-white rounded font-medium text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                          {isVerifying ? 'Verifying ML-DSA-65 Signature…' : 'Verify ML-DSA-65'}
                        </button>

                        <button
                          type="button"
                          onClick={() => handleVerifyAnchor(record.event_id)}
                          disabled={isVerifyingAnchor}
                          className="px-3 py-1.5 bg-amber-600/90 hover:bg-amber-500 text-white rounded font-medium text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                        >
                          <Anchor className="w-3.5 h-3.5" />
                          {isVerifyingAnchor ? 'Verifying Anchor…' : 'Verify Ledger Anchor'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-border-subtle">
              <button
                type="button"
                onClick={() => {
                  setProvenanceModalDoc(null);
                  setProvenanceRecords([]);
                  setVerificationResults({});
                  setAnchorResults({});
                  setChainVerificationResult(null);
                }}
                className="px-3.5 py-1 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Policy Edit Modal (Owner / Admin) */}
      {policyModalDoc && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-surface border border-slate-700 rounded-lg max-w-md w-full p-5 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <span className="font-semibold text-slate-200 uppercase flex items-center gap-1.5">
                <Settings2 className="w-4 h-4 text-blue-400" />
                Configure Policy: {policyModalDoc.original_filename}
              </span>
              <button
                onClick={() => setPolicyModalDoc(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                &times;
              </button>
            </div>

            {policyModalDoc.policy && (
              <div className="flex items-center gap-2 text-[10px] text-slate-400 bg-slate-950/60 p-2 rounded border border-slate-800">
                <span>Version: <strong className="text-slate-200">v{policyModalDoc.policy.policy_version || 1}</strong></span>
                <span>•</span>
                <span>Status: <strong className={policyModalDoc.policy.status === 'ACTIVE' ? 'text-emerald-400' : 'text-rose-400'}>{policyModalDoc.policy.status || 'ACTIVE'}</strong></span>
                <span>•</span>
                <span>Consumed: <strong className="text-slate-200">{policyModalDoc.policy.consumed_decryptions || 0}</strong></span>
              </div>
            )}

            <form onSubmit={handleSavePolicy} className="space-y-3">
              <div>
                <label className="block text-[11px] text-slate-400">Valid From (UTC)</label>
                <input
                  type="datetime-local"
                  value={editPolicyFrom}
                  onChange={(e) => setEditPolicyFrom(e.target.value)}
                  className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                />
              </div>

              <div>
                <label className="block text-[11px] text-slate-400">Valid Until / Expiration (UTC)</label>
                <input
                  type="datetime-local"
                  value={editPolicyUntil}
                  onChange={(e) => setEditPolicyUntil(e.target.value)}
                  className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                />
              </div>

              <div>
                <label className="block text-[11px] text-slate-400">Max Permitted Decryptions</label>
                <input
                  type="number"
                  min="1"
                  placeholder="Leave empty for unlimited"
                  value={editPolicyMaxDecryptions}
                  onChange={(e) => setEditPolicyMaxDecryptions(e.target.value)}
                  className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                />
              </div>

              <div>
                <label className="block text-[11px] text-slate-400">Role Restriction (optional)</label>
                <input
                  type="text"
                  placeholder="e.g. OFFICER, RECIPIENT"
                  value={editPolicyAllowedRoles}
                  onChange={(e) => setEditPolicyAllowedRoles(e.target.value)}
                  className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                />
              </div>

              <div className="pt-2">
                <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={editPolicyRequireDevice}
                    onChange={(e) => setEditPolicyRequireDevice(e.target.checked)}
                    className="rounded border-slate-700 text-blue-600 focus:ring-0"
                  />
                  <span>Require Registered Device</span>
                </label>
              </div>

              {/* Multi-Party Approval Configuration */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={editPolicyRequireMultiParty}
                    onChange={(e) => setEditPolicyRequireMultiParty(e.target.checked)}
                    className="rounded border-slate-700 text-purple-600 focus:ring-0"
                  />
                  <span>Require Multi-Party Decryption Approval</span>
                </label>
                {editPolicyRequireMultiParty && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pl-4">
                    <div>
                      <label className="block text-[10px] text-slate-400">Required Approvals Threshold</label>
                      <input
                        type="number"
                        min="2"
                        value={editPolicyRequiredApprovals}
                        onChange={(e) => setEditPolicyRequiredApprovals(e.target.value)}
                        className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">Eligible Approver Roles</label>
                      <input
                        type="text"
                        placeholder="OFFICER, ADMIN"
                        value={editPolicyEligibleApprovers}
                        onChange={(e) => setEditPolicyEligibleApprovers(e.target.value)}
                        className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Emergency Break-Glass Configuration */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={editPolicyAllowEmergency}
                    onChange={(e) => setEditPolicyAllowEmergency(e.target.checked)}
                    className="rounded border-slate-700 text-amber-500 focus:ring-0"
                  />
                  <span>Allow Emergency Break-Glass Access</span>
                </label>
                {editPolicyAllowEmergency && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pl-4">
                    <div>
                      <label className="block text-[10px] text-slate-400">Eligible Emergency Roles</label>
                      <input
                        type="text"
                        placeholder="ADMIN, OFFICER"
                        value={editPolicyEligibleEmergencyRoles}
                        onChange={(e) => setEditPolicyEligibleEmergencyRoles(e.target.value)}
                        className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">Max Emergency Duration (mins)</label>
                      <input
                        type="number"
                        min="1"
                        max="120"
                        value={editPolicyEmergencyDuration}
                        onChange={(e) => setEditPolicyEmergencyDuration(e.target.value)}
                        className="mt-1 block w-full px-2 py-1 bg-slate-950 border border-slate-700 rounded text-slate-200 text-xs"
                      />
                    </div>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-border-subtle">
                <button
                  type="button"
                  onClick={handleRevokePolicy}
                  disabled={isSavingPolicy}
                  className="px-2.5 py-1 text-xs border border-rose-900 text-rose-400 hover:bg-rose-950/40 rounded transition-colors"
                >
                  Revoke Policy
                </button>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setPolicyModalDoc(null)}
                    disabled={isSavingPolicy}
                    className="px-3 py-1 text-xs border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isSavingPolicy}
                    className="px-3.5 py-1 text-xs bg-blue-600 hover:bg-blue-500 text-white rounded font-medium disabled:opacity-50"
                  >
                    {isSavingPolicy ? 'Saving…' : 'Save Version'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Recipient Access Authorization Verification Modal (Phase 7 Real Policy Evaluation) */}
      {accessCheckDoc && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-surface border border-slate-700 rounded-lg max-w-md w-full p-5 space-y-4 font-mono text-xs shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-2.5">
              <div>
                <h3 className="font-bold text-slate-100 text-sm flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  Access Authorization Verification
                </h3>
                <p className="text-[11px] text-slate-400 truncate max-w-xs mt-0.5">
                  {accessCheckDoc.title} ({accessCheckDoc.original_filename})
                </p>
              </div>
              <button
                onClick={() => {
                  setAccessCheckDoc(null);
                  setAccessCheckResult(null);
                }}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                &times;
              </button>
            </div>

            {accessCheckLoading ? (
              <div className="py-8 text-center text-slate-400 animate-pulse">
                Evaluating authoritative backend policy checks…
              </div>
            ) : accessCheckResult ? (
              <div className="space-y-3.5">
                <div className="space-y-1.5">
                  <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block mb-1">
                    Access checks
                  </span>

                  <div className="flex items-center justify-between py-1.5 px-3 rounded bg-slate-950/70 border border-slate-800">
                    <span className="text-slate-300">Identity verified</span>
                    {accessCheckResult.checks.identity_verified ? (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">✓ Verified</span>
                    ) : (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">✗ Failed</span>
                    )}
                  </div>

                  <div className="flex items-center justify-between py-1.5 px-3 rounded bg-slate-950/70 border border-slate-800">
                    <span className="text-slate-300">Recipient authorized</span>
                    {accessCheckResult.checks.recipient_authorized ? (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">✓ Authorized</span>
                    ) : (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">✗ Failed</span>
                    )}
                  </div>

                  <div className="flex items-center justify-between py-1.5 px-3 rounded bg-slate-950/70 border border-slate-800">
                    <span className="text-slate-300">Device verified</span>
                    {accessCheckResult.checks.device_verified ? (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">✓ Verified</span>
                    ) : (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">✗ Required / Revoked</span>
                    )}
                  </div>

                  <div className="flex items-center justify-between py-1.5 px-3 rounded bg-slate-950/70 border border-slate-800">
                    <span className="text-slate-300">Policy active</span>
                    {accessCheckResult.checks.policy_active ? (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">✓ Active</span>
                    ) : (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">✗ Inactive / Revoked</span>
                    )}
                  </div>

                  <div className="flex items-center justify-between py-1.5 px-3 rounded bg-slate-950/70 border border-slate-800">
                    <span className="text-slate-300">Time window valid</span>
                    {accessCheckResult.checks.time_window_valid ? (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">✓ Valid</span>
                    ) : (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">✗ Expired / Not Started</span>
                    )}
                  </div>

                  <div className="flex items-center justify-between py-1.5 px-3 rounded bg-slate-950/70 border border-slate-800">
                    <span className="text-slate-300">Decryption allowance available</span>
                    {accessCheckResult.checks.decryption_allowance_available ? (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">✓ Available</span>
                    ) : (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">✗ Limit Reached</span>
                    )}
                  </div>

                  {Boolean(accessCheckDoc.policy?.require_multi_party_approval || accessCheckDoc.policy?.require_approval) && (
                    <div className="flex items-center justify-between py-1.5 px-3 rounded bg-slate-950/70 border border-slate-800">
                      <span className="text-slate-300">Multi-party approval</span>
                      {accessCheckResult.checks.approval_verified ? (
                        <span className="text-emerald-400 font-semibold flex items-center gap-1">✓ Approved</span>
                      ) : (
                        <span className="text-amber-400 font-semibold flex items-center gap-1">⏳ Required</span>
                      )}
                    </div>
                  )}
                </div>

                {/* Contextual Multi-Party Approval Block for Requester (Section 11) */}
                {Boolean(accessCheckDoc.policy?.require_multi_party_approval || accessCheckDoc.policy?.require_approval) && (() => {
                  const activeApprovalReq = approvalRequests.find(
                    (req) =>
                      req.document_id === accessCheckDoc.id &&
                      req.requesting_user_id === user?.id &&
                      (req.status === 'PENDING' || req.status === 'APPROVED')
                  );

                  return (
                    <div className="p-3 bg-slate-950/90 border border-purple-900/60 rounded space-y-2 text-[11px]">
                      <div className="font-semibold text-purple-300 uppercase tracking-wider text-[10px] flex items-center gap-1.5">
                        <Users className="w-3.5 h-3.5 text-purple-400" />
                        Multi-Party Approval
                      </div>
                      <div className="space-y-1 text-slate-300">
                        <div>Document: <span className="text-slate-100 font-semibold">{accessCheckDoc.original_filename}</span></div>
                        <div>Access policy: <span className="text-slate-100">Version {accessCheckDoc.policy?.policy_version || 1}</span></div>
                        <div>Approval required: <span className="text-slate-100 font-bold">{accessCheckDoc.policy?.required_approvals || 2}</span></div>
                        <div className="pt-1">
                          Approval status:{' '}
                          <span
                            className={`font-bold ${
                              activeApprovalReq?.status === 'APPROVED' ? 'text-emerald-400' : 'text-amber-400'
                            }`}
                          >
                            {activeApprovalReq
                              ? `${activeApprovalReq.current_approvals} / ${activeApprovalReq.required_approvals}`
                              : `0 / ${accessCheckDoc.policy?.required_approvals || 2}`}
                          </span>
                          {activeApprovalReq && (
                            <span className="ml-1.5 text-[10px] text-slate-400 font-mono">[{activeApprovalReq.status}]</span>
                          )}
                        </div>
                      </div>

                      {activeApprovalReq && activeApprovalReq.status === 'PENDING' && (
                        <div className="pt-1.5 flex items-center justify-between border-t border-purple-900/30">
                          <span className="text-amber-400 animate-pulse text-[10px]">Waiting for authorized approvers...</span>
                          <button
                            type="button"
                            onClick={() => handleCancelApprovalRequest(activeApprovalReq.id)}
                            disabled={Boolean(cancellingRequestId)}
                            className="text-[10px] text-rose-400 hover:text-rose-300 underline"
                          >
                            {cancellingRequestId === activeApprovalReq.id ? 'Cancelling…' : 'Cancel Request'}
                          </button>
                        </div>
                      )}

                      {(!activeApprovalReq || activeApprovalReq.status === 'REJECTED' || activeApprovalReq.status === 'EXPIRED' || activeApprovalReq.status === 'CANCELLED') && (
                        <button
                          type="button"
                          onClick={() => handleRequestApproval(accessCheckDoc)}
                          disabled={isRequestingApprovalDocId === accessCheckDoc.id}
                          className="w-full mt-2 py-1.5 px-3 bg-purple-600 hover:bg-purple-500 text-white rounded text-xs font-medium transition-colors"
                        >
                          {isRequestingApprovalDocId === accessCheckDoc.id ? 'Submitting…' : 'Request Multi-Party Approval'}
                        </button>
                      )}
                    </div>
                  );
                })()}

                {!accessCheckResult.allowed && (
                  <div className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-rose-300 text-xs">
                    {accessCheckResult.message || `Access Denied: ${accessCheckResult.reason_code}`}
                  </div>
                )}

                <div className="flex justify-end gap-2 pt-3 border-t border-border-subtle">
                  <button
                    onClick={() => {
                      setAccessCheckDoc(null);
                      setAccessCheckResult(null);
                    }}
                    className="px-3 py-1.5 border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
                  >
                    Close
                  </button>
                  {(() => {
                    const approvedReq = approvalRequests.find(
                      (req) =>
                        req.document_id === accessCheckDoc.id &&
                        req.requesting_user_id === user?.id &&
                        req.status === 'APPROVED'
                    );

                    return (
                      <button
                        onClick={() => handleExecuteDecrypt(accessCheckDoc, approvedReq?.id)}
                        disabled={!accessCheckResult.allowed || decryptingDocId === accessCheckDoc.id}
                        className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white rounded font-medium inline-flex items-center gap-1.5"
                      >
                        <Unlock className="w-3.5 h-3.5" />
                        {decryptingDocId === accessCheckDoc.id ? 'Decrypting…' : 'Decrypt Document'}
                      </button>
                    );
                  })()}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Controlled Decrypted Document Viewer Modal supporting PDFs, Images, Office Docs, Text */}
      {decryptedResult && (
        <DecryptedDocumentViewer
          result={decryptedResult}
          isEmergencySession={isEmergencySession}
          onClose={handleCloseViewer}
          formatDate={formatDate}
        />
      )}

      {/* Emergency Break-Glass Access Modal (Phase 8) */}
      {emergencyModalDoc && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-surface border border-rose-800/80 rounded-lg max-w-lg w-full p-5 space-y-4 font-mono text-xs shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-rose-400" />
                <div>
                  <h3 className="font-bold text-slate-100 text-sm">Emergency Break-Glass Access</h3>
                  <span className="text-[10px] text-slate-400">
                    {emergencyModalDoc.title} ({emergencyModalDoc.original_filename})
                  </span>
                </div>
              </div>
              <button
                onClick={() => setEmergencyModalDoc(null)}
                className="text-slate-400 hover:text-slate-200 text-base"
              >
                &times;
              </button>
            </div>

            {/* Protocol Notice */}
            <div className="p-3 bg-rose-950/40 border border-rose-900/60 rounded space-y-1 text-slate-300 text-[11px]">
              <div className="font-semibold text-rose-300 flex items-center gap-1 text-[10px] uppercase">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                Strict Operational Break-Glass Protocol
              </div>
              <ul className="list-disc list-inside space-y-0.5 text-slate-400 text-[10px]">
                <li>Explicit operational necessity justification required (minimum 15 characters).</li>
                <li>Requires independent emergency authorization before decryption.</li>
                <li>Emergency authorization is strictly time-limited.</li>
                <li>All key accesses and decryptions are immutably logged to the audit log.</li>
              </ul>
            </div>

            {/* Current Request State if exists */}
            {(() => {
              const activeReq = emergencyRequests.find(
                (r) =>
                  r.document_id === emergencyModalDoc.id &&
                  (r.status === 'REQUESTED' || r.status === 'AUTHORIZED')
              );

              if (!activeReq) {
                return (
                  <form onSubmit={handleSubmitEmergencyRequest} className="space-y-3">
                    <div>
                      <label className="text-slate-400 text-[10px] uppercase font-semibold block mb-1">
                        Incident Reason / Justification (Min 15 chars)
                      </label>
                      <textarea
                        value={emergencyReason}
                        onChange={(e) => setEmergencyReason(e.target.value)}
                        placeholder="Urgent incident response requires immediate access to the restricted report."
                        rows={3}
                        required
                        className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-200 text-xs focus:outline-none focus:border-rose-500"
                      />
                      <span className="text-[10px] text-slate-500">
                        {emergencyReason.length} / 15 characters minimum
                      </span>
                    </div>

                    <div>
                      <label className="text-slate-400 text-[10px] uppercase font-semibold block mb-1">
                        Requested Access Duration (Minutes)
                      </label>
                      <input
                        type="number"
                        min="1"
                        max="60"
                        value={emergencyDurationMinutes}
                        onChange={(e) => setEmergencyDurationMinutes(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-700 rounded p-1.5 text-slate-200 text-xs focus:outline-none focus:border-rose-500"
                      />
                    </div>

                    <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
                      <button
                        type="button"
                        onClick={() => setEmergencyModalDoc(null)}
                        className="px-3 py-1.5 border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={isSubmittingEmergency || emergencyReason.trim().length < 15}
                        className="px-4 py-1.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white rounded font-medium inline-flex items-center gap-1.5 transition-colors"
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        {isSubmittingEmergency ? 'Submitting…' : 'Submit Break-Glass Request'}
                      </button>
                    </div>
                  </form>
                );
              }

              // Active request exists
              const isRequester = activeReq.requester_user_id === user?.id;
              const canAuthorize = !isRequester && (user?.role === 'ADMIN' || user?.role === 'OFFICER');

              return (
                <div className="space-y-3">
                  <div className="p-3 bg-slate-950/80 border border-slate-800 rounded space-y-1.5 text-[11px]">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Request ID:</span>
                      <span className="text-slate-200 font-mono">{activeReq.id.slice(0, 13)}…</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Status:</span>
                      <span
                        className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                          activeReq.status === 'AUTHORIZED'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-amber-950 text-amber-400 border border-amber-800'
                        }`}
                      >
                        {activeReq.status}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Requester:</span>
                      <span className="text-slate-200">{activeReq.requester_user_id}</span>
                    </div>
                    <div className="pt-1">
                      <span className="text-slate-400 block mb-0.5">Reason:</span>
                      <p className="text-slate-200 bg-slate-900 p-2 rounded border border-slate-800 italic">
                        "{activeReq.reason}"
                      </p>
                    </div>
                    {activeReq.status === 'AUTHORIZED' && activeReq.expires_at && (
                      <div className="flex items-center justify-between pt-1 text-emerald-400 font-semibold">
                        <span>Authorized Until:</span>
                        <span>{formatDate(activeReq.expires_at)}</span>
                      </div>
                    )}
                  </div>

                  {/* Independent Approver Actions */}
                  {activeReq.status === 'REQUESTED' && canAuthorize && (
                    <div className="space-y-2 pt-2 border-t border-slate-800">
                      <span className="text-[10px] text-slate-400 block uppercase font-semibold">
                        Independent Emergency Authorization
                      </span>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => handleApproveEmergency(activeReq.id)}
                          disabled={Boolean(isApprovingEmergencyId)}
                          className="flex-1 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-medium transition-colors"
                        >
                          {isApprovingEmergencyId === activeReq.id ? 'Authorizing…' : 'Authorize Emergency Access'}
                        </button>
                      </div>
                      <div className="pt-1.5 flex gap-2">
                        <input
                          type="text"
                          placeholder="Rejection reason…"
                          value={emergencyRejectionReasons[activeReq.id] || ''}
                          onChange={(e) =>
                            setEmergencyRejectionReasons((prev) => ({
                              ...prev,
                              [activeReq.id]: e.target.value,
                            }))
                          }
                          className="flex-1 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs"
                        />
                        <button
                          type="button"
                          onClick={() => handleRejectEmergency(activeReq.id)}
                          disabled={Boolean(isRejectingEmergencyId) || !emergencyRejectionReasons[activeReq.id]?.trim()}
                          className="px-3 py-1 bg-rose-900/60 hover:bg-rose-800 disabled:opacity-50 text-white rounded text-xs transition-colors"
                        >
                          {isRejectingEmergencyId === activeReq.id ? 'Rejecting…' : 'Reject'}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Requester Waiting State */}
                  {activeReq.status === 'REQUESTED' && isRequester && (
                    <div className="p-2.5 rounded bg-amber-950/40 border border-amber-800 text-amber-300 text-center animate-pulse text-[11px]">
                      ⏳ Awaiting independent authorization from an eligible officer or admin.
                    </div>
                  )}

                  {/* Authorized State: Execute Decryption */}
                  {activeReq.status === 'AUTHORIZED' && (
                    <div className="pt-2">
                      <button
                        type="button"
                        onClick={() => handleExecuteEmergencyDecrypt(emergencyModalDoc, activeReq.id)}
                        disabled={isExecutingEmergencyDocId === emergencyModalDoc.id}
                        className="w-full py-2 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded flex items-center justify-center gap-2 shadow transition-colors"
                      >
                        <Unlock className="w-4 h-4" />
                        {isExecutingEmergencyDocId === emergencyModalDoc.id
                          ? 'Executing Emergency Decryption…'
                          : 'Execute Emergency Decryption'}
                      </button>
                    </div>
                  )}

                  <div className="flex justify-end pt-2 border-t border-border-subtle">
                    <button
                      type="button"
                      onClick={() => setEmergencyModalDoc(null)}
                      className="px-3 py-1 border border-slate-700 text-slate-400 hover:text-slate-200 rounded"
                    >
                      Close
                    </button>
                  </div>
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* Approver Reviews: Pending Multi-Party Approval Requests (Section 11) */}
      {canApprove && (() => {
        const pendingForReview = approvalRequests.filter((req) => req.status === 'PENDING');
        if (pendingForReview.length === 0) return null;

        return (
          <div className="p-4 bg-purple-950/20 border border-purple-900/50 rounded-lg space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="font-bold text-purple-300 flex items-center gap-1.5 uppercase text-[11px]">
                <Users className="w-4 h-4 text-purple-400" />
                Pending Multi-Party Approval Reviews ({pendingForReview.length})
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {pendingForReview.map((req) => {
                const isRequester = req.requesting_user_id === user?.id;
                const hasApproved = req.records?.some((rec) => rec.approver_user_id === user?.id);
                const relatedDoc = documents.find((d) => d.id === req.document_id);

                return (
                  <div
                    key={req.id}
                    className="p-3 bg-slate-950/80 border border-purple-900/30 rounded space-y-2 text-[11px]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-slate-100 font-semibold truncate max-w-[200px]">
                        {relatedDoc?.original_filename || req.document_id.slice(0, 13)}
                      </span>
                      <span className="text-purple-400 font-mono text-[10px]">
                        {req.current_approvals} / {req.required_approvals} Approvals
                      </span>
                    </div>
                    <div className="space-y-0.5 text-slate-400 text-[10px]">
                      <div>
                        Requester: <span className="text-slate-200">{req.requesting_user_id}</span>
                      </div>
                      <div>
                        Policy summary: <span className="text-slate-200">Version {req.policy_version}, Requires {req.required_approvals} approvals</span>
                      </div>
                      <div>
                        Requested: <span className="text-slate-200">{formatDate(req.created_at)}</span>
                      </div>
                      <div>
                        Expires: <span className="text-amber-400">{formatDate(req.expires_at)}</span>
                      </div>
                    </div>

                    {isRequester ? (
                      <div className="p-1.5 bg-slate-900 border border-slate-800 rounded text-amber-400 text-[10px] text-center">
                        Your request (Requester cannot approve own request)
                      </div>
                    ) : hasApproved ? (
                      <div className="p-1.5 bg-emerald-950/40 border border-emerald-900/60 rounded text-emerald-400 text-[10px] text-center flex items-center justify-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        Approved by you (waiting for remaining approvals)
                      </div>
                    ) : (
                      <div className="space-y-1.5 pt-1 border-t border-purple-900/30">
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => handleApproveRequest(req.id)}
                            disabled={Boolean(isApprovingRequestId)}
                            className="flex-1 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded text-[11px] font-medium transition-colors"
                          >
                            {isApprovingRequestId === req.id ? 'Approving…' : 'Approve'}
                          </button>
                        </div>
                        <div className="flex gap-1.5">
                          <input
                            type="text"
                            placeholder="Rejection reason…"
                            value={approvalRejectionReasons[req.id] || ''}
                            onChange={(e) =>
                              setApprovalRejectionReasons((prev) => ({
                                ...prev,
                                [req.id]: e.target.value,
                              }))
                            }
                            className="flex-1 bg-slate-900 border border-slate-700 rounded px-2 py-0.5 text-slate-200 text-[11px]"
                          />
                          <button
                            type="button"
                            onClick={() => handleRejectRequest(req.id)}
                            disabled={Boolean(isRejectingRequestId) || !approvalRejectionReasons[req.id]?.trim()}
                            className="px-2.5 py-0.5 bg-rose-900/60 hover:bg-rose-800 disabled:opacity-40 text-white rounded text-[11px] transition-colors"
                          >
                            {isRejectingRequestId === req.id ? 'Rejecting…' : 'Reject'}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* Approver Reviews: Pending Emergency Break-Glass Authorizations (Section 16) */}
      {canApprove && (() => {
        const pendingEmergForReview = emergencyRequests.filter((req) => req.status === 'REQUESTED');
        if (pendingEmergForReview.length === 0) return null;

        return (
          <div className="p-4 bg-rose-950/20 border border-rose-900/50 rounded-lg space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="font-bold text-rose-300 flex items-center gap-1.5 uppercase text-[11px]">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                Pending Emergency Break-Glass Authorizations ({pendingEmergForReview.length})
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {pendingEmergForReview.map((req) => {
                const isRequester = req.requester_user_id === user?.id;
                const relatedDoc = documents.find((d) => d.id === req.document_id);

                return (
                  <div
                    key={req.id}
                    className="p-3 bg-slate-950/80 border border-rose-900/30 rounded space-y-2 text-[11px]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-slate-100 font-semibold truncate max-w-[200px]">
                        {relatedDoc?.original_filename || req.document_id.slice(0, 13)}
                      </span>
                      <span className="text-rose-400 font-mono text-[10px]">
                        {req.requested_duration_minutes || 15} min window
                      </span>
                    </div>
                    <div className="space-y-0.5 text-slate-400 text-[10px]">
                      <div>
                        Requester: <span className="text-slate-200">{req.requester_user_id} ({req.requester_role})</span>
                      </div>
                      <div>
                        Requested at: <span className="text-slate-200">{formatDate(req.created_at)}</span>
                      </div>
                      <div className="pt-0.5">
                        <span className="block text-slate-400">Reason:</span>
                        <p className="text-slate-200 italic bg-slate-900 p-1.5 rounded border border-slate-800">
                          "{req.reason}"
                        </p>
                      </div>
                    </div>

                    {isRequester ? (
                      <div className="p-1.5 bg-slate-900 border border-slate-800 rounded text-amber-400 text-[10px] text-center">
                        Your request (Requester cannot authorize own emergency access)
                      </div>
                    ) : (
                      <div className="space-y-1.5 pt-1 border-t border-rose-900/30">
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => handleApproveEmergency(req.id)}
                            disabled={Boolean(isApprovingEmergencyId)}
                            className="flex-1 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[11px] font-medium transition-colors"
                          >
                            {isApprovingEmergencyId === req.id ? 'Authorizing…' : 'Authorize Emergency Access'}
                          </button>
                        </div>
                        <div className="flex gap-1.5">
                          <input
                            type="text"
                            placeholder="Rejection reason…"
                            value={emergencyRejectionReasons[req.id] || ''}
                            onChange={(e) =>
                              setEmergencyRejectionReasons((prev) => ({
                                ...prev,
                                [req.id]: e.target.value,
                              }))
                            }
                            className="flex-1 bg-slate-900 border border-slate-700 rounded px-2 py-0.5 text-slate-200 text-[11px]"
                          />
                          <button
                            type="button"
                            onClick={() => handleRejectEmergency(req.id)}
                            disabled={Boolean(isRejectingEmergencyId) || !emergencyRejectionReasons[req.id]?.trim()}
                            className="px-2.5 py-0.5 bg-rose-900/60 hover:bg-rose-800 disabled:opacity-40 text-white rounded text-[11px] transition-colors"
                          >
                            {isRejectingEmergencyId === req.id ? 'Rejecting…' : 'Reject'}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* Documents Table */}
      <div className="bg-surface border border-border rounded overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            Querying encrypted documents from PostgreSQL...
          </div>
        ) : documents.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            {canUpload
              ? 'No encrypted documents stored. Click "+ Upload & Encrypt" to encrypt a document.'
              : 'No encrypted documents have been distributed to your account.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 border-b border-border text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-4">Title / Filename</th>
                  <th className="py-2.5 px-4">Classification</th>
                  <th className="py-2.5 px-4">Size</th>
                  <th className="py-2.5 px-4">Policy / Restrictions</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Uploaded</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-slate-300">
                {documents.map((d) => {
                  const isAssignedRecipient =
                    d.recipients?.some((r) => r.recipient_id === user?.id && r.status === 'ACTIVE') ?? false;
                  const isOwnerOrAdmin = user?.role === 'ADMIN' || user?.id === d.owner_id;
                  const canAttemptDecrypt = isAssignedRecipient || user?.role === 'RECIPIENT';
                  const isDecryptingThis = decryptingDocId === d.id;

                  return (
                    <tr key={d.id} className="hover:bg-slate-900/30 transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-semibold text-slate-100 block">{d.title}</span>
                        <span className="text-[11px] text-slate-400">{d.original_filename}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                          {d.classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        <span>{formatFileSize(d.original_size_bytes)}</span>
                        <span className="text-[10px] text-slate-500 block">
                          Cipher: {formatFileSize(d.encrypted_size_bytes)}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">
                        {d.policy ? (
                          <div className="space-y-0.5">
                            {d.policy.max_decryptions === 1 && (
                              <span className="inline-block text-[10px] px-1.5 py-0.2 rounded bg-amber-950/60 border border-amber-800 text-amber-300 mr-1">
                                One-Time
                              </span>
                            )}
                            {d.policy.require_registered_device && (
                              <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.2 rounded bg-blue-950/60 border border-blue-800 text-blue-300 mr-1">
                                <Smartphone className="w-2.5 h-2.5" /> Device
                              </span>
                            )}
                            {Boolean(d.policy.require_multi_party_approval || d.policy.require_approval) && (
                              <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.2 rounded bg-purple-950/60 border border-purple-800 text-purple-300 mr-1">
                                <Users className="w-2.5 h-2.5" /> {d.policy.required_approvals || 2}-Approvals
                              </span>
                            )}
                            {d.policy.allow_emergency_access && (
                              <span className="inline-flex items-center gap-0.5 text-[10px] px-1.5 py-0.2 rounded bg-rose-950/60 border border-rose-800 text-rose-300 mr-1">
                                <AlertTriangle className="w-2.5 h-2.5" /> Break-Glass
                              </span>
                            )}
                            {d.policy.valid_until && (
                              <span className="text-[10px] text-slate-500 block flex items-center gap-1">
                                <Clock className="w-2.5 h-2.5" /> Exp: {formatDate(d.policy.valid_until)}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-600 italic text-[10px]">Default Access</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                            d.status === 'ENCRYPTED'
                              ? 'bg-emerald-950/40 border-emerald-800 text-emerald-400'
                              : d.status === 'ENCRYPTING'
                              ? 'bg-blue-950/40 border-blue-800 text-blue-400'
                              : 'bg-rose-950/40 border-rose-800 text-rose-400'
                          }`}
                        >
                          {d.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px]">{formatDate(d.created_at)}</td>
                      <td className="py-3 px-4 text-right space-x-1.5 whitespace-nowrap">
                        {/* Recipient Open / Decrypt Button */}
                        {canAttemptDecrypt && (
                          <button
                            onClick={() => handleOpenAccessCheck(d)}
                            disabled={isDecryptingThis || d.status === 'REVOKED'}
                            className="px-2.5 py-1 text-[11px] bg-emerald-600/80 hover:bg-emerald-500 text-white rounded font-medium disabled:opacity-50 transition-colors inline-flex items-center gap-1"
                          >
                            <Unlock className="w-3 h-3" />
                            {isDecryptingThis ? 'Decrypting…' : 'Open'}
                          </button>
                        )}

                        {/* Emergency Break-Glass Button (Section 21: shown only when user has permission & doc allows) */}
                        {canEmergencyAccess && d.policy?.allow_emergency_access && (
                          <button
                            onClick={() => handleOpenEmergencyModal(d)}
                            className="px-2 py-1 text-[11px] border border-rose-900/80 bg-rose-950/30 hover:bg-rose-900/50 text-rose-300 hover:text-rose-100 rounded font-medium transition-colors inline-flex items-center gap-1"
                            title="Request time-limited emergency break-glass access"
                          >
                            <AlertTriangle className="w-3 h-3 text-rose-400" />
                            Break-Glass
                          </button>
                        )}

                        <button
                          onClick={() => setInspectDoc(d)}
                          className="px-2 py-1 text-[11px] border border-slate-700 hover:border-slate-500 rounded text-slate-300 hover:text-white transition-colors"
                          title="View cryptographic hashes"
                        >
                          Hashes
                        </button>

                        <button
                          onClick={() => handleOpenProvenanceModal(d)}
                          className="px-2 py-1 text-[11px] border border-emerald-900/60 bg-emerald-950/20 hover:bg-emerald-900/40 text-emerald-300 hover:text-emerald-100 rounded font-medium transition-colors inline-flex items-center gap-1"
                          title="View cryptographic ML-DSA-65 provenance records"
                        >
                          <FileCheck className="w-3 h-3 text-emerald-400" />
                          Provenance
                        </button>

                        {/* Owner / Admin Policy Button */}
                        {isOwnerOrAdmin && (
                          <button
                            onClick={() => handleOpenPolicyModal(d)}
                            className="px-2 py-1 text-[11px] border border-slate-700 hover:border-blue-500 text-slate-300 hover:text-blue-300 rounded transition-colors"
                            title="Edit access policy conditions"
                          >
                            <Settings2 className="w-3.5 h-3.5 inline" />
                          </button>
                        )}

                        {/* Owner / Admin Revoke / Reactivate Document */}
                        {isOwnerOrAdmin && (d.status === 'ENCRYPTED' || d.status === 'ACTIVE') && (
                          <button
                            onClick={() => handleRevokeDocument(d)}
                            className="px-2 py-1 text-[11px] border border-amber-900/70 text-amber-400 hover:bg-amber-950/40 rounded transition-colors"
                            title="Administratively revoke document access"
                          >
                            Revoke
                          </button>
                        )}

                        {isOwnerOrAdmin && d.status === 'REVOKED' && (
                          <button
                            onClick={() => handleReactivateDocument(d)}
                            className="px-2 py-1 text-[11px] border border-emerald-900/70 text-emerald-400 hover:bg-emerald-950/40 rounded transition-colors"
                            title="Reactivate revoked document access"
                          >
                            Reactivate
                          </button>
                        )}

                        {isOwnerOrAdmin && (
                          <button
                            onClick={() => handleDelete(d)}
                            className="px-2 py-1 text-[11px] border border-rose-900/60 text-rose-400 hover:bg-rose-950/40 rounded transition-colors"
                            title="Delete encrypted document"
                          >
                            <Trash2 className="w-3.5 h-3.5 inline" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
