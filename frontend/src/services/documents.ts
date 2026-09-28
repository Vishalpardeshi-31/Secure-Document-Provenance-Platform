import { request, requestBlob } from './api';
import {
  EncryptedDocument,
  RecipientUserSummary,
  RecipientKeyDetail,
  AccessPolicy,
  AccessPolicyUpdatePayload,
  DocumentAccessCheckResult,
  DecryptionResult,
  ApprovalRequest,
  EmergencyAccessRequest,
  ProvenanceRecord,
  ProvenanceVerificationResult,
  ProvenanceChainHead,
  ProvenanceChainVerificationResult,
  LedgerAnchorVerificationResult,
  ViewerSessionResponse,
  ViewerHeartbeatResponse,
  ViewerCloseResponse,
  ViewerSessionCreatePayload,
} from '../types/auth';

export const documentService = {
  async listDocuments(token: string): Promise<EncryptedDocument[]> {
    return request<EncryptedDocument[]>('/documents', {
      method: 'GET',
      token,
    });
  },

  async getDocument(token: string, documentId: string): Promise<EncryptedDocument> {
    return request<EncryptedDocument>(`/documents/${documentId}`, {
      method: 'GET',
      token,
    });
  },

  async uploadDocument(
    token: string,
    file: File,
    title?: string,
    classification: string = 'RESTRICTED',
    recipientIds?: string[],
    policy?: {
      valid_from?: string;
      valid_until?: string;
      max_decryptions?: number;
      require_registered_device?: boolean;
      allowed_roles?: string;
      require_multi_party_approval?: boolean;
      required_approvals?: number;
      eligible_approver_roles?: string;
      allow_emergency_access?: boolean;
      eligible_emergency_roles?: string;
      maximum_emergency_duration?: number;
    }
  ): Promise<EncryptedDocument> {
    const formData = new FormData();
    formData.append('file', file);
    if (title) formData.append('title', title);
    formData.append('classification', classification);
    if (recipientIds && recipientIds.length > 0) {
      formData.append('recipient_ids', recipientIds.join(','));
    }
    if (policy) {
      if (policy.valid_from) formData.append('policy_valid_from', policy.valid_from);
      if (policy.valid_until) formData.append('policy_valid_until', policy.valid_until);
      if (policy.max_decryptions !== undefined && policy.max_decryptions !== null) {
        formData.append('policy_max_decryptions', policy.max_decryptions.toString());
      }
      if (policy.require_registered_device) {
        formData.append('policy_require_registered_device', 'true');
      }
      if (policy.allowed_roles) {
        formData.append('policy_allowed_roles', policy.allowed_roles);
      }
      if (policy.require_multi_party_approval) {
        formData.append('policy_require_multi_party_approval', 'true');
      }
      if (policy.required_approvals !== undefined && policy.required_approvals !== null) {
        formData.append('policy_required_approvals', policy.required_approvals.toString());
      }
      if (policy.eligible_approver_roles) {
        formData.append('policy_eligible_approver_roles', policy.eligible_approver_roles);
      }
      if (policy.allow_emergency_access) {
        formData.append('policy_allow_emergency_access', 'true');
      }
      if (policy.eligible_emergency_roles) {
        formData.append('policy_eligible_emergency_roles', policy.eligible_emergency_roles);
      }
      if (policy.maximum_emergency_duration !== undefined && policy.maximum_emergency_duration !== null) {
        formData.append('policy_maximum_emergency_duration', policy.maximum_emergency_duration.toString());
      }
    }

    return request<EncryptedDocument>('/documents', {
      method: 'POST',
      token,
      body: formData,
    });
  },

  async deleteDocument(token: string, documentId: string): Promise<{ message: string }> {
    return request<{ message: string }>(`/documents/${documentId}`, {
      method: 'DELETE',
      token,
    });
  },

  // Phase 7 Policy Pre-Check (Non-destructive, authoritative backend evaluation)
  async checkDocumentAccess(token: string, documentId: string, deviceId?: string): Promise<DocumentAccessCheckResult> {
    const url = deviceId
      ? `/documents/${documentId}/access-check?device_id=${encodeURIComponent(deviceId)}`
      : `/documents/${documentId}/access-check`;
    return request<DocumentAccessCheckResult>(url, {
      method: 'GET',
      token,
    });
  },

  // Phase 5/7/8 Controlled Decryption
  async decryptDocument(
    token: string,
    documentId: string,
    deviceId?: string,
    approvalRequestId?: string,
    emergencyRequestId?: string
  ): Promise<DecryptionResult> {
    return request<DecryptionResult>(`/documents/${documentId}/decrypt`, {
      method: 'POST',
      token,
      body: JSON.stringify({
        device_id: deviceId || undefined,
        approval_request_id: approvalRequestId || undefined,
        emergency_request_id: emergencyRequestId || undefined,
      }),
    });
  },

  // Phase 8 Multi-Party Decryption Approval Requests
  async createApprovalRequest(
    token: string,
    documentId: string,
    deviceId?: string
  ): Promise<ApprovalRequest> {
    return request<ApprovalRequest>(`/documents/${documentId}/decryption-requests`, {
      method: 'POST',
      token,
      body: JSON.stringify({
        device_id: deviceId || undefined,
      }),
    });
  },

  async getApprovalRequest(token: string, requestId: string): Promise<ApprovalRequest> {
    return request<ApprovalRequest>(`/decryption-requests/${requestId}`, {
      method: 'GET',
      token,
    });
  },

  async listApprovalRequests(token: string, documentId?: string): Promise<ApprovalRequest[]> {
    const url = documentId
      ? `/decryption-requests?document_id=${encodeURIComponent(documentId)}`
      : '/decryption-requests';
    return request<ApprovalRequest[]>(url, {
      method: 'GET',
      token,
    });
  },

  async approveRequest(token: string, requestId: string, reason?: string): Promise<ApprovalRequest> {
    return request<ApprovalRequest>(`/decryption-requests/${requestId}/approve`, {
      method: 'POST',
      token,
      body: JSON.stringify({ reason: reason || undefined }),
    });
  },

  async rejectRequest(token: string, requestId: string, reason: string): Promise<ApprovalRequest> {
    return request<ApprovalRequest>(`/decryption-requests/${requestId}/reject`, {
      method: 'POST',
      token,
      body: JSON.stringify({ reason }),
    });
  },

  async cancelRequest(token: string, requestId: string): Promise<ApprovalRequest> {
    return request<ApprovalRequest>(`/decryption-requests/${requestId}/cancel`, {
      method: 'POST',
      token,
    });
  },

  // Phase 8 Emergency Break-Glass Access
  async createEmergencyRequest(
    token: string,
    documentId: string,
    reason: string,
    requestedDurationMinutes?: number
  ): Promise<EmergencyAccessRequest> {
    return request<EmergencyAccessRequest>(`/documents/${documentId}/emergency-requests`, {
      method: 'POST',
      token,
      body: JSON.stringify({
        reason,
        requested_duration_minutes: requestedDurationMinutes || undefined,
      }),
    });
  },

  async getEmergencyRequest(token: string, requestId: string): Promise<EmergencyAccessRequest> {
    return request<EmergencyAccessRequest>(`/emergency-requests/${requestId}`, {
      method: 'GET',
      token,
    });
  },

  async listEmergencyRequests(token: string, documentId?: string): Promise<EmergencyAccessRequest[]> {
    const url = documentId
      ? `/emergency-requests?document_id=${encodeURIComponent(documentId)}`
      : '/emergency-requests';
    return request<EmergencyAccessRequest[]>(url, {
      method: 'GET',
      token,
    });
  },

  async approveEmergencyRequest(
    token: string,
    requestId: string,
    reason?: string
  ): Promise<EmergencyAccessRequest> {
    return request<EmergencyAccessRequest>(`/emergency-requests/${requestId}/approve`, {
      method: 'POST',
      token,
      body: JSON.stringify({ reason: reason || undefined }),
    });
  },

  async rejectEmergencyRequest(
    token: string,
    requestId: string,
    reason: string
  ): Promise<EmergencyAccessRequest> {
    return request<EmergencyAccessRequest>(`/emergency-requests/${requestId}/reject`, {
      method: 'POST',
      token,
      body: JSON.stringify({ reason }),
    });
  },

  async executeEmergencyDecrypt(
    token: string,
    documentId: string,
    emergencyRequestId: string,
    deviceId?: string
  ): Promise<DecryptionResult> {
    return request<DecryptionResult>(`/documents/${documentId}/emergency-decrypt`, {
      method: 'POST',
      token,
      body: JSON.stringify({
        emergency_request_id: emergencyRequestId,
        device_id: deviceId || undefined,
      }),
    });
  },

  // Phase 7 Access Policy Management
  async getDocumentPolicy(token: string, documentId: string): Promise<AccessPolicy | null> {
    return request<AccessPolicy | null>(`/documents/${documentId}/policy`, {
      method: 'GET',
      token,
    });
  },

  async updateDocumentPolicy(
    token: string,
    documentId: string,
    payload: AccessPolicyUpdatePayload
  ): Promise<AccessPolicy> {
    return request<AccessPolicy>(`/documents/${documentId}/policy`, {
      method: 'PUT',
      token,
      body: JSON.stringify(payload),
    });
  },

  async revokePolicy(token: string, documentId: string): Promise<AccessPolicy> {
    return request<AccessPolicy>(`/documents/${documentId}/policy/revoke`, {
      method: 'POST',
      token,
    });
  },

  async revokeDocument(token: string, documentId: string): Promise<EncryptedDocument> {
    return request<EncryptedDocument>(`/documents/${documentId}/revoke`, {
      method: 'POST',
      token,
    });
  },

  async reactivateDocument(token: string, documentId: string): Promise<EncryptedDocument> {
    return request<EncryptedDocument>(`/documents/${documentId}/reactivate`, {
      method: 'POST',
      token,
    });
  },

  // Recipient Key Management (Phase 4)
  async listRecipients(token: string): Promise<RecipientUserSummary[]> {
    return request<RecipientUserSummary[]>('/recipients', {
      method: 'GET',
      token,
    });
  },

  async provisionRecipientKey(token: string, recipientId: string): Promise<RecipientKeyDetail> {
    return request<RecipientKeyDetail>(`/recipients/${recipientId}/provision-key`, {
      method: 'POST',
      token,
    });
  },

  async revokeRecipientKey(token: string, recipientId: string): Promise<RecipientKeyDetail> {
    return request<RecipientKeyDetail>(`/recipients/${recipientId}/revoke-key`, {
      method: 'POST',
      token,
    });
  },

  // Cryptographic Provenance (Phase 9 - ML-DSA-65)
  async getDocumentProvenance(token: string, documentId: string): Promise<ProvenanceRecord[]> {
    return request<ProvenanceRecord[]>(`/documents/${documentId}/provenance`, {
      method: 'GET',
      token,
    });
  },

  async getProvenanceById(token: string, eventId: string): Promise<ProvenanceRecord> {
    return request<ProvenanceRecord>(`/provenance/${eventId}`, {
      method: 'GET',
      token,
    });
  },

  async verifyProvenanceRecord(token: string, eventId: string): Promise<ProvenanceVerificationResult> {
    return request<ProvenanceVerificationResult>(`/provenance/${eventId}/verify`, {
      method: 'POST',
      token,
    });
  },

  // Phase 10 Tamper-Evident Hash Chain & Permissioned Ledger
  async getChainHead(token: string, chainId?: string): Promise<ProvenanceChainHead> {
    const url = chainId ? `/provenance/chain/head?chain_id=${encodeURIComponent(chainId)}` : '/provenance/chain/head';
    return request<ProvenanceChainHead>(url, {
      method: 'GET',
      token,
    });
  },

  async listChainRecords(token: string, chainId?: string, skip = 0, limit = 50): Promise<ProvenanceRecord[]> {
    const params = new URLSearchParams({ skip: skip.toString(), limit: limit.toString() });
    if (chainId) params.append('chain_id', chainId);
    return request<ProvenanceRecord[]>(`/provenance/chain/records?${params.toString()}`, {
      method: 'GET',
      token,
    });
  },

  async verifyFullChain(token: string, chainId?: string): Promise<ProvenanceChainVerificationResult> {
    return request<ProvenanceChainVerificationResult>('/provenance/chain/verify', {
      method: 'POST',
      token,
      body: JSON.stringify({
        chain_id: chainId || undefined,
      }),
    });
  },

  async verifyLedgerAnchor(token: string, eventId: string): Promise<LedgerAnchorVerificationResult> {
    return request<LedgerAnchorVerificationResult>(`/provenance/${eventId}/ledger-anchor`, {
      method: 'GET',
      token,
    });
  },

  // Phase 11 Secure Document Viewer
  async createViewerSession(
    token: string,
    documentId: string,
    payload?: ViewerSessionCreatePayload,
    deviceId?: string
  ): Promise<ViewerSessionResponse> {
    const headers: Record<string, string> = {};
    if (deviceId) {
      headers['X-Device-ID'] = deviceId;
    }
    return request<ViewerSessionResponse>(`/documents/${documentId}/viewer-session`, {
      method: 'POST',
      token,
      headers,
      body: JSON.stringify(payload || {}),
    });
  },

  async getViewerSession(
    token: string,
    sessionId: string,
    deviceId?: string
  ): Promise<ViewerSessionResponse> {
    const headers: Record<string, string> = {};
    if (deviceId) {
      headers['X-Device-ID'] = deviceId;
    }
    return request<ViewerSessionResponse>(`/viewer-sessions/${sessionId}`, {
      method: 'GET',
      token,
      headers,
    });
  },

  async getViewerContent(
    token: string,
    sessionId: string,
    deviceId?: string
  ): Promise<{ blob: Blob; contentType: string; filename?: string }> {
    const headers: Record<string, string> = {};
    if (deviceId) {
      headers['X-Device-ID'] = deviceId;
    }
    return requestBlob(`/viewer-sessions/${sessionId}/content`, {
      method: 'GET',
      token,
      headers,
    });
  },

  async viewerHeartbeat(
    token: string,
    sessionId: string,
    deviceId?: string
  ): Promise<ViewerHeartbeatResponse> {
    const headers: Record<string, string> = {};
    if (deviceId) {
      headers['X-Device-ID'] = deviceId;
    }
    return request<ViewerHeartbeatResponse>(`/viewer-sessions/${sessionId}/heartbeat`, {
      method: 'POST',
      token,
      headers,
    });
  },

  async closeViewerSession(
    token: string,
    sessionId: string,
    deviceId?: string
  ): Promise<ViewerCloseResponse> {
    const headers: Record<string, string> = {};
    if (deviceId) {
      headers['X-Device-ID'] = deviceId;
    }
    return request<ViewerCloseResponse>(`/viewer-sessions/${sessionId}/close`, {
      method: 'POST',
      token,
      headers,
    });
  },
};

