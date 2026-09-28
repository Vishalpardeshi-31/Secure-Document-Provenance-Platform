export type UserRole = 'ADMIN' | 'OFFICER' | 'RECIPIENT' | 'AUDITOR';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  department_id?: string | null;
  department_name?: string | null;
  is_active: boolean;
  can_emergency_decrypt?: boolean;
  created_at: string;
  updated_at: string;
}


export interface LoginCredentials {
  username_or_email: string;
  password: string;
}

export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user_id: string;
  username: string;
  email: string;
  role: UserRole;
}

export interface CreateUserPayload {
  username: string;
  email: string;
  password: string;
  role: UserRole;
  department_id?: string | null;
}

export interface UpdateUserPayload {
  role?: UserRole;
  department_id?: string | null;
  is_active?: boolean;
}

export interface Department {
  id: string;
  name: string;
  code: string;
  description?: string | null;
  is_active: boolean;
  user_count: number;
  created_at: string;
  updated_at: string;
}

export interface CreateDepartmentPayload {
  name: string;
  code: string;
  description?: string | null;
}

export interface UpdateDepartmentPayload {
  name?: string;
  code?: string;
  description?: string | null;
  is_active?: boolean;
}

export interface Device {
  id: string;
  user_id: string;
  device_name: string;
  device_fingerprint: string;
  registration_status: string;
  created_at: string;
  last_seen_at?: string | null;
}

export interface RegisterDevicePayload {
  device_name: string;
  device_fingerprint: string;
}

export interface AuditEvent {
  id: string;
  event_type: string;
  user_id?: string | null;
  document_id?: string | null;
  session_id?: string | null;
  timestamp: string;
  event_hash: string;
  previous_event_hash?: string | null;
  metadata_json?: Record<string, unknown> | null;
}

export interface DocumentRecipientSummary {
  recipient_id: string;
  username?: string | null;
  recipient_key_version: number;
  key_algorithm: string;
  status: string;
  granted_at: string;
}

export interface AccessPolicy {
  id: string;
  document_id: string;
  policy_version?: number;
  status?: string;
  enabled: boolean;
  valid_from?: string | null;
  valid_until?: string | null;
  max_decryptions?: number | null;
  consumed_decryptions?: number;
  require_registered_device: boolean;
  require_approval: boolean;
  require_multi_party_approval?: boolean;
  required_approvals?: number;
  eligible_approver_roles?: string | null;
  allow_emergency_access?: boolean;
  eligible_emergency_roles?: string | null;
  eligible_emergency_permission?: string | null;
  emergency_approval_required?: boolean;
  maximum_emergency_duration?: number;
  allowed_roles?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AccessPolicyUpdatePayload {
  enabled?: boolean;
  valid_from?: string | null;
  valid_until?: string | null;
  max_decryptions?: number | null;
  require_registered_device?: boolean;
  require_approval?: boolean;
  require_multi_party_approval?: boolean;
  required_approvals?: number;
  eligible_approver_roles?: string[];
  allow_emergency_access?: boolean;
  eligible_emergency_roles?: string[];
  eligible_emergency_permission?: string;
  emergency_approval_required?: boolean;
  maximum_emergency_duration?: number;
  allowed_roles?: string[];
}

export interface ApprovalRecord {
  id: string;
  approval_request_id: string;
  approver_user_id: string;
  approver_role: string;
  decision: 'APPROVED' | 'REJECTED';
  reason?: string | null;
  created_at: string;
}

export interface ApprovalRequest {
  id: string;
  document_id: string;
  requesting_user_id: string;
  decryption_session_id?: string | null;
  policy_id: string;
  policy_version: number;
  required_approvals: number;
  current_approvals: number;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED';
  created_at: string;
  expires_at: string;
  completed_at?: string | null;
  records?: ApprovalRecord[];
}

export interface EmergencyAccessRequest {
  id: string;
  document_id: string;
  requester_user_id: string;
  requester_role: string;
  reason: string;
  status: 'REQUESTED' | 'AUTHORIZED' | 'USED' | 'EXPIRED' | 'REJECTED' | 'REVOKED';
  requested_duration_minutes?: number;
  created_at: string;
  expires_at: string;
  approved_at?: string | null;
  completed_at?: string | null;
  approver_user_id?: string | null;
  rejection_reason?: string | null;
}

export interface DocumentAccessCheckResult {
  allowed: boolean;
  policy_id: string | null;
  policy_version: number | null;
  reason_code: string | null;
  message: string | null;
  checked_at: string;
  checks: {
    identity_verified: boolean;
    recipient_authorized: boolean;
    role_authorized?: boolean;
    device_verified: boolean;
    approval_verified?: boolean;
    policy_active: boolean;
    time_window_valid: boolean;
    decryption_allowance_available: boolean;
    document_active?: boolean;
  };
}


export interface DecryptionResult {
  session_id: string;
  document_id: string;
  status: string;
  original_filename: string;
  mime_type: string;
  original_size_bytes: number;
  plaintext_sha256: string;
  plaintext_base64: string;
  completed_at: string;
}

export interface EncryptedDocument {
  id: string;
  title: string;
  original_filename: string;
  mime_type: string;
  original_size_bytes: number;
  encrypted_size_bytes: number;
  plaintext_sha256: string;
  ciphertext_sha256: string;
  encryption_algorithm: string;
  classification: string;
  status: string;
  owner_id: string;
  recipients?: DocumentRecipientSummary[];
  recipient_count?: number;
  policy?: AccessPolicy | null;
  created_at: string;
  updated_at: string;
}

export interface RecipientUserSummary {
  id: string;
  username: string;
  email: string;
  is_active: boolean;
  has_active_key: boolean;
  active_key_version?: number | null;
  active_key_id?: string | null;
  key_algorithm?: string | null;
}

export interface RecipientKeyDetail {
  id: string;
  user_id: string;
  key_version: number;
  algorithm: string;
  status: string;
  created_at: string;
  revoked_at?: string | null;
}

export interface ProvenanceRecord {
  event_id: string;
  document_id: string;
  document_version_id: string;
  user_id: string;
  recipient_key_id?: string | null;
  recipient_key_version?: number | null;
  device_id?: string | null;
  decryption_session_id: string;
  policy_id: string;
  policy_version: number;
  access_type: 'NORMAL' | 'MULTI_PARTY_APPROVED' | 'EMERGENCY';
  approval_request_id?: string | null;
  emergency_access_request_id?: string | null;
  document_plaintext_sha256: string;
  document_ciphertext_sha256: string;
  event_timestamp: string;
  protocol_version: string;
  provenance_version: string;
  canonical_record_hash: string;
  signature_algorithm: string;
  signature_key_id: string;
  signature_key_version: number;
  signature: string;
  chain_id?: string | null;
  chain_sequence?: number | null;
  previous_record_hash?: string | null;
  chain_hash?: string | null;
  chain_version?: string | null;
  ledger_transaction_id?: string | null;
  ledger_status?: 'PENDING' | 'CONFIRMED' | 'FAILED' | 'SIGNED_BUT_NOT_ANCHORED' | string | null;
  ledger_record_hash?: string | null;
  ledger_created_at?: string | null;
  created_at: string;
}

export interface ProvenanceVerificationResult {
  event_id: string;
  document_id: string;
  document_version_id: string;
  user_id: string;
  access_type: string;
  event_timestamp: string;
  canonical_record_hash: string;
  recalculated_hash: string;
  hash_valid: boolean;
  signature_algorithm: string;
  signature_key_id: string;
  signature_key_version: number;
  signing_key_status: string;
  signature_valid: boolean;
  verified: boolean;
  verified_at: string;
  message?: string | null;
}

export interface ProvenanceChainHead {
  chain_id: string;
  latest_sequence: number;
  latest_chain_hash: string;
  genesis_hash: string;
  updated_at: string;
}

export interface ProvenanceChainVerificationResult {
  chain_id: string;
  chain_valid: boolean;
  records_checked: number;
  first_invalid_sequence?: number | null;
  failure_type?: string | null;
  failure_reason?: string | null;
  signatures_verified: number;
  ledger_anchors_verified: number;
  genesis_hash: string;
  chain_head_hash: string;
  verified_at: string;
}

export interface LedgerAnchorVerificationResult {
  event_id: string;
  is_anchored: boolean;
  transaction_id?: string | null;
  ledger_transaction_id?: string | null;
  expected_chain_hash?: string;
  ledger_chain_hash?: string | null;
  hash_matched: boolean;
  status: string;
  details?: string | null;
  anchored_at?: string | null;
  chain_id?: string;
  chain_sequence?: number;
  chain_hash?: string;
  ledger_record_hash?: string | null;
  verified_at?: string;
  message?: string | null;
}

export interface ViewerSessionResponse {
  viewer_session_id: string;
  decryption_session_id: string;
  provenance_event_id?: string | null;
  document_id: string;
  document_title?: string | null;
  original_filename: string;
  mime_type: string;
  classification: string;
  user_id: string;
  device_id?: string | null;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED' | 'COMPLETED' | string;
  duration_seconds: number;
  remaining_seconds: number;
  created_at: string;
  expires_at: string;
  last_activity_at?: string | null;
  closed_at?: string | null;
  is_expired: boolean;
}

export interface ViewerHeartbeatResponse {
  viewer_session_id: string;
  status: string;
  last_activity_at: string;
  expires_at: string;
  remaining_seconds: number;
}

export interface ViewerCloseResponse {
  viewer_session_id: string;
  status: string;
  closed_at: string;
  message: string;
}

export interface ViewerSessionCreatePayload {
  duration_seconds?: number;
  device_id?: string;
  approval_request_id?: string;
  emergency_request_id?: string;
}


