export interface InvestigationCase {
  id: string;
  case_reference: string;
  title: string;
  description?: string;
  created_by: string;
  document_id?: string;
  document_version_id?: string;
  evidence_filename?: string;
  evidence_sha256?: string;
  evidence_size?: number;
  evidence_mime_type?: string;
  status: 'OPEN' | 'ANALYZING' | 'COMPLETED' | 'FAILED' | 'CLOSED';
  created_at: string;
  updated_at: string;
  completed_at?: string;
  evidence_count: number;
  results_count: number;
}

export interface InvestigationEvidence {
  id: string;
  case_id: string;
  original_filename: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  uploaded_by: string;
  uploaded_at: string;
  evidence_version: number;
  processing_status: string;
}

export interface CustodyEvent {
  id: string;
  case_id: string;
  evidence_id?: string;
  actor_id: string;
  action: string;
  evidence_sha256?: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface TimelineEvent {
  event_name: string;
  timestamp: string;
  actor_or_source: string;
  description: string;
  verification_status?: string;
}

export interface InvestigationResult {
  id: string;
  case_id: string;
  evidence_id: string;
  detection_status: string;
  fingerprint_id?: string;
  provenance_event_id?: string;
  provenance_signature_status?: string;
  chain_verification_status?: string;
  ledger_verification_status?: string;
  confidence_score: number;
  analyzed_at: string;
  analyzer_version: string;
  result_summary: string;
  limitations: string;
  details: Record<string, any>;
}

export interface InvestigationCaseDetail {
  case: InvestigationCase;
  evidence_items: InvestigationEvidence[];
  custody_chain: CustodyEvent[];
  results: InvestigationResult[];
  timeline: TimelineEvent[];
}

export interface InvestigationReport {
  report_id: string;
  report_version: string;
  case_reference: string;
  case_title: string;
  generated_at: string;
  generated_by_user_id: string;
  evidence_metadata: Record<string, any>;
  evidence_sha256: string;
  detection_status: string;
  provenance_verification: Record<string, any>;
  chain_verification: Record<string, any>;
  ledger_verification: Record<string, any>;
  factual_findings: string;
  timeline: TimelineEvent[];
  limitations_disclaimer: string;
  report_sha256: string;
}
