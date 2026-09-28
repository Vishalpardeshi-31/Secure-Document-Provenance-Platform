import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../hooks/useAuth';
import { investigationService } from '../services/investigation';
import {
  InvestigationCase,
  InvestigationCaseDetail,
  InvestigationReport,
} from '../types/investigation';

export const InvestigationSection: React.FC = () => {
  const { token } = useAuth();
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [caseDetail, setCaseDetail] = useState<InvestigationCaseDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Case Modal State
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newDocId, setNewDocId] = useState('');

  // Evidence Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  // Report Modal State
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [showReportModal, setShowReportModal] = useState(false);

  // Load cases
  const loadCases = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const data = await investigationService.listCases(token);
      setCases(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load investigation cases.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  // Load case detail
  const loadCaseDetail = useCallback(async (caseId: string) => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const detail = await investigationService.getCaseDetail(caseId, token);
      setCaseDetail(detail);
      setSelectedCaseId(caseId);
    } catch (err: any) {
      setError(err?.message || 'Failed to load case details.');
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Handle case creation
  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !newTitle.trim()) return;
    setActionLoading(true);
    setError(null);
    try {
      const created = await investigationService.createCase(
        {
          title: newTitle.trim(),
          description: newDescription.trim() || undefined,
          document_id: newDocId.trim() || undefined,
        },
        token
      );
      setShowNewCaseModal(false);
      setNewTitle('');
      setNewDescription('');
      setNewDocId('');
      setSuccessMsg(`Investigation case ${created.case_reference} successfully initialized.`);
      await loadCases();
      await loadCaseDetail(created.id);
    } catch (err: any) {
      setError(err?.message || 'Failed to create investigation case.');
    } finally {
      setActionLoading(false);
    }
  };

  // Handle evidence upload
  const handleUploadEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !selectedCaseId || !selectedFile) return;
    setActionLoading(true);
    setError(null);
    try {
      const ev = await investigationService.uploadEvidence(selectedCaseId, selectedFile, token);
      setSelectedFile(null);
      setSuccessMsg(`Evidence artifact '${ev.original_filename}' deposited and verified (SHA-256: ${ev.sha256.slice(0, 16)}...).`);
      await loadCaseDetail(selectedCaseId);
      await loadCases();
    } catch (err: any) {
      setError(err?.message || 'Failed to deposit evidence.');
    } finally {
      setActionLoading(false);
    }
  };

  // Handle running forensic analysis
  const handleAnalyze = async () => {
    if (!token || !selectedCaseId) return;
    setActionLoading(true);
    setError(null);
    try {
      const res = await investigationService.analyzeEvidence(selectedCaseId, token);
      setSuccessMsg(`Forensic analysis completed with status: ${res.detection_status}`);
      await loadCaseDetail(selectedCaseId);
      await loadCases();
    } catch (err: any) {
      setError(err?.message || 'Forensic analysis failed.');
    } finally {
      setActionLoading(false);
    }
  };

  // Handle export report
  const handleExportReport = async () => {
    if (!token || !selectedCaseId) return;
    setActionLoading(true);
    setError(null);
    try {
      const rep = await investigationService.exportReport(selectedCaseId, token);
      setReport(rep);
      setShowReportModal(true);
    } catch (err: any) {
      setError(err?.message || 'Failed to generate investigation report.');
    } finally {
      setActionLoading(false);
    }
  };

  // Helper status color badge
  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'OPEN':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800">OPEN</span>;
      case 'ANALYZING':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 animate-pulse">ANALYZING</span>;
      case 'COMPLETED':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">COMPLETED</span>;
      case 'FAILED':
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-100 text-rose-800">FAILED</span>;
      default:
        return <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-800">{status}</span>;
    }
  };

  const getDetectionBadge = (status: string) => {
    if (status.includes('PROVENANCE_VALID')) {
      return <span className="px-3 py-1 rounded-md text-xs font-bold bg-emerald-700 text-white">FINGERPRINT DETECTED • PROVENANCE VALID</span>;
    }
    if (status.includes('INVALID') || status.includes('MISMATCH')) {
      return <span className="px-3 py-1 rounded-md text-xs font-bold bg-rose-700 text-white">{status}</span>;
    }
    if (status === 'NO_DETECTABLE_FINGERPRINT') {
      return <span className="px-3 py-1 rounded-md text-xs font-bold bg-amber-600 text-white">NO DETECTABLE FINGERPRINT</span>;
    }
    return <span className="px-3 py-1 rounded-md text-xs font-bold bg-slate-600 text-white">{status}</span>;
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Actions */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-slate-200 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Forensic Leak Investigation & Attribution Workflow</h2>
          <p className="text-xs text-slate-500 mt-1">
            Deposit digital leak evidence, extract recipient-specific 2D-DCT spread-spectrum fingerprints, and cryptographically verify post-quantum ML-DSA-65 provenance chains.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {selectedCaseId ? (
            <button
              onClick={() => {
                setSelectedCaseId(null);
                setCaseDetail(null);
              }}
              className="px-3.5 py-2 text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-md hover:bg-slate-50 transition"
            >
              ← All Cases
            </button>
          ) : (
            <button
              onClick={() => setShowNewCaseModal(true)}
              className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 rounded-md shadow-sm hover:bg-indigo-700 transition"
            >
              + New Investigation Case
            </button>
          )}
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3 text-xs bg-rose-50 border border-rose-200 text-rose-700 rounded-md flex justify-between items-center">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-rose-500 hover:text-rose-700 font-bold ml-2">×</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 text-xs bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-md flex justify-between items-center">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-600 hover:text-emerald-900 font-bold ml-2">×</button>
        </div>
      )}

      {/* VIEW 1: Cases Table */}
      {!selectedCaseId && (
        <div className="bg-white rounded-lg border border-slate-200 shadow-sm overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 bg-slate-50/50 flex justify-between items-center">
            <h3 className="text-sm font-semibold text-slate-800">Active Investigation Cases</h3>
            <span className="text-xs text-slate-500">{cases.length} cases registered</span>
          </div>

          {loading ? (
            <div className="py-12 text-center text-xs text-slate-500">Loading investigation records...</div>
          ) : cases.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-500">
              No investigation cases open. Create a new case above to begin leak analysis.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-600 uppercase font-semibold border-b border-slate-200">
                  <tr>
                    <th className="py-3 px-4">Case Reference</th>
                    <th className="py-3 px-4">Title</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Evidence</th>
                    <th className="py-3 px-4">Created Date</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {cases.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-50/70 transition">
                      <td className="py-3 px-4 font-mono font-bold text-indigo-700">{c.case_reference}</td>
                      <td className="py-3 px-4 font-medium text-slate-900">{c.title}</td>
                      <td className="py-3 px-4">{getStatusBadge(c.status)}</td>
                      <td className="py-3 px-4 text-slate-600">
                        {c.evidence_count} item{c.evidence_count !== 1 ? 's' : ''}
                        {c.evidence_sha256 && (
                          <span className="block font-mono text-[10px] text-slate-400">
                            {c.evidence_sha256.slice(0, 12)}...
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-500">
                        {new Date(c.created_at).toLocaleDateString()} {new Date(c.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => loadCaseDetail(c.id)}
                          className="px-3 py-1 text-xs font-semibold text-indigo-600 bg-indigo-50 hover:bg-indigo-100 rounded transition"
                        >
                          Open Dossier →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: Case Detail Dossier */}
      {selectedCaseId && caseDetail && (
        <div className="space-y-6">
          {/* Dossier Header Card */}
          <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-sm">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-100 pb-4">
              <div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm font-extrabold text-indigo-700 px-2.5 py-1 bg-indigo-50 border border-indigo-200 rounded">
                    {caseDetail.case.case_reference}
                  </span>
                  <h3 className="text-base font-bold text-slate-900">{caseDetail.case.title}</h3>
                  {getStatusBadge(caseDetail.case.status)}
                </div>
                {caseDetail.case.description && (
                  <p className="text-xs text-slate-600 mt-2">{caseDetail.case.description}</p>
                )}
              </div>
              <div className="flex items-center gap-2">
                {caseDetail.results.length > 0 && (
                  <button
                    onClick={handleExportReport}
                    disabled={actionLoading}
                    className="px-3.5 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition shadow-xs"
                  >
                    📄 Export Formal Report
                  </button>
                )}
                {caseDetail.evidence_items.length > 0 && (
                  <button
                    onClick={handleAnalyze}
                    disabled={actionLoading}
                    className="px-4 py-2 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-md transition shadow-xs"
                  >
                    {actionLoading ? 'Analyzing Signal...' : '⚡ Run Forensic Analysis'}
                  </button>
                )}
              </div>
            </div>

            {/* Evidence & Case Metadata Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-4 text-xs">
              <div>
                <span className="text-slate-400 block uppercase text-[10px] font-semibold">Created By</span>
                <span className="font-mono text-slate-800">{caseDetail.case.created_by.slice(0, 8)}...</span>
              </div>
              <div>
                <span className="text-slate-400 block uppercase text-[10px] font-semibold">Associated Document</span>
                <span className="text-slate-800">{caseDetail.case.document_id || 'Unknown / General Leak'}</span>
              </div>
              <div>
                <span className="text-slate-400 block uppercase text-[10px] font-semibold">Evidence Deposited</span>
                <span className="text-slate-800">{caseDetail.evidence_items.length} Artifact(s)</span>
              </div>
              <div>
                <span className="text-slate-400 block uppercase text-[10px] font-semibold">Case Status</span>
                <span className="text-slate-800">{caseDetail.case.status}</span>
              </div>
            </div>
          </div>

          {/* Section: Latest Forensic Detection Result */}
          {caseDetail.results.length > 0 && (() => {
            const latestRes = caseDetail.results[caseDetail.results.length - 1];
            const details = latestRes.details || {};
            const correlation = details.correlation || {};
            const prov = details.provenance || {};
            const chain = details.chain || {};
            const ledger = details.ledger || {};

            return (
              <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-sm space-y-5">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-100 pb-3">
                  <div className="flex items-center gap-3">
                    <h4 className="text-sm font-bold text-slate-900">Forensic Attribution Findings</h4>
                    {getDetectionBadge(latestRes.detection_status)}
                  </div>
                  <div className="text-xs text-slate-500">
                    Confidence: <span className="font-mono font-bold text-slate-800">{(latestRes.confidence_score * 100).toFixed(1)}%</span>
                  </div>
                </div>

                {/* Findings Narrative Card */}
                <div className={`p-4 rounded-md text-xs border ${
                  latestRes.detection_status.includes('PROVENANCE_VALID')
                    ? 'bg-emerald-50/60 border-emerald-200 text-emerald-950'
                    : latestRes.detection_status === 'NO_DETECTABLE_FINGERPRINT'
                    ? 'bg-amber-50/60 border-amber-200 text-amber-950'
                    : 'bg-rose-50/60 border-rose-200 text-rose-950'
                }`}>
                  <p className="font-medium leading-relaxed">{latestRes.result_summary}</p>
                  <p className="mt-2 text-[11px] opacity-80 border-t border-slate-300/40 pt-2 font-mono">
                    {latestRes.limitations}
                  </p>
                </div>

                {/* Cryptographic Verification Proof Grid */}
                {correlation.recipient_id && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                    {/* Recipient / Session Association */}
                    <div className="p-3.5 bg-slate-50 rounded-lg border border-slate-200 text-xs space-y-2">
                      <div className="font-semibold text-slate-800 uppercase text-[10px] tracking-wider border-b border-slate-200 pb-1">
                        Associated Authorized Session
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Recipient Username:</span>
                        <span className="font-semibold text-slate-900">{correlation.recipient_username}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Department:</span>
                        <span className="text-slate-800">{correlation.recipient_department || 'General'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Viewer Session ID:</span>
                        <span className="font-mono text-[10px] text-indigo-700">{correlation.viewer_session_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Decryption Session ID:</span>
                        <span className="font-mono text-[10px] text-slate-600">{correlation.decryption_session_id}</span>
                      </div>
                    </div>

                    {/* Post-Quantum ML-DSA-65 Signature Proof */}
                    <div className="p-3.5 bg-slate-50 rounded-lg border border-slate-200 text-xs space-y-2">
                      <div className="flex justify-between items-center border-b border-slate-200 pb-1">
                        <span className="font-semibold text-slate-800 uppercase text-[10px] tracking-wider">
                          Cryptographic Provenance
                        </span>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          latestRes.provenance_signature_status === 'VALID' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                        }`}>
                          {latestRes.provenance_signature_status}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Signature Algorithm:</span>
                        <span className="font-bold text-slate-800">FIPS 204 (ML-DSA-65)</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Provenance Event ID:</span>
                        <span className="font-mono text-[10px] text-slate-700">{prov.event_id || latestRes.provenance_event_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Canonical Hash Valid:</span>
                        <span className="text-slate-800 font-semibold">{prov.hash_valid ? 'True (SHA-256)' : 'False'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Recomputation Proof:</span>
                        <span className="text-emerald-700 font-medium">Independent Real Signature Check</span>
                      </div>
                    </div>

                    {/* Tamper-Evident Ledger Anchor Proof */}
                    <div className="p-3.5 bg-slate-50 rounded-lg border border-slate-200 text-xs space-y-2">
                      <div className="flex justify-between items-center border-b border-slate-200 pb-1">
                        <span className="font-semibold text-slate-800 uppercase text-[10px] tracking-wider">
                          Ledger Chain & Anchor
                        </span>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          latestRes.chain_verification_status === 'CHAIN_VALID' ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                        }`}>
                          {latestRes.chain_verification_status}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Chain Status:</span>
                        <span className="font-semibold text-slate-800">{latestRes.chain_verification_status} ({chain.records_checked ?? 1} blocks verified)</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Ledger Status:</span>
                        <span className="font-bold text-indigo-800">{latestRes.ledger_verification_status}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Transaction ID:</span>
                        <span className="font-mono text-[10px] text-slate-700">{ledger.transaction_id || 'Pending Outbox'}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">Chain Hash Matched:</span>
                        <span className="text-slate-800 font-semibold">{ledger.hash_matched ? 'Verified' : 'Unchecked'}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })()}

          {/* Section: Evidence Management */}
          <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-sm space-y-4">
            <h4 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-2">
              Deposited Evidence Artifacts
            </h4>

            {caseDetail.evidence_items.length === 0 ? (
              <div className="p-4 bg-slate-50 rounded-md border border-dashed border-slate-300 text-center text-xs text-slate-500">
                No evidence uploaded yet. Select a suspected leak file (PDF, PNG, JPEG, WebP) to upload below.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {caseDetail.evidence_items.map((ev) => (
                  <div key={ev.id} className="p-3.5 bg-slate-50 rounded-md border border-slate-200 text-xs space-y-1.5">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-slate-900">{ev.original_filename}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-200 text-slate-700 rounded">
                        v{ev.evidence_version}
                      </span>
                    </div>
                    <div className="text-slate-500 text-[11px]">
                      {(ev.size_bytes / 1024).toFixed(1)} KB • {ev.mime_type}
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase font-semibold">SHA-256 Hash</span>
                      <span className="font-mono text-[10px] text-slate-800 break-all bg-white px-2 py-1 rounded border border-slate-200 block">
                        {ev.sha256}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Evidence Deposit Form */}
            <form onSubmit={handleUploadEvidence} className="flex flex-col sm:flex-row items-center gap-3 pt-2">
              <input
                type="file"
                accept=".pdf,.png,.jpg,.jpeg,.webp"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                className="text-xs text-slate-600 file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-100 file:text-slate-700 hover:file:bg-slate-200 w-full sm:w-auto"
              />
              <button
                type="submit"
                disabled={!selectedFile || actionLoading}
                className="px-4 py-1.5 text-xs font-semibold text-white bg-slate-800 rounded-md hover:bg-slate-900 disabled:opacity-40 transition whitespace-nowrap"
              >
                {actionLoading ? 'Uploading...' : 'Deposit Evidence'}
              </button>
            </form>
          </div>

          {/* Section: Factual Investigation Timeline */}
          {caseDetail.timeline.length > 0 && (
            <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-sm space-y-4">
              <h4 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-2">
                Factual Chronology & Chain of Provenance Timeline
              </h4>
              <div className="space-y-3">
                {caseDetail.timeline.map((evt, idx) => (
                  <div key={idx} className="flex items-start gap-3 text-xs">
                    <div className="w-2 h-2 rounded-full bg-indigo-600 mt-1.5 shrink-0" />
                    <div className="flex-1 bg-slate-50 p-3 rounded border border-slate-100 space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="font-bold text-slate-900">{evt.event_name}</span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          {new Date(evt.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <p className="text-slate-700">{evt.description}</p>
                      <div className="flex items-center gap-2 pt-1 text-[10px] text-slate-500">
                        <span>Actor / Entity: <strong className="text-slate-700">{evt.actor_or_source}</strong></span>
                        {evt.verification_status && (
                          <span className="px-2 py-0.5 bg-slate-200 text-slate-800 rounded font-mono font-medium">
                            {evt.verification_status}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section: Immutable Evidence Chain of Custody */}
          {caseDetail.custody_chain.length > 0 && (
            <div className="bg-white rounded-lg border border-slate-200 p-5 shadow-sm space-y-3">
              <h4 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-2">
                Chain of Custody Audit Log
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-50 text-slate-500 font-semibold border-b border-slate-200">
                    <tr>
                      <th className="py-2 px-3">Timestamp</th>
                      <th className="py-2 px-3">Action</th>
                      <th className="py-2 px-3">Actor ID</th>
                      <th className="py-2 px-3">Evidence SHA-256</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 text-[11px]">
                    {caseDetail.custody_chain.map((c) => (
                      <tr key={c.id}>
                        <td className="py-2 px-3 text-slate-500 font-mono">
                          {new Date(c.created_at).toLocaleString()}
                        </td>
                        <td className="py-2 px-3 font-semibold text-slate-800">{c.action}</td>
                        <td className="py-2 px-3 font-mono text-slate-600">{c.actor_id.slice(0, 8)}...</td>
                        <td className="py-2 px-3 font-mono text-slate-500">
                          {c.evidence_sha256 ? `${c.evidence_sha256.slice(0, 16)}...` : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* MODAL: New Case */}
      {showNewCaseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-lg max-w-md w-full p-5 space-y-4 shadow-xl">
            <div className="flex justify-between items-center border-b border-slate-200 pb-3">
              <h3 className="text-sm font-bold text-slate-900">Initialize Investigation Case</h3>
              <button onClick={() => setShowNewCaseModal(false)} className="text-slate-400 hover:text-slate-600 font-bold">×</button>
            </div>
            <form onSubmit={handleCreateCase} className="space-y-3 text-xs">
              <div>
                <label className="block font-medium text-slate-700 mb-1">Case Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Dossier Leak Analysis - Q3 Briefing"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 rounded focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-700 mb-1">Context / Source Notes</label>
                <textarea
                  rows={3}
                  placeholder="Details of the intercepted leak or suspected transmission source..."
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 rounded focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block font-medium text-slate-700 mb-1">Suspected Document ID (Optional)</label>
                <input
                  type="text"
                  placeholder="Optional UUID of source document if known"
                  value={newDocId}
                  onChange={(e) => setNewDocId(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 rounded font-mono text-[11px] focus:ring-1 focus:ring-indigo-500 focus:outline-none"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowNewCaseModal(false)}
                  className="px-3 py-1.5 bg-slate-100 text-slate-700 rounded hover:bg-slate-200 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading || !newTitle.trim()}
                  className="px-4 py-1.5 bg-indigo-600 text-white rounded font-semibold hover:bg-indigo-700 disabled:opacity-50"
                >
                  {actionLoading ? 'Creating...' : 'Initialize Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Formal Investigation Report */}
      {showReportModal && report && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-white rounded-lg max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto text-xs">
            <div className="flex justify-between items-start border-b border-slate-200 pb-3">
              <div>
                <span className="font-mono text-indigo-700 font-bold block">{report.report_id}</span>
                <h3 className="text-base font-bold text-slate-900 mt-0.5">{report.case_title}</h3>
                <span className="text-[11px] text-slate-500">Case Reference: {report.case_reference}</span>
              </div>
              <button onClick={() => setShowReportModal(false)} className="text-slate-400 hover:text-slate-600 font-bold text-lg">×</button>
            </div>

            <div className="space-y-3">
              <div className="p-3 bg-slate-50 rounded border border-slate-200 space-y-1">
                <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Report Integrity Signature</div>
                <div className="font-mono text-[11px] text-slate-800 break-all">SHA-256: {report.report_sha256}</div>
                <div className="text-[10px] text-slate-500">Generated: {new Date(report.generated_at).toUTCString()}</div>
              </div>

              <div>
                <h5 className="font-bold text-slate-800 mb-1">Evidence Artifact</h5>
                <div className="font-mono text-[11px] bg-slate-50 p-2 rounded border border-slate-200">
                  SHA-256: {report.evidence_sha256}
                </div>
              </div>

              <div>
                <h5 className="font-bold text-slate-800 mb-1">Factual Findings</h5>
                <p className="p-3 bg-slate-50 rounded border border-slate-200 text-slate-800 leading-relaxed">
                  {report.factual_findings}
                </p>
              </div>

              <div>
                <h5 className="font-bold text-slate-800 mb-1">Cryptographic & Forensic Limitations</h5>
                <pre className="p-3 bg-slate-100 rounded border border-slate-200 text-[10px] text-slate-700 whitespace-pre-wrap font-sans leading-normal">
                  {report.limitations_disclaimer}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-200">
              <button
                onClick={() => window.print()}
                className="px-4 py-1.5 bg-indigo-600 text-white font-semibold rounded hover:bg-indigo-700 transition"
              >
                Print / Save PDF
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
