import React, { useState, useEffect, useCallback } from 'react';
import { AuditEvent } from '../types/auth';
import { adminService } from '../services/admin';
import { useAuth } from '../hooks/useAuth';
import { ErrorBanner } from '../components/ErrorBanner';
import { formatDate } from '../lib/utils';
import { ShieldCheck, RefreshCw, Hash } from 'lucide-react';

export const AuditSection: React.FC = () => {
  const { token } = useAuth();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const fetchEvents = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await adminService.getAuditEvents(token);
      setEvents(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to query security audit trail.');
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h2 className="text-base font-semibold text-slate-100 tracking-wide uppercase font-mono">
            Security Audit Trail
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Immutable, database-persisted security events with SHA-256 hash chaining.
          </p>
        </div>
        <button
          onClick={fetchEvents}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 border border-slate-700 hover:border-slate-500 rounded text-xs font-mono text-slate-300 hover:text-white transition-colors self-start sm:self-auto disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh Audit Trail
        </button>
      </div>

      {error && <ErrorBanner error={error} onDismiss={() => setError(null)} />}

      {/* Selected Event Detail Modal / Panel */}
      {selectedEvent && (
        <div className="bg-surface border border-slate-700 p-5 rounded space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-2">
            <span className="font-semibold text-slate-200 uppercase flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Audit Record: {selectedEvent.event_type}
            </span>
            <button
              onClick={() => setSelectedEvent(null)}
              className="text-slate-400 hover:text-slate-200 text-sm"
            >
              &times;
            </button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
            <div>
              <span className="text-slate-500 block uppercase">Event ID</span>
              <span className="text-slate-200 select-all">{selectedEvent.id}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase">Timestamp</span>
              <span className="text-slate-200">{formatDate(selectedEvent.timestamp)}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase">Actor / User ID</span>
              <span className="text-slate-200 select-all">{selectedEvent.user_id || 'SYSTEM / UNAUTHENTICATED'}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase">Current SHA-256 Hash</span>
              <span className="text-slate-300 break-all select-all">{selectedEvent.event_hash}</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-500 block uppercase">Previous Linked Event Hash</span>
              <span className="text-slate-400 break-all select-all">
                {selectedEvent.previous_event_hash || '0'.repeat(64)}
              </span>
            </div>
            {selectedEvent.metadata_json && Object.keys(selectedEvent.metadata_json).length > 0 && (
              <div className="sm:col-span-2">
                <span className="text-slate-500 block uppercase mb-1">Event Metadata Payload</span>
                <pre className="p-2.5 bg-slate-950 border border-slate-800 rounded text-slate-300 text-[11px] overflow-x-auto">
                  {JSON.stringify(selectedEvent.metadata_json, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Audit Events Table */}
      <div className="bg-surface border border-border rounded overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            Querying audit log from PostgreSQL...
          </div>
        ) : events.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-400">
            No audit events recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/60 border-b border-border text-slate-400 uppercase text-[10px]">
                <tr>
                  <th className="py-2.5 px-4">Event Type</th>
                  <th className="py-2.5 px-4">User ID / Actor</th>
                  <th className="py-2.5 px-4">Chained Hash Link</th>
                  <th className="py-2.5 px-4">Timestamp</th>
                  <th className="py-2.5 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle text-slate-300">
                {events.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-900/30 transition-colors">
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block font-semibold px-2 py-0.5 rounded text-[11px] border ${
                          e.event_type.includes('SUCCESS')
                            ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                            : e.event_type.includes('FAILURE') || e.event_type.includes('DEACTIVATED')
                            ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                            : 'bg-blue-950/40 border-blue-800 text-blue-300'
                        }`}
                      >
                        {e.event_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] truncate max-w-xs">
                      {e.user_id ? e.user_id : <span className="text-slate-500">SYSTEM / AUTH_GATE</span>}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] font-mono flex items-center gap-1.5">
                      <Hash className="w-3 h-3 text-slate-600 shrink-0" />
                      <span className="truncate max-w-[140px] select-all">{e.event_hash}</span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {formatDate(e.timestamp)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(e)}
                        className="px-2 py-1 text-[11px] border border-slate-700 hover:border-slate-500 rounded text-slate-300 hover:text-white transition-colors"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
