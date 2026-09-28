import React, { useState, useEffect, useCallback } from 'react';
import { RecipientUserSummary } from '../types/auth';
import { documentService } from '../services/documents';
import { useAuth } from '../hooks/useAuth';
import { ErrorBanner } from '../components/ErrorBanner';
import { KeyRound, ShieldAlert, CheckCircle2, XCircle } from 'lucide-react';

export const RecipientKeysSection: React.FC = () => {
  const { token } = useAuth();
  const [recipients, setRecipients] = useState<RecipientUserSummary[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [processingId, setProcessingId] = useState<string | null>(null);

  const fetchRecipients = useCallback(async () => {
    if (!token) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await documentService.listRecipients(token);
      setRecipients(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retrieve recipient users.');
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchRecipients();
  }, [fetchRecipients]);

  const handleProvisionKey = async (recipientId: string, username: string) => {
    if (!token) return;
    setProcessingId(recipientId);
    setError(null);
    setActionMsg(null);
    try {
      const res = await documentService.provisionRecipientKey(token, recipientId);
      setActionMsg(`Provisioned ML-KEM-768 key pair (v${res.key_version}) for '${username}'. Private key safely protected at rest.`);
      await fetchRecipients();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed to provision key for '${username}'.`);
    } finally {
      setProcessingId(null);
    }
  };

  const handleRevokeKey = async (recipientId: string, username: string) => {
    if (!token) return;
    setProcessingId(recipientId);
    setError(null);
    setActionMsg(null);
    try {
      await documentService.revokeRecipientKey(token, recipientId);
      setActionMsg(`Revoked cryptographic key for '${username}'. User cannot receive new encrypted documents.`);
      await fetchRecipients();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : `Failed to revoke key for '${username}'.`);
    } finally {
      setProcessingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-border pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-primary" />
            Recipient Cryptographic Keys
          </h2>
          <p className="text-sm text-muted-foreground mt-1">
            Manage post-quantum ML-KEM-768 asymmetric key pairs for recipient users.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} />

      {actionMsg && (
        <div className="p-3 bg-primary/10 border border-primary/20 rounded-md text-xs text-primary flex items-center justify-between">
          <span>{actionMsg}</span>
          <button onClick={() => setActionMsg(null)} className="font-semibold underline ml-2">
            Dismiss
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-12 text-muted-foreground text-sm">
          Loading recipient cryptographic perimeter...
        </div>
      ) : recipients.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-border rounded-lg text-muted-foreground text-sm">
          No users with the RECIPIENT role currently exist in the system.
        </div>
      ) : (
        <div className="border border-border rounded-lg overflow-hidden bg-card">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-muted/50 text-xs font-semibold text-muted-foreground uppercase border-b border-border">
                <tr>
                  <th className="px-4 py-3">Recipient</th>
                  <th className="px-4 py-3">Account Status</th>
                  <th className="px-4 py-3">Algorithm</th>
                  <th className="px-4 py-3">Key Version</th>
                  <th className="px-4 py-3">Key Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {recipients.map((r) => (
                  <tr key={r.id} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-3 font-medium text-foreground">
                      <div>{r.username}</div>
                      <div className="text-xs text-muted-foreground">{r.email}</div>
                    </td>
                    <td className="px-4 py-3">
                      {r.is_active ? (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-500 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-red-500 font-medium">
                          <XCircle className="w-3.5 h-3.5" /> Deactivated
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-foreground">
                      {r.key_algorithm || 'ML-KEM-768'}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {r.has_active_key ? (
                        <span className="font-semibold text-foreground">v{r.active_key_version}</span>
                      ) : (
                        <span className="text-muted-foreground italic">None</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {r.has_active_key ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                          Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-500 border border-amber-500/20">
                          Unprovisioned
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleProvisionKey(r.id, r.username)}
                          disabled={processingId === r.id || !r.is_active}
                          className="px-2.5 py-1 text-xs rounded border border-primary/30 text-primary hover:bg-primary/10 transition-colors disabled:opacity-50"
                        >
                          {r.has_active_key ? 'Rotate Key' : 'Provision Key'}
                        </button>

                        {r.has_active_key && (
                          <button
                            onClick={() => handleRevokeKey(r.id, r.username)}
                            disabled={processingId === r.id}
                            className="px-2.5 py-1 text-xs rounded border border-red-500/30 text-red-500 hover:bg-red-500/10 transition-colors disabled:opacity-50"
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="p-4 bg-muted/20 border border-border rounded-lg text-xs text-muted-foreground space-y-1">
        <div className="font-semibold text-foreground flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-primary" />
          Cryptographic Protection Model
        </div>
        <p>
          Each recipient key pair uses <strong>ML-KEM-768</strong> (NIST FIPS 203).
          Private keys are strictly encrypted at rest under a dedicated master key-protection key.
          Private keys are never accessible to administrators or transmitted across any API boundary.
        </p>
      </div>
    </div>
  );
};
