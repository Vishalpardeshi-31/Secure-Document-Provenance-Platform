import React from 'react';
import { useAuth } from '../hooks/useAuth';
import { useSystemStatus } from '../hooks/useSystemStatus';
import { StatusBadge } from '../components/StatusBadge';
import { formatDate } from '../lib/utils';
import { CheckCircle2, Clock, ShieldCheck, Database, KeyRound } from 'lucide-react';

export const SessionSection: React.FC = () => {
  const { user } = useAuth();
  const { health } = useSystemStatus();

  if (!user) return null;

  return (
    <div className="space-y-6">
      <div className="pb-4 border-b border-border">
        <h2 className="text-base font-semibold text-slate-100 tracking-wide uppercase font-mono">
          Active Authenticated Session
        </h2>
        <p className="text-xs text-slate-400 mt-0.5">
          Backend-verified identity perimeter and cryptographic session characteristics.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Authenticated Identity Card */}
        <div className="bg-surface border border-border rounded p-5 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-border-subtle pb-3">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-blue-400" />
              <h3 className="font-semibold text-slate-100 uppercase">
                Verified Identity
              </h3>
            </div>
            <StatusBadge status={user.role} variant="role" />
          </div>

          <div className="space-y-3 text-[11px]">
            <div>
              <span className="text-slate-500 block uppercase text-[10px]">User ID</span>
              <span className="text-slate-200 select-all">{user.id}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase text-[10px]">Username</span>
              <span className="text-slate-200 font-semibold">{user.username}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase text-[10px]">Email Address</span>
              <span className="text-slate-200">{user.email}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase text-[10px]">Department</span>
              <span className="text-slate-200">{user.department_name || 'Unassigned'}</span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase text-[10px]">Account Status</span>
              <span className={user.is_active ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
                {user.is_active ? 'ACTIVE & AUTHORIZED' : 'DEACTIVATED'}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block uppercase text-[10px]">Account Created</span>
              <span className="text-slate-400">{formatDate(user.created_at)}</span>
            </div>
          </div>
        </div>

        {/* Security Perimeter Card */}
        <div className="bg-surface border border-border rounded p-5 space-y-4 text-xs font-mono">
          <div className="flex items-center justify-between border-b border-border-subtle pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h3 className="font-semibold text-slate-100 uppercase">
                Security Perimeter
              </h3>
            </div>
            <span className="text-[10px] text-slate-400">JWT BEARER (JTI TRACKED)</span>
          </div>

          <div className="space-y-3 text-[11px]">
            <div className="flex items-start gap-2.5 text-slate-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">Argon2id Hash Enforced</span>
                <span className="text-slate-400 font-sans text-[11px]">Password verified with 64 MiB RAM cost, 3 iterations, and 4 lanes.</span>
              </div>
            </div>

            <div className="flex items-start gap-2.5 text-slate-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">Stateless Token with Revocation</span>
                <span className="text-slate-400 font-sans text-[11px]">Server tracks individual JTI identifiers upon logout to prevent replay attacks.</span>
              </div>
            </div>

            <div className="flex items-start gap-2.5 text-slate-300">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">Zero Plaintext / Hash Leakage</span>
                <span className="text-slate-400 font-sans text-[11px]">Password hashes are never returned across any API boundary.</span>
              </div>
            </div>

            <div className="flex items-start gap-2.5 text-slate-300">
              <Clock className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">Session Expiration</span>
                <span className="text-slate-400 font-sans text-[11px]">Tokens expire after 60 minutes and require re-authentication.</span>
              </div>
            </div>

            <div className="flex items-start gap-2.5 text-slate-300">
              <Database className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">PostgreSQL Live Latency</span>
                <span className="text-slate-400 font-sans text-[11px]">{health?.database.latency_ms ?? 0} ms response time.</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
