import React, { useState } from 'react';
import { Lock, Server } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useSystemStatus } from '../hooks/useSystemStatus';
import { ErrorBanner } from '../components/ErrorBanner';
import { StatusBadge } from '../components/StatusBadge';

export const AuthPage: React.FC = () => {
  const { login, isLoading, error, clearError } = useAuth();
  const { health, isLoading: isHealthLoading, refreshStatus } = useSystemStatus();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [clientValidationError, setClientValidationError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setClientValidationError(null);

    if (!username.trim()) {
      setClientValidationError('Username is required.');
      return;
    }
    if (!password) {
      setClientValidationError('Password is required.');
      return;
    }

    await login({
      username_or_email: username.trim(),
      password,
    });
  };

  return (
    <div className="min-h-screen bg-background flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center mb-3">
          <div className="w-10 h-10 rounded bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-300">
            <Lock className="w-5 h-5 text-blue-400" />
          </div>
        </div>

        <h1 className="text-center text-base font-semibold tracking-wider text-slate-100 uppercase font-mono">
          SECURE DOCUMENT PORTAL
        </h1>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-surface py-6 px-6 border border-border sm:rounded sm:px-8 space-y-5">
          {/* Health indicator */}
          <div className="flex items-center justify-between pb-3 border-b border-border text-xs font-mono">
            <span className="text-slate-400 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-slate-500" />
              Backend Connection
            </span>
            <div className="flex items-center gap-2">
              <StatusBadge
                status={isHealthLoading ? 'CHECKING' : (typeof health === 'object' && health?.database?.status) || 'DOWN'}
                variant="health"
              />
              <button
                onClick={refreshStatus}
                type="button"
                className="text-slate-500 hover:text-slate-300 transition-colors"
                title="Refresh system status"
              >
                &orarr;
              </button>
            </div>
          </div>

          {/* Validation & Auth Error Display */}
          <ErrorBanner
            error={clientValidationError || error}
            onDismiss={() => {
              setClientValidationError(null);
              clearError();
            }}
          />

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                htmlFor="username"
                className="block text-xs font-medium text-slate-300 uppercase tracking-wider"
              >
                Username
              </label>
              <div className="mt-1">
                <input
                  id="username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={isLoading}
                  placeholder="Enter username"
                  className="block w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50 font-mono"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="password"
                className="block text-xs font-medium text-slate-300 uppercase tracking-wider"
              >
                Password
              </label>
              <div className="mt-1">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading}
                  placeholder="Enter password"
                  className="block w-full px-3 py-2 text-sm bg-slate-950 border border-slate-700 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 disabled:opacity-50 font-mono"
                />
              </div>
            </div>

            <div className="pt-1">
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex justify-center items-center py-2 px-4 border border-transparent rounded text-xs font-semibold uppercase tracking-wider text-white bg-blue-600 hover:bg-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isLoading ? 'Verifying...' : 'Sign In'}
              </button>
            </div>
          </form>

          {/* Secure Admin Init Reference */}
          <div className="pt-3 border-t border-border-subtle text-[11px] text-slate-400 font-mono">
            <span className="text-slate-500">First-time administrator setup:</span>
            <code className="block mt-1 p-1.5 bg-black/40 rounded border border-slate-800 text-[10px] text-slate-300">
              python -m app.cli.admin_init
            </code>
          </div>
        </div>
      </div>
    </div>
  );
};
