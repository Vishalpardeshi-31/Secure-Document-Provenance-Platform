import React from 'react';
import { Shield, Server, LogOut, User as UserIcon } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useSystemStatus } from '../hooks/useSystemStatus';
import { StatusBadge } from './StatusBadge';

export const Navbar: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const { health } = useSystemStatus();

  return (
    <header className="border-b border-border bg-surface/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-200">
            <Shield className="w-4 h-4 text-blue-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="font-semibold text-sm tracking-tight text-slate-100">
              SECURE DOCUMENT PROVENANCE PLATFORM
            </span>
            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700/60">
              Foundation Phase
            </span>
          </div>
        </div>

        {/* Status and User Bar */}
        <div className="flex items-center gap-4">
          {/* Live system health ping */}
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 border-r border-border pr-4">
            <Server className="w-3.5 h-3.5 text-slate-500" />
            <span>DB:</span>
            <StatusBadge
              status={health?.database.status || 'CHECKING'}
              variant="health"
            />
          </div>

          {isAuthenticated && user ? (
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400">
                  <UserIcon className="w-3.5 h-3.5" />
                </div>
                <div className="flex flex-col text-left">
                  <span className="text-xs font-medium text-slate-200">{user.username}</span>
                  <span className="text-[10px] font-mono text-slate-400">{user.role}</span>
                </div>
              </div>

              <button
                onClick={logout}
                title="Sign out of platform session"
                className="text-slate-400 hover:text-slate-200 hover:bg-slate-800/70 p-1.5 rounded transition-colors text-xs flex items-center gap-1 border border-transparent hover:border-slate-700"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Sign Out</span>
              </button>
            </div>
          ) : (
            <span className="text-xs font-mono text-slate-500">Unauthenticated</span>
          )}
        </div>
      </div>
    </header>
  );
};
