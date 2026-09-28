import React, { ReactNode } from 'react';
import { Navbar } from '../components/Navbar';
import { useSystemStatus } from '../hooks/useSystemStatus';
import { formatDate } from '../lib/utils';

interface AppLayoutProps {
  children: ReactNode;
  activeTab?: string;
  onTabChange?: (tab: string) => void;
  availableTabs?: { id: string; label: string; roleRequirement?: string }[];
}

export const AppLayout: React.FC<AppLayoutProps> = ({
  children,
  activeTab,
  onTabChange,
  availableTabs = [],
}) => {
  const { health } = useSystemStatus();

  return (
    <div className="min-h-screen flex flex-col bg-background text-slate-200">
      <Navbar />

      {/* Role-based minimal sub-navigation bar (foundation for future role views) */}
      {availableTabs.length > 0 && (
        <div className="border-b border-border-subtle bg-surface/40">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <nav className="flex space-x-1 py-1.5" aria-label="Sections">
              {availableTabs.map((tab) => {
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => onTabChange?.(tab.id)}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
                      isActive
                        ? 'bg-slate-800 text-slate-100 border border-slate-700'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent'
                    }`}
                  >
                    {tab.label}
                    {tab.roleRequirement && (
                      <span className="ml-1.5 text-[9px] font-mono text-slate-500 uppercase">
                        [{tab.roleRequirement}]
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>
        </div>
      )}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* Restrained System Status Footer */}
      <footer className="border-t border-border bg-surface text-slate-500 text-xs py-2.5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2 font-mono text-[11px]">
          <div className="flex items-center gap-3">
            <span>Environment: {health?.environment || 'unknown'}</span>
            <span>&bull;</span>
            <span>Platform Status: {health?.status || 'POLLING'}</span>
            {health?.database && (
              <>
                <span>&bull;</span>
                <span>DB Latency: {health.database.latency_ms}ms</span>
              </>
            )}
          </div>
          <div>
            <span>Timestamp: {health?.timestamp ? formatDate(health.timestamp) : 'N/A'}</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
