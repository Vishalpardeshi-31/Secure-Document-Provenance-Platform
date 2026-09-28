import React from 'react';
import { AlertCircle } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-background flex flex-col items-center justify-center p-4 text-center">
      <AlertCircle className="w-10 h-10 text-rose-500 mb-4" />
      <h1 className="text-xl font-bold font-mono text-slate-100">404 - NOT FOUND</h1>
      <p className="mt-2 text-xs font-mono text-slate-400">
        The requested security resource or endpoint does not exist.
      </p>
      <a
        href="/"
        className="mt-6 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-mono transition-colors"
      >
        Return to Platform Shell
      </a>
    </div>
  );
};
