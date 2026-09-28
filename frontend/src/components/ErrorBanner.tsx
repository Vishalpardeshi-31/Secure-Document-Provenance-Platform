import React from 'react';
import { AlertCircle, XCircle } from 'lucide-react';
import { ApiError } from '../types/api';

interface ErrorBannerProps {
  error: ApiError | string | null;
  onDismiss?: () => void;
  className?: string;
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({ error, onDismiss, className = '' }) => {
  if (!error) return null;

  const isApiError = typeof error !== 'string';
  const message = isApiError ? error.message : error;
  const code = isApiError ? error.code : 'ERROR';
  const details = isApiError ? error.details : [];

  return (
    <div
      role="alert"
      className={`border border-rose-900/60 bg-rose-950/30 text-rose-200 px-4 py-3 rounded text-sm ${className}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <AlertCircle className="w-5 h-5 text-rose-400 mt-0.5 shrink-0" />
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-semibold px-1.5 py-0.5 bg-rose-950 border border-rose-800 text-rose-300 rounded">
                {code}
              </span>
              <p className="font-medium text-slate-100">{message}</p>
            </div>

            {details && details.length > 0 && (
              <ul className="mt-2 list-disc list-inside text-xs text-rose-300/90 font-mono space-y-0.5">
                {details.map((detail, idx) => (
                  <li key={idx}>
                    {detail.field ? <span className="font-semibold">{detail.field}: </span> : null}
                    {detail.message}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {onDismiss && (
          <button
            onClick={onDismiss}
            aria-label="Dismiss error"
            className="text-rose-400 hover:text-rose-200 p-0.5"
          >
            <XCircle className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
};
