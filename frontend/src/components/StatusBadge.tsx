import React from 'react';
import { cn } from '../lib/utils';

interface StatusBadgeProps {
  status: string;
  variant?: 'health' | 'role' | 'neutral';
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, variant = 'neutral', className }) => {
  let badgeStyles = 'bg-slate-800 text-slate-300 border-slate-700';

  if (variant === 'health') {
    if (status === 'HEALTHY' || status === 'UP') {
      badgeStyles = 'bg-emerald-950/60 text-emerald-400 border-emerald-800/80';
    } else if (status === 'DEGRADED') {
      badgeStyles = 'bg-amber-950/60 text-amber-400 border-amber-800/80';
    } else if (status === 'DOWN') {
      badgeStyles = 'bg-rose-950/60 text-rose-400 border-rose-800/80';
    }
  } else if (variant === 'role') {
    if (status === 'ADMIN') {
      badgeStyles = 'bg-purple-950/60 text-purple-300 border-purple-800/70';
    } else if (status === 'OFFICER') {
      badgeStyles = 'bg-blue-950/60 text-blue-300 border-blue-800/70';
    } else if (status === 'AUDITOR') {
      badgeStyles = 'bg-amber-950/60 text-amber-300 border-amber-800/70';
    } else {
      badgeStyles = 'bg-slate-800 text-slate-300 border-slate-700';
    }
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 text-xs font-mono font-medium rounded border',
        badgeStyles,
        className
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80" />
      {status}
    </span>
  );
};
