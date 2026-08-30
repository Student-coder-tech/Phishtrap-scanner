import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  id: string;
  title: string;
  value: number | string;
  subtext?: string;
  icon: LucideIcon;
  iconColor?: string;
  badge?: {
    text: string;
    type: 'safe' | 'warning' | 'danger' | 'info';
  };
}

export const StatCard: React.FC<StatCardProps> = ({
  id,
  title,
  value,
  subtext,
  icon: Icon,
  iconColor = 'text-cyan-500',
  badge,
}) => {
  const badgeClasses = {
    safe: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20',
    warning: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20',
    danger: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20',
    info: 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/20',
  }[badge?.type || 'info'];

  return (
    <div
      id={id}
      className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition-all flex flex-col justify-between"
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
          {title}
        </span>
        <div className={`p-2.5 rounded-xl bg-slate-100 dark:bg-slate-800/80 ${iconColor}`}>
          <Icon size={18} />
        </div>
      </div>

      <div className="flex items-baseline justify-between gap-2">
        <div className="text-3xl font-extrabold font-mono text-slate-900 dark:text-slate-100 tracking-tight">
          {value}
        </div>
        {badge && (
          <span className={`px-2 py-0.5 text-xs font-mono font-bold rounded-md border ${badgeClasses}`}>
            {badge.text}
          </span>
        )}
      </div>

      {subtext && (
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-2 font-medium">
          {subtext}
        </p>
      )}
    </div>
  );
};
