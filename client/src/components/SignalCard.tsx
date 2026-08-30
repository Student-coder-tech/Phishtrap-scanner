import React, { useState } from 'react';
import {
  Globe,
  Link2,
  ShieldAlert,
  Lock,
  KeyRound,
  ArrowRightLeft,
  BookmarkCheck,
  HelpCircle,
  Binary,
  Server,
  ChevronDown,
  ChevronUp,
  CheckCircle2
} from 'lucide-react';
import { SignalDetail } from '../types';
import { RiskBadge } from './RiskBadge';

interface SignalCardProps {
  signal: SignalDetail;
}

export const SignalCard: React.FC<SignalCardProps> = ({ signal }) => {
  const [showEvidence, setShowEvidence] = useState(false);

  const getIcon = (key: string) => {
    switch (key) {
      case 'domainReputation':
        return <Globe size={18} className="text-cyan-500" />;
      case 'urlStructure':
        return <Link2 size={18} className="text-indigo-500" />;
      case 'brandImpersonation':
        return <ShieldAlert size={18} className="text-rose-500" />;
      case 'keywords':
        return <KeyRound size={18} className="text-amber-500" />;
      case 'punycode':
        return <Binary size={18} className="text-violet-500" />;
      case 'dns':
        return <Server size={18} className="text-blue-500" />;
      case 'ssl':
        return <Lock size={18} className="text-emerald-500" />;
      case 'redirects':
        return <ArrowRightLeft size={18} className="text-purple-500" />;
      case 'watchlist':
        return <BookmarkCheck size={18} className="text-cyan-500" />;
      default:
        return <HelpCircle size={18} className="text-slate-400" />;
    }
  };

  const getProgressColor = (score: number | null) => {
    if (score === null) return 'bg-slate-300 dark:bg-slate-700';
    if (score >= 80) return 'bg-rose-500';
    if (score >= 55) return 'bg-orange-500';
    if (score >= 25) return 'bg-amber-500';
    return 'bg-emerald-500';
  };

  const scoreDisplay = signal.score !== null ? `${signal.score}%` : 'Unavailable';
  const hasEvidence = signal.evidence && Object.keys(signal.evidence).length > 0;

  return (
    <div
      id={`signal-card-${signal.key}`}
      className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition-all"
    >
      <div className="flex items-start justify-between gap-3 mb-2.5">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/80 shrink-0">
            {getIcon(signal.key)}
          </div>
          <div>
            <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              {signal.name}
              <span className="text-[10px] font-mono font-medium text-slate-400 dark:text-slate-500">
                ({Math.round(signal.weight * 100)}% wt)
              </span>
            </h4>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed">
              {signal.explanation}
            </p>
          </div>
        </div>

        <div className="flex flex-col items-end gap-1 shrink-0">
          <span className="text-sm font-bold font-mono text-slate-900 dark:text-slate-100">
            {scoreDisplay}
          </span>
          <RiskBadge level={signal.status} size="sm" showIcon={false} />
        </div>
      </div>

      {/* Progress meter */}
      <div className="w-full bg-slate-100 dark:bg-slate-800 h-2 rounded-full overflow-hidden mt-3">
        <div
          className={`h-full rounded-full transition-all duration-700 ${getProgressColor(signal.score)}`}
          style={{ width: signal.score !== null ? `${Math.max(4, signal.score)}%` : '0%' }}
        />
      </div>

      {/* Optional evidence viewer */}
      {hasEvidence && (
        <div className="mt-3 pt-2.5 border-t border-slate-100 dark:border-slate-800/70">
          <button
            type="button"
            onClick={() => setShowEvidence(!showEvidence)}
            className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
          >
            <span>Telemetry Evidence</span>
            {showEvidence ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>

          {showEvidence && (
            <div className="mt-2 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 text-[11px] font-mono text-slate-600 dark:text-slate-300 overflow-x-auto border border-slate-200/60 dark:border-slate-800/60">
              <pre className="whitespace-pre-wrap leading-tight">
                {JSON.stringify(signal.evidence, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
