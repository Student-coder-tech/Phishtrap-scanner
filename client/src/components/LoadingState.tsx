import React, { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Shield, CheckCircle2, Loader2 } from 'lucide-react';

const SCAN_STEPS = [
  'Normalizing hostname and extracting authority structure...',
  'Computing Shannon character entropy and DGA indicators...',
  'Checking against active enterprise monitored watchlist...',
  'Evaluating brand impersonation and typosquatting distance...',
  'Validating SSL/TLS certificates and redirect pathways...',
  'Synthesizing multi-signal weights and calculating risk score...',
];

export const LoadingState: React.FC<{ domain: string }> = ({ domain }) => {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < SCAN_STEPS.length - 1 ? prev + 1 : prev));
    }, 450);
    return () => clearInterval(interval);
  }, []);

  return (
    <div
      id="scanning-loading-state"
      className="p-8 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col items-center justify-center text-center max-w-xl mx-auto my-6"
    >
      <div className="relative flex items-center justify-center mb-6">
        <div className="absolute w-24 h-24 rounded-full bg-cyan-500/10 animate-ping" />
        <div className="w-20 h-20 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500">
          <Shield size={36} className="animate-pulse" />
        </div>
      </div>

      <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100">
        Running Security Intelligence Engine
      </h3>
      <p className="text-sm font-mono text-cyan-600 dark:text-cyan-400 mt-1 max-w-md truncate">
        Target: {domain}
      </p>

      {/* Step checklist */}
      <div className="w-full max-w-md mt-6 space-y-2.5 text-left">
        {SCAN_STEPS.map((step, idx) => {
          const isDone = idx < currentStepIndex;
          const isCurrent = idx === currentStepIndex;

          return (
            <motion.div
              key={step}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: idx <= currentStepIndex ? 1 : 0.4, x: 0 }}
              className={`flex items-center gap-2.5 text-xs font-mono p-2 rounded-lg transition-colors ${
                isCurrent
                  ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 font-semibold border border-cyan-500/20'
                  : isDone
                  ? 'text-slate-600 dark:text-slate-300'
                  : 'text-slate-400 dark:text-slate-600'
              }`}
            >
              {isDone ? (
                <CheckCircle2 size={14} className="text-emerald-500 shrink-0" />
              ) : isCurrent ? (
                <Loader2 size={14} className="animate-spin text-cyan-500 shrink-0" />
              ) : (
                <div className="w-3.5 h-3.5 rounded-full border border-slate-300 dark:border-slate-700 shrink-0" />
              )}
              <span className="truncate">{step}</span>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
};
