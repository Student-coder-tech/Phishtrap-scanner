import React from 'react';
import { motion } from 'motion/react';
import { RiskLevel, VerdictType } from '../types';
import { RiskBadge } from './RiskBadge';

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
  probability: number;
  confidence?: number;
  verdictType?: VerdictType;
  verdictLabel?: string;
  mode?: 'DEMO' | 'LIVE';
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  level,
  probability,
  confidence = 0.95,
  verdictType,
  verdictLabel,
  mode = 'DEMO'
}) => {
  const radius = 68;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getColor = (s: number) => {
    if (s >= 80) return { stroke: '#f43f5e', fill: 'rgba(244, 63, 94, 0.1)', text: 'text-rose-500' };
    if (s >= 60) return { stroke: '#f97316', fill: 'rgba(249, 115, 22, 0.1)', text: 'text-orange-500' };
    if (s >= 30) return { stroke: '#f59e0b', fill: 'rgba(245, 158, 11, 0.1)', text: 'text-amber-500' };
    return { stroke: '#10b981', fill: 'rgba(16, 185, 129, 0.1)', text: 'text-emerald-500' };
  };

  const themeColors = getColor(score);
  const badgeLevel = verdictType === 'VERIFIED_SAFE' ? 'VERIFIED_SAFE' : level;

  return (
    <div
      id="risk-gauge-container"
      className="flex flex-col items-center justify-center p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm relative overflow-hidden"
    >
      {/* Background ambient gradient glow */}
      <div
        className="absolute -top-12 -right-12 w-36 h-36 rounded-full blur-3xl opacity-20 pointer-events-none"
        style={{ backgroundColor: themeColors.stroke }}
      />

      <div className="flex items-center justify-between w-full mb-3">
        <span className="text-xs font-mono font-semibold tracking-wider text-slate-500 dark:text-slate-400 uppercase">
          Threat Classification
        </span>
        <div className="flex items-center gap-1.5">
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-widest border ${
              mode === 'LIVE'
                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                : 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30'
            }`}
          >
            {mode} MODE
          </span>
        </div>
      </div>

      <div className="relative flex items-center justify-center my-2">
        <svg className="w-48 h-48 -rotate-90 transform" viewBox="0 0 160 160">
          {/* Background track circle */}
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="currentColor"
            strokeWidth="12"
            fill="transparent"
            className="text-slate-100 dark:text-slate-800"
          />
          {/* Animated score ring */}
          <motion.circle
            cx="80"
            cy="80"
            r={radius}
            stroke={themeColors.stroke}
            strokeWidth="12"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1, ease: 'easeOut' }}
            strokeLinecap="round"
            fill="transparent"
          />
        </svg>

        {/* Inner stats text */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <motion.span
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5 }}
            className={`text-4xl font-extrabold font-mono tracking-tight ${themeColors.text}`}
          >
            {score}
          </motion.span>
          <span className="text-[11px] font-mono text-slate-400 dark:text-slate-500 uppercase tracking-wider font-semibold">
            / 100 RISK
          </span>
        </div>
      </div>

      {/* Probability and Level status */}
      <div className="w-full mt-3 flex flex-col items-center gap-2">
        <RiskBadge level={badgeLevel} size="lg" />

        {verdictLabel && (
          <span className="text-[11px] font-medium text-slate-500 dark:text-slate-400 text-center line-clamp-1">
            {verdictLabel}
          </span>
        )}

        <div className="grid grid-cols-2 gap-2 w-full mt-2">
          <div className="flex flex-col items-center justify-center px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800 text-xs">
            <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase font-semibold">Probability:</span>
            <span className="font-mono font-bold text-slate-900 dark:text-slate-100 mt-0.5">
              {Math.round(probability * 100)}%
            </span>
          </div>

          <div className="flex flex-col items-center justify-center px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800 text-xs">
            <span className="text-slate-500 dark:text-slate-400 text-[10px] uppercase font-semibold">Confidence:</span>
            <span className="font-mono font-bold text-cyan-600 dark:text-cyan-400 mt-0.5">
              {Math.round((confidence || 0.95) * 100)}%
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
