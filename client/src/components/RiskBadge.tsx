import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, AlertOctagon, HelpCircle, CheckCircle2 } from 'lucide-react';
import { RiskLevel } from '../types';

interface RiskBadgeProps {
  level?: RiskLevel | string;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  className?: string;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  level = 'SAFE',
  size = 'md',
  showIcon = true,
  className = '',
}) => {
  const normLevel = (level || 'SAFE').toUpperCase();

  const config = {
    VERIFIED_SAFE: {
      label: 'VERIFIED SAFE',
      icon: CheckCircle2,
      classes: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/40 font-bold',
      dot: 'bg-emerald-500',
    },
    NO_THREATS_DETECTED: {
      label: 'NO THREATS DETECTED',
      icon: ShieldCheck,
      classes: 'bg-teal-500/10 text-teal-700 dark:text-teal-300 border-teal-500/30',
      dot: 'bg-teal-500',
    },
    SAFE: {
      label: 'SAFE',
      icon: ShieldCheck,
      classes: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
      dot: 'bg-emerald-500',
    },
    SUSPICIOUS: {
      label: 'SUSPICIOUS',
      icon: AlertTriangle,
      classes: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
      dot: 'bg-amber-500',
    },
    HIGH_RISK: {
      label: 'HIGH RISK',
      icon: ShieldAlert,
      classes: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30',
      dot: 'bg-orange-500',
    },
    CRITICAL: {
      label: 'CRITICAL',
      icon: AlertOctagon,
      classes: 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30',
      dot: 'bg-rose-500 animate-pulse',
    },
    UNAVAILABLE: {
      label: 'UNAVAILABLE',
      icon: HelpCircle,
      classes: 'bg-slate-500/10 text-slate-500 dark:text-slate-400 border-slate-500/30',
      dot: 'bg-slate-400',
    },
  }[normLevel] || {
    label: normLevel,
    icon: HelpCircle,
    classes: 'bg-slate-500/10 text-slate-500 dark:text-slate-400 border-slate-500/30',
    dot: 'bg-slate-400',
  };

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-xs font-semibold gap-1',
    md: 'px-2.5 py-1 text-xs font-semibold tracking-wide gap-1.5',
    lg: 'px-3.5 py-1.5 text-sm font-bold tracking-wider gap-2',
  }[size];

  const IconComponent = config.icon;
  const iconSize = size === 'sm' ? 12 : size === 'lg' ? 16 : 14;

  return (
    <span
      id={`risk-badge-${normLevel.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}
      className={`inline-flex items-center rounded-md border font-mono uppercase transition-colors select-none ${config.classes} ${sizeClasses} ${className}`}
    >
      {showIcon && <IconComponent size={iconSize} className="shrink-0" />}
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      <span>{config.label}</span>
    </span>
  );
};
