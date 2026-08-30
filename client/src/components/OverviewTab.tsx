import React from 'react';
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  BookmarkCheck,
  ArrowRight,
  TrendingUp,
  Activity,
  Zap
} from 'lucide-react';
import { OverviewMetrics, ScanReport } from '../types';
import { StatCard } from './StatCard';
import { ScanTable } from './ScanTable';

interface OverviewTabProps {
  metrics: OverviewMetrics | null;
  isLoading: boolean;
  onNavigateScanner: () => void;
  onNavigateReports: () => void;
  onSelectScan: (scan: ScanReport) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  metrics,
  isLoading,
  onNavigateScanner,
  onNavigateReports,
  onSelectScan,
}) => {
  if (isLoading && !metrics) {
    return (
      <div className="flex items-center justify-center py-24 text-slate-400">
        <div className="w-8 h-8 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin mb-3" />
        <p className="font-mono text-xs ml-3">Loading security telemetry...</p>
      </div>
    );
  }

  const m = metrics || {
    totalScans: 0,
    safe: 0,
    suspicious: 0,
    highRisk: 0,
    critical: 0,
    watchlistMatches: 0,
    safePercentage: 0,
    suspiciousPercentage: 0,
    highRiskPercentage: 0,
    criticalPercentage: 0,
    recentScans: [],
  };

  const threatPercentage = Math.round(((m.highRisk + m.critical) / Math.max(1, m.totalScans)) * 100);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Banner / Quick Action Bar */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950 border border-cyan-500/20 text-white flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative overflow-hidden shadow-lg">
        <div className="relative z-10 space-y-1 max-w-xl">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-widest bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase">
              Threat Intelligence Feed Active
            </span>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-white">
            Multi-Signal Phishing Analysis Platform
          </h2>
          <p className="text-xs text-slate-300">
            Real-time evaluation across 7 behavioral and structural security indicators. Detects typosquatting, credential harvesters, and corporate brand impersonation.
          </p>
        </div>

        <button
          id="overview-launch-scanner-btn"
          onClick={onNavigateScanner}
          className="relative z-10 flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono tracking-wide shadow-md shadow-cyan-500/20 transition-all cursor-pointer shrink-0"
        >
          <Zap size={16} />
          <span>Launch Scanner</span>
          <ArrowRight size={14} />
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          id="stat-total-scans"
          title="Total Scans"
          value={m.totalScans}
          subtext="Total domains analyzed"
          icon={Shield}
          iconColor="text-cyan-500"
          badge={{ text: 'ALL', type: 'info' }}
        />

        <StatCard
          id="stat-safe-domains"
          title="Safe Domains"
          value={m.safe}
          subtext={`${m.safePercentage}% of scanned pool`}
          icon={ShieldCheck}
          iconColor="text-emerald-500"
          badge={{ text: `${m.safePercentage}%`, type: 'safe' }}
        />

        <StatCard
          id="stat-suspicious-domains"
          title="Suspicious"
          value={m.suspicious}
          subtext={`${m.suspiciousPercentage}% flagged anomalous`}
          icon={AlertTriangle}
          iconColor="text-amber-500"
          badge={{ text: `${m.suspiciousPercentage}%`, type: 'warning' }}
        />

        <StatCard
          id="stat-highrisk-domains"
          title="High Risk / Critical"
          value={m.highRisk + m.critical}
          subtext={`${threatPercentage}% dangerous phishing`}
          icon={ShieldAlert}
          iconColor="text-rose-500"
          badge={{ text: `${threatPercentage}%`, type: 'danger' }}
        />

        <StatCard
          id="stat-watchlist-matches"
          title="Watchlist Matches"
          value={m.watchlistMatches}
          subtext="Brand impersonation attempts"
          icon={BookmarkCheck}
          iconColor="text-purple-500"
          badge={{ text: 'ALERTS', type: 'danger' }}
        />
      </div>

      {/* Threat Distribution Visualizer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Card */}
        <div className="lg:col-span-1 p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Activity size={16} className="text-cyan-500" />
                Risk Distribution
              </h3>
              <span className="text-[11px] font-mono text-slate-400">
                {m.totalScans} Total
              </span>
            </div>

            {/* Stacked Bar Distribution */}
            <div className="w-full h-3 rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden flex my-3">
              <div
                style={{ width: `${m.safePercentage}%` }}
                className="bg-emerald-500 h-full transition-all duration-500"
                title={`Safe: ${m.safePercentage}%`}
              />
              <div
                style={{ width: `${m.suspiciousPercentage}%` }}
                className="bg-amber-500 h-full transition-all duration-500"
                title={`Suspicious: ${m.suspiciousPercentage}%`}
              />
              <div
                style={{ width: `${m.highRiskPercentage}%` }}
                className="bg-orange-500 h-full transition-all duration-500"
                title={`High Risk: ${m.highRiskPercentage}%`}
              />
              <div
                style={{ width: `${m.criticalPercentage}%` }}
                className="bg-rose-500 h-full transition-all duration-500"
                title={`Critical: ${m.criticalPercentage}%`}
              />
            </div>

            {/* Legend with percentages */}
            <div className="space-y-2 mt-4 text-xs font-mono">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-600 dark:text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                  Safe (0–29)
                </span>
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  {m.safe} ({m.safePercentage}%)
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-600 dark:text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                  Suspicious (30–59)
                </span>
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  {m.suspicious} ({m.suspiciousPercentage}%)
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-600 dark:text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
                  High Risk (60–79)
                </span>
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  {m.highRisk} ({m.highRiskPercentage}%)
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-slate-600 dark:text-slate-300">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                  Critical (80–100)
                </span>
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  {m.critical} ({m.criticalPercentage}%)
                </span>
              </div>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 text-[11px] text-slate-500 dark:text-slate-400 mt-4">
            Analysis incorporates Shannon character entropy, brand typosquatting distance, credential keywords, and TLS state.
          </div>
        </div>

        {/* Engine Signal Weights Card */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <TrendingUp size={16} className="text-cyan-500" />
                Detection Signal Weighting Matrix
              </h3>
              <span className="text-xs font-mono font-semibold text-cyan-600 dark:text-cyan-400">
                100% Normalized
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
                <div className="flex justify-between text-xs font-semibold mb-1">
                  <span className="text-slate-800 dark:text-slate-200">Brand Impersonation</span>
                  <span className="font-mono text-cyan-600 dark:text-cyan-400">25% Weight</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-cyan-500 h-full w-[25%]" />
                </div>
                <p className="text-[10px] text-slate-400 mt-1">Typosquatting distance & brand keyword embedding</p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
                <div className="flex justify-between text-xs font-semibold mb-1">
                  <span className="text-slate-800 dark:text-slate-200">Domain Reputation & DGA</span>
                  <span className="font-mono text-cyan-600 dark:text-cyan-400">20% Weight</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-cyan-500 h-full w-[20%]" />
                </div>
                <p className="text-[10px] text-slate-400 mt-1">Shannon entropy, high-abuse TLDs, hyphen chaining</p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
                <div className="flex justify-between text-xs font-semibold mb-1">
                  <span className="text-slate-800 dark:text-slate-200">URL Structure & Obfuscation</span>
                  <span className="font-mono text-cyan-600 dark:text-cyan-400">15% Weight</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-cyan-500 h-full w-[15%]" />
                </div>
                <p className="text-[10px] text-slate-400 mt-1">IPv4 authority, excessive length, Punycode / IDN</p>
              </div>

              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
                <div className="flex justify-between text-xs font-semibold mb-1">
                  <span className="text-slate-800 dark:text-slate-200">Keywords, SSL, Redirects & Watchlist</span>
                  <span className="font-mono text-cyan-600 dark:text-cyan-400">40% Weight (10% each)</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div className="bg-cyan-500 h-full w-[40%]" />
                </div>
                <p className="text-[10px] text-slate-400 mt-1">Credential triggers, TLS validation, corporate watchlist match</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
              Recent Threat Scans
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Latest domains processed by PHISHTRAP analysis engine.
            </p>
          </div>

          <button
            onClick={onNavigateReports}
            className="flex items-center gap-1 text-xs font-mono font-semibold text-cyan-600 dark:text-cyan-400 hover:underline cursor-pointer"
          >
            <span>View All Reports</span>
            <ArrowRight size={14} />
          </button>
        </div>

        <ScanTable
          scans={m.recentScans}
          isLoading={isLoading}
          onSelectScan={onSelectScan}
          showFilters={false}
        />
      </div>
    </div>
  );
};
