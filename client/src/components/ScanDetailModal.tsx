import React, { useState } from 'react';
import { X, Copy, Check, ExternalLink, Calendar, ShieldAlert, CheckCircle2, ShieldCheck } from 'lucide-react';
import { ScanReport } from '../types';
import { RiskBadge } from './RiskBadge';
import { RiskGauge } from './RiskGauge';
import { SignalCard } from './SignalCard';

interface ScanDetailModalProps {
  scan: ScanReport | null;
  onClose: () => void;
}

export const ScanDetailModal: React.FC<ScanDetailModalProps> = ({ scan, onClose }) => {
  const [copied, setCopied] = useState(false);
  const [tab, setTab] = useState<'signals' | 'raw'>('signals');

  if (!scan) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(scan, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      id="scan-detail-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-fade-in"
      onClick={onClose}
    >
      <div
        id="scan-detail-modal-card"
        className="relative w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-500">
              <ShieldAlert size={20} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Scan Audit Report
                </h3>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                  {scan.scanId}
                </span>
              </div>
              <p className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-0.5 truncate max-w-md">
                {scan.url}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyJson}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
            >
              {copied ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Modal content body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Top summary row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="md:col-span-1">
              <RiskGauge
                score={scan.risk.score}
                level={scan.risk.level}
                probability={scan.risk.probability}
                confidence={scan.risk.confidence}
                verdictType={scan.risk.verdictType}
                verdictLabel={scan.risk.verdictLabel}
                mode={scan.mode}
              />
            </div>

            <div className="md:col-span-2 space-y-4">
              {/* Target info card */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                  Target Telemetry
                </h4>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Domain:</span>
                    <span className="font-mono font-bold text-slate-900 dark:text-slate-100 truncate block">
                      {scan.domain}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Impersonated Brand:</span>
                    <span className="font-mono font-bold text-rose-500 truncate block">
                      {scan.matchedBrand || 'None (Generic / Baseline)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Analysis Mode:</span>
                    <span className="font-mono font-bold text-cyan-600 dark:text-cyan-400">
                      {scan.mode} MODE
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Timestamp:</span>
                    <span className="font-mono text-slate-700 dark:text-slate-300 flex items-center gap-1">
                      <Calendar size={12} />
                      {new Date(scan.timestamp || scan.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Entropy:</span>
                    <span className="font-mono text-slate-700 dark:text-slate-300">
                      {scan.targetInfo?.entropy ? `${scan.targetInfo.entropy} bits` : 'Standard'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">TLS Certificate:</span>
                    <span className="font-mono text-slate-700 dark:text-slate-300 truncate block">
                      {scan.targetInfo?.tlsIssuer || 'Standard CA'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Reasons list */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                  Detection Rationale ({scan.reasons.length} Findings)
                </h4>
                <ul className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                  {scan.reasons.map((r, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-cyan-500 font-bold">•</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          {/* Tab selector */}
          <div className="flex border-b border-slate-200 dark:border-slate-800 gap-4">
            <button
              onClick={() => setTab('signals')}
              className={`pb-2 text-xs font-semibold uppercase tracking-wider transition-colors border-b-2 ${
                tab === 'signals'
                  ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-600 dark:hover:text-slate-300'
              }`}
            >
              Multi-Signal Breakdown
            </button>
            <button
              onClick={() => setTab('raw')}
              className={`pb-2 text-xs font-semibold uppercase tracking-wider transition-colors border-b-2 ${
                tab === 'raw'
                  ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-600 dark:hover:text-slate-300'
              }`}
            >
              Raw SOC Payload (JSON)
            </button>
          </div>

          {/* Tab Content */}
          {tab === 'signals' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {scan.signalDetails && scan.signalDetails.length > 0 ? (
                scan.signalDetails.map((sig) => (
                  <SignalCard key={sig.key} signal={sig} />
                ))
              ) : (
                Object.entries(scan.signals).map(([key, val]) => {
                  const numVal = typeof val === 'number' ? val : null;
                  const status =
                    numVal === null
                      ? 'UNAVAILABLE'
                      : numVal >= 80
                      ? 'CRITICAL'
                      : numVal >= 55
                      ? 'HIGH_RISK'
                      : numVal >= 25
                      ? 'SUSPICIOUS'
                      : 'SAFE';

                  return (
                    <SignalCard
                      key={key}
                      signal={{
                        name: key.replace(/([A-Z])/g, ' $1').replace(/^./, (s) => s.toUpperCase()),
                        key,
                        score: numVal,
                        status,
                        weight: 0.11,
                        explanation: `Evaluated score: ${numVal !== null ? `${numVal}%` : 'Unavailable'}`,
                      }}
                    />
                  );
                })
              )}
            </div>
          ) : (
            <div className="rounded-xl bg-slate-950 p-4 font-mono text-xs text-cyan-400 overflow-x-auto max-h-96 border border-slate-800">
              <pre>{JSON.stringify(scan, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
