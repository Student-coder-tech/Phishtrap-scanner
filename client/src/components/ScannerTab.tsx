import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Sparkles,
  Zap,
  Globe,
  AlertCircle,
  Copy,
  Check,
  RotateCcw,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
  Info,
  Server,
  Lock,
  Binary
} from 'lucide-react';
import { ScanResult, AnalysisMode } from '../types';
import { api, ApiError } from '../services/api';
import { RiskGauge } from './RiskGauge';
import { SignalCard } from './SignalCard';
import { LoadingState } from './LoadingState';
import { RiskBadge } from './RiskBadge';

const SAMPLE_PRESETS = [
  {
    label: 'Chase Phish (Critical)',
    url: 'https://chase-security-login-portal.xyz/auth/verify',
    type: 'critical',
  },
  {
    label: 'PayPal Phish (Critical)',
    url: 'https://paypal-account-verification-alert.top/signin',
    type: 'critical',
  },
  {
    label: 'Apple ID Typosquat (High)',
    url: 'https://apple-icloud-secure-confirm.info/idmswebauth',
    type: 'high',
  },
  {
    label: 'DocuSign Impersonation (Suspicious)',
    url: 'https://portal-app-secure-doc-gateway.com/view',
    type: 'suspicious',
  },
  {
    label: 'GitHub Official (Safe)',
    url: 'https://github.com/security',
    type: 'safe',
  },
  {
    label: 'Microsoft 365 Official (Safe)',
    url: 'https://microsoft.com',
    type: 'safe',
  },
];

interface ScannerTabProps {
  onScanCompleted: (result: ScanResult) => void;
  lastScanResult: ScanResult | null;
}

export const ScannerTab: React.FC<ScannerTabProps> = ({
  onScanCompleted,
  lastScanResult,
}) => {
  const [inputUrl, setInputUrl] = useState('');
  const [mode, setMode] = useState<AnalysisMode>('DEMO');
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(lastScanResult);
  const [copied, setCopied] = useState(false);

  const handleScan = async (targetDomain?: string) => {
    const domainToScan = (targetDomain || inputUrl).trim();
    if (!domainToScan) {
      setErrorMsg('Please enter a target domain or URL to analyze.');
      return;
    }

    setErrorMsg(null);
    setIsScanning(true);

    try {
      const result = await api.analyzeDomain(domainToScan, mode);
      setCurrentResult(result);
      onScanCompleted(result);
    } catch (err: any) {
      const msg = err instanceof ApiError ? err.message : 'Unable to connect to the analysis service. Please ensure the backend is running.';
      setErrorMsg(msg);
    } finally {
      setIsScanning(false);
    }
  };

  const handlePresetSelect = (presetUrl: string) => {
    setInputUrl(presetUrl);
    setErrorMsg(null);
    handleScan(presetUrl);
  };

  const handleCopyTarget = () => {
    if (!currentResult) return;
    navigator.clipboard.writeText(currentResult.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const verdictType = currentResult?.risk?.verdictType || (currentResult?.risk?.level === 'SAFE' ? 'NO_THREATS_DETECTED' : currentResult?.risk?.level);

  return (
    <div className="space-y-6 animate-fade-in max-w-6xl mx-auto">
      {/* Scanner Input Card */}
      <div
        id="scanner-input-container"
        className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-500">
              <ShieldAlert size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                PHISHTRAP MULTI-SIGNAL SCANNER
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Enter any fully-qualified domain, IP, or URL for deep multi-signal risk scoring and real-time telemetry.
              </p>
            </div>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold text-slate-500 dark:text-slate-400 hidden sm:inline">
              Analysis Mode:
            </span>
            <div className="inline-flex rounded-xl p-1 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
              <button
                id="mode-btn-demo"
                type="button"
                onClick={() => setMode('DEMO')}
                className={`px-3 py-1 text-xs font-mono font-bold rounded-lg transition-all ${
                  mode === 'DEMO'
                    ? 'bg-white dark:bg-slate-900 text-cyan-600 dark:text-cyan-400 shadow-xs'
                    : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                DEMO
              </button>
              <button
                id="mode-btn-live"
                type="button"
                onClick={() => setMode('LIVE')}
                className={`px-3 py-1 text-xs font-mono font-bold rounded-lg transition-all ${
                  mode === 'LIVE'
                    ? 'bg-white dark:bg-slate-900 text-emerald-600 dark:text-emerald-400 shadow-xs'
                    : 'text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                }`}
              >
                LIVE
              </button>
            </div>
          </div>
        </div>

        {/* Input Bar Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="space-y-3"
        >
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                <Globe size={18} />
              </div>
              <input
                id="scanner-target-input"
                type="text"
                value={inputUrl}
                onChange={(e) => {
                  setInputUrl(e.target.value);
                  if (errorMsg) setErrorMsg(null);
                }}
                placeholder="https://examplebank-secure-login.com"
                disabled={isScanning}
                className="w-full pl-10 pr-4 py-3 text-sm font-mono rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 focus:border-cyan-500 transition-all"
              />
            </div>

            <button
              id="run-security-scan-btn"
              type="submit"
              disabled={isScanning || !inputUrl.trim()}
              className="flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-mono font-bold text-xs tracking-wider uppercase transition-all shadow-md shadow-cyan-600/20 cursor-pointer shrink-0"
            >
              {isScanning ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>ANALYZING SIGNALS...</span>
                </>
              ) : (
                <>
                  <Zap size={16} />
                  <span>RUN SECURITY SCAN</span>
                </>
              )}
            </button>
          </div>

          {/* Quick Demo Presets */}
          <div className="pt-2">
            <div className="flex items-center gap-1.5 mb-2 text-[11px] font-mono font-semibold text-slate-400">
              <Sparkles size={13} className="text-cyan-500" />
              <span>Quick Intelligence Presets:</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {SAMPLE_PRESETS.map((preset) => (
                <button
                  key={preset.url}
                  type="button"
                  onClick={() => handlePresetSelect(preset.url)}
                  disabled={isScanning}
                  className={`px-2.5 py-1 rounded-lg text-xs font-mono border transition-all cursor-pointer ${
                    preset.type === 'critical'
                      ? 'bg-rose-500/5 text-rose-600 dark:text-rose-400 border-rose-500/20 hover:bg-rose-500/10'
                      : preset.type === 'high'
                      ? 'bg-orange-500/5 text-orange-600 dark:text-orange-400 border-orange-500/20 hover:bg-orange-500/10'
                      : preset.type === 'suspicious'
                      ? 'bg-amber-500/5 text-amber-600 dark:text-amber-400 border-amber-500/20 hover:bg-amber-500/10'
                      : 'bg-emerald-500/5 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/10'
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
        </form>

        {/* Error Alert */}
        {errorMsg && (
          <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 text-xs flex items-center gap-2.5">
            <AlertCircle size={16} className="shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Live scanning progress animation */}
      {isScanning && <LoadingState domain={inputUrl} />}

      {/* Results Display */}
      {!isScanning && currentResult && (
        <div id="scan-results-container" className="space-y-6">
          {/* Verdict Distinction Banner */}
          {verdictType === 'VERIFIED_SAFE' && (
            <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-800 dark:text-emerald-200 flex items-center gap-3">
              <CheckCircle2 size={20} className="text-emerald-500 shrink-0" />
              <div className="text-xs">
                <span className="font-bold block">Verified Authentic Enterprise Endpoint</span>
                <span>
                  This domain matches the confirmed official infrastructure for{' '}
                  <strong className="text-emerald-600 dark:text-emerald-300">
                    {currentResult.matchedBrand || 'the organization'}
                  </strong>
                  . Zero spoofing indicators found.
                </span>
              </div>
            </div>
          )}

          {verdictType === 'NO_THREATS_DETECTED' && (
            <div className="p-4 rounded-2xl bg-teal-500/10 border border-teal-500/30 text-teal-800 dark:text-teal-200 flex items-center gap-3">
              <ShieldCheck size={20} className="text-teal-500 shrink-0" />
              <div className="text-xs">
                <span className="font-bold block">No Threat Evidence Detected (Low Risk)</span>
                <span>
                  Multi-signal heuristics returned normal baseline values. Note: "No threat evidence detected" denotes lack of malicious signals rather than organizational certification.
                </span>
              </div>
            </div>
          )}

          {/* Top Findings Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Overall Risk Gauge */}
            <div className="lg:col-span-1">
              <RiskGauge
                score={currentResult.risk.score}
                level={currentResult.risk.level}
                probability={currentResult.risk.probability}
                confidence={currentResult.risk.confidence}
                verdictType={currentResult.risk.verdictType}
                verdictLabel={currentResult.risk.verdictLabel}
                mode={currentResult.mode}
              />
            </div>

            {/* Target Information & Findings Details */}
            <div className="lg:col-span-2 space-y-4">
              {/* Target Header Card */}
              <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
                <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100 dark:border-slate-800">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-semibold text-slate-400 uppercase">
                      Target Domain
                    </span>
                    <span className="font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
                      {currentResult.domain}
                    </span>
                  </div>

                  <button
                    onClick={handleCopyTarget}
                    className="flex items-center gap-1 px-2.5 py-1 text-xs font-mono rounded-lg text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 bg-slate-100 dark:bg-slate-800 transition-colors"
                  >
                    {copied ? <Check size={13} className="text-emerald-500" /> : <Copy size={13} />}
                    <span>{copied ? 'Copied' : 'Copy URL'}</span>
                  </button>
                </div>

                {/* Target Metadata Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Protocol:</span>
                    <span className="font-mono font-bold uppercase text-slate-800 dark:text-slate-200 flex items-center gap-1">
                      <Lock size={11} className={currentResult.targetInfo?.protocol === 'https' ? 'text-emerald-500' : 'text-rose-500'} />
                      {currentResult.targetInfo?.protocol?.toUpperCase() || 'HTTPS'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Shannon Entropy:</span>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200">
                      {currentResult.targetInfo?.entropy !== undefined ? `${currentResult.targetInfo.entropy} bits` : 'Standard'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Subdomains Count:</span>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200">
                      {currentResult.targetInfo?.subdomainsCount ?? 0}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">Matched Brand:</span>
                    <span className="font-mono font-bold text-rose-500 truncate block">
                      {currentResult.matchedBrand || 'None (Generic / Baseline)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">DNS Host Resolution:</span>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200 truncate block">
                      {currentResult.targetInfo?.resolvedIps && currentResult.targetInfo.resolvedIps.length > 0
                        ? `${currentResult.targetInfo.resolvedIps[0]}`
                        : currentResult.targetInfo?.dnsResolved
                        ? 'Active DNS A-Record'
                        : 'Simulated / Standard'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block">TLS Certificate:</span>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-200 truncate block">
                      {currentResult.targetInfo?.tlsIssuer || 'Standard CA'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Why Flagged Explanation Card */}
              <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
                <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-2">
                  <AlertCircle size={14} className="text-cyan-500" />
                  Detailed Detection Rationale ({currentResult.reasons.length} Signals Verified)
                </h3>

                <div className="space-y-2">
                  {currentResult.reasons.map((reason, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800/80 text-xs text-slate-700 dark:text-slate-300 flex items-start gap-2.5"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 mt-1.5 shrink-0" />
                      <span>{reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Multi-Signal Breakdown Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Multi-Signal Security Breakdown
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Real measurable telemetry across URL structure, DNS, TLS, Punycode, brand imitation, keywords, and redirects.
                </p>
              </div>

              <span className="text-xs font-mono text-slate-400">
                Scan ID: {currentResult.scanId}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {currentResult.signalDetails && currentResult.signalDetails.length > 0 ? (
                currentResult.signalDetails.map((sig) => (
                  <SignalCard key={sig.key} signal={sig} />
                ))
              ) : (
                Object.entries(currentResult.signals).map(([key, val]) => {
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
                        explanation: `Computed score: ${numVal !== null ? `${numVal}%` : 'Unavailable'}`,
                      }}
                    />
                  );
                })
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
