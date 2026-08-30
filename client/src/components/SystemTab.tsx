import React from 'react';
import {
  Server,
  Cpu,
  Database,
  Terminal,
  CheckCircle2,
  ExternalLink,
  Code2,
  ShieldCheck,
  Zap,
  Network
} from 'lucide-react';
import { HealthStatus } from '../types';

export const SystemTab: React.FC<{ health: HealthStatus | null }> = ({ health }) => {
  const apis = [
    {
      method: 'POST',
      path: '/api/scanner/analyze',
      desc: 'Performs multi-signal phishing analysis on domain or URL.',
      req: `{ "domain": "chase-secure-login.xyz", "mode": "DEMO" }`,
    },
    {
      method: 'GET',
      path: '/api/overview',
      desc: 'Retrieves global SOC metrics and risk distribution telemetry.',
      req: 'None',
    },
    {
      method: 'GET',
      path: '/api/reports?search=chase&risk=CRITICAL',
      desc: 'Queries stored threat reports with search and filter parameters.',
      req: 'Query parameters',
    },
    {
      method: 'GET',
      path: '/api/watchlist',
      desc: 'Returns all active monitored corporate brand entities.',
      req: 'None',
    },
    {
      method: 'POST',
      path: '/api/watchlist',
      desc: 'Registers a new enterprise brand to the monitored watchlist.',
      req: `{ "name": "Barclays", "domain": "barclays.co.uk", "category": "Banking" }`,
    },
    {
      method: 'GET',
      path: '/api/reports/export/json | /csv',
      desc: 'Downloads complete scan audit log as structured JSON or CSV.',
      req: 'None',
    },
    {
      method: 'GET',
      path: '/api/health',
      desc: 'Returns operational diagnostics for Node and Python services.',
      req: 'None',
    },
  ];

  return (
    <div className="space-y-6 animate-fade-in max-w-5xl mx-auto">
      {/* Architecture Overview */}
      <div className="p-6 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-500">
              <Network size={20} />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                PHISHTRAP System Architecture
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Multi-tier cybersecurity microservice architecture and signal pipeline.
              </p>
            </div>
          </div>

          <span className="px-2.5 py-1 text-xs font-mono font-bold rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
            SYSTEM OPERATIONAL
          </span>
        </div>

        {/* Architecture flow nodes */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-2 font-mono text-xs">
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-1.5">
            <span className="text-[10px] text-cyan-600 dark:text-cyan-400 font-bold uppercase tracking-wider block">
              Tier 1: Frontend
            </span>
            <h4 className="font-bold text-slate-900 dark:text-slate-100">React + Vite</h4>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
              Cybersecurity SOC interface with real-time gauges, telemetry, and dark/light themes.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-1.5">
            <span className="text-[10px] text-indigo-600 dark:text-indigo-400 font-bold uppercase tracking-wider block">
              Tier 2: Backend API
            </span>
            <h4 className="font-bold text-slate-900 dark:text-slate-100">Node + Express</h4>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
              REST router, input sanitization, export generator, and microservice orchestrator.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-1.5">
            <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-bold uppercase tracking-wider block">
              Tier 3: Analysis Engine
            </span>
            <h4 className="font-bold text-slate-900 dark:text-slate-100">Python FastAPI / Heuristics</h4>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
              Shannon entropy, Levenshtein typosquatting, TLD abuse matrix, and weighted scoring.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 space-y-1.5">
            <span className="text-[10px] text-purple-600 dark:text-purple-400 font-bold uppercase tracking-wider block">
              Tier 4: Storage
            </span>
            <h4 className="font-bold text-slate-900 dark:text-slate-100">MongoDB / Transactional Store</h4>
            <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
              Enterprise scan audit logs, target telemetry records, and brand watchlist database.
            </p>
          </div>
        </div>
      </div>

      {/* Diagnostics Card */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Cpu size={16} className="text-cyan-500" />
            Runtime Diagnostics
          </h3>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
              <span className="text-slate-500">Service Status:</span>
              <span className="text-emerald-500 font-bold flex items-center gap-1.5">
                <CheckCircle2 size={13} />
                {health?.status?.toUpperCase() || 'OK'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
              <span className="text-slate-500">Analysis Microservice:</span>
              <span className="text-cyan-600 dark:text-cyan-400 font-bold uppercase">
                {health?.pythonEngine === 'connected' ? 'FastAPI Connected' : 'Built-in Engine Active'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
              <span className="text-slate-500">Database Engine:</span>
              <span className="text-slate-800 dark:text-slate-200 font-bold uppercase">
                {health?.database || 'In-Memory Persisted'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-100 dark:border-slate-800">
              <span className="text-slate-500">Engine Build:</span>
              <span className="text-slate-800 dark:text-slate-200 font-bold">
                PHISHTRAP v1.0.0
              </span>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Terminal size={16} className="text-cyan-500" />
            Standalone Microservice Execution
          </h3>

          <p className="text-xs text-slate-500 dark:text-slate-400">
            Run the Python analysis microservice locally on port 8000:
          </p>

          <pre className="p-3 rounded-xl bg-slate-950 text-cyan-400 text-xs font-mono overflow-x-auto border border-slate-800">
{`# Install Python dependencies
pip install -r server/python/requirements.txt

# Start FastAPI Microservice
uvicorn server.python.main:app --host 127.0.0.1 --port 8000 --reload`}
          </pre>
        </div>
      </div>

      {/* REST API Explorer */}
      <div className="p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <Code2 size={16} className="text-cyan-500" />
            REST API Endpoint Directory
          </h3>
          <span className="text-xs font-mono text-slate-400">
            Prefix: /api
          </span>
        </div>

        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {apis.map((apiItem, i) => (
            <div key={i} className="py-3 first:pt-0 last:pb-0 space-y-1.5">
              <div className="flex items-center gap-2.5">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                    apiItem.method === 'POST'
                      ? 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                      : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                  }`}
                >
                  {apiItem.method}
                </span>
                <span className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100">
                  {apiItem.path}
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 pl-14">
                {apiItem.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
