import React, { useState, useEffect } from 'react';
import {
  FileSpreadsheet,
  Download,
  Search,
  Filter,
  RefreshCw,
  FileJson,
  Calendar,
  Layers
} from 'lucide-react';
import { ScanReport } from '../types';
import { api } from '../services/api';
import { ScanTable } from './ScanTable';

interface ReportsTabProps {
  reports: ScanReport[];
  isLoading: boolean;
  onRefresh: () => void;
  onSelectScan: (scan: ScanReport) => void;
}

export const ReportsTab: React.FC<ReportsTabProps> = ({
  reports,
  isLoading,
  onRefresh,
  onSelectScan,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [brandFilter, setBrandFilter] = useState('ALL');

  // Extract unique matched brands for filter dropdown
  const uniqueBrands = Array.from(
    new Set(reports.map((r) => r.matchedBrand).filter((b): b is string => !!b))
  );

  const filteredReports = reports.filter((r) => {
    const q = searchTerm.toLowerCase();
    const matchesSearch =
      searchTerm === '' ||
      r.domain.toLowerCase().includes(q) ||
      r.url.toLowerCase().includes(q) ||
      (r.matchedBrand && r.matchedBrand.toLowerCase().includes(q)) ||
      r.scanId.toLowerCase().includes(q);

    const matchesRisk = riskFilter === 'ALL' || r.risk.level === riskFilter;
    const matchesBrand = brandFilter === 'ALL' || r.matchedBrand === brandFilter;

    return matchesSearch && matchesRisk && matchesBrand;
  });

  const handleExport = (format: 'json' | 'csv') => {
    const url = api.getExportUrl(format);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishtrap-reports-${Date.now()}.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header bar with Export Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div>
          <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <FileSpreadsheet size={18} className="text-cyan-500" />
            Threat Intelligence Scan Reports
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Audit database of processed phishing queries ({filteredReports.length} records).
          </p>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            onClick={onRefresh}
            disabled={isLoading}
            className="p-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
            title="Refresh reports"
          >
            <RefreshCw size={15} className={isLoading ? 'animate-spin' : ''} />
          </button>

          <button
            id="export-json-btn"
            onClick={() => handleExport('json')}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-mono font-bold rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors cursor-pointer"
          >
            <FileJson size={14} className="text-amber-500" />
            <span>Export JSON</span>
          </button>

          <button
            id="export-csv-btn"
            onClick={() => handleExport('csv')}
            className="flex-1 sm:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 text-xs font-mono font-bold rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white shadow-xs shadow-cyan-600/20 transition-colors cursor-pointer"
          >
            <Download size={14} />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-4 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        {/* Search Input */}
        <div className="relative">
          <Search className="absolute left-3 top-2.5 text-slate-400" size={15} />
          <input
            type="text"
            placeholder="Search domain, brand, or scan ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
          />
        </div>

        {/* Risk Level Filter */}
        <div className="flex items-center gap-2">
          <Filter size={15} className="text-slate-400 shrink-0" />
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="w-full px-3 py-2 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="SAFE">Safe (0-29)</option>
            <option value="SUSPICIOUS">Suspicious (30-59)</option>
            <option value="HIGH_RISK">High Risk (60-79)</option>
            <option value="CRITICAL">Critical (80-100)</option>
          </select>
        </div>

        {/* Brand Impersonation Filter */}
        <div className="flex items-center gap-2">
          <Layers size={15} className="text-slate-400 shrink-0" />
          <select
            value={brandFilter}
            onChange={(e) => setBrandFilter(e.target.value)}
            className="w-full px-3 py-2 text-xs font-mono rounded-xl bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
          >
            <option value="ALL">All Target Brands</option>
            {uniqueBrands.map((b) => (
              <option key={b} value={b}>
                {b}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Reports Table */}
      <ScanTable
        scans={filteredReports}
        isLoading={isLoading}
        onSelectScan={onSelectScan}
        showFilters={false}
      />
    </div>
  );
};
