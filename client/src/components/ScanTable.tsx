import React, { useState } from 'react';
import { Search, Eye, ExternalLink, Filter, ArrowUpDown } from 'lucide-react';
import { ScanReport, RiskLevel } from '../types';
import { RiskBadge } from './RiskBadge';

interface ScanTableProps {
  scans: ScanReport[];
  isLoading?: boolean;
  onSelectScan: (scan: ScanReport) => void;
  showFilters?: boolean;
  onFilterChange?: (filters: { search?: string; risk?: string; brand?: string }) => void;
}

export const ScanTable: React.FC<ScanTableProps> = ({
  scans,
  isLoading = false,
  onSelectScan,
  showFilters = true,
  onFilterChange,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRisk, setSelectedRisk] = useState('ALL');

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = e.target.value;
    setSearchTerm(val);
    if (onFilterChange) {
      onFilterChange({ search: val, risk: selectedRisk });
    }
  };

  const handleRiskChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    setSelectedRisk(val);
    if (onFilterChange) {
      onFilterChange({ search: searchTerm, risk: val });
    }
  };

  // Local filtering if external onFilterChange is not handling it
  const filteredScans = onFilterChange
    ? scans
    : scans.filter((s) => {
        const matchesSearch =
          searchTerm === '' ||
          s.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
          s.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
          (s.matchedBrand && s.matchedBrand.toLowerCase().includes(searchTerm.toLowerCase()));

        const matchesRisk = selectedRisk === 'ALL' || s.risk.level === selectedRisk;
        return matchesSearch && matchesRisk;
      });

  return (
    <div className="w-full flex flex-col rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs overflow-hidden">
      {/* Search & Filter Bar */}
      {showFilters && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/40">
          <div className="relative w-full sm:w-80">
            <Search className="absolute left-3 top-2.5 text-slate-400" size={16} />
            <input
              id="scans-search-input"
              type="text"
              placeholder="Search domain, URL or brand..."
              value={searchTerm}
              onChange={handleSearchChange}
              className="w-full pl-9 pr-4 py-2 text-xs rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex items-center gap-2.5 w-full sm:w-auto">
            <Filter size={15} className="text-slate-400 shrink-0" />
            <select
              id="scans-risk-filter"
              value={selectedRisk}
              onChange={handleRiskChange}
              className="w-full sm:w-auto px-3 py-2 text-xs font-mono rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/20"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="SAFE">Safe (0-29)</option>
              <option value="SUSPICIOUS">Suspicious (30-59)</option>
              <option value="HIGH_RISK">High Risk (60-79)</option>
              <option value="CRITICAL">Critical (80-100)</option>
            </select>
          </div>
        </div>
      )}

      {/* Table Container */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/60 text-slate-500 dark:text-slate-400 font-mono uppercase tracking-wider text-[11px]">
              <th className="py-3 px-4 font-semibold">Target Domain</th>
              <th className="py-3 px-4 font-semibold">Risk Classification</th>
              <th className="py-3 px-4 font-semibold">Probability</th>
              <th className="py-3 px-4 font-semibold">Matched Brand</th>
              <th className="py-3 px-4 font-semibold">Mode</th>
              <th className="py-3 px-4 font-semibold">Timestamp</th>
              <th className="py-3 px-4 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-sans">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-400">
                  <div className="inline-block w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mb-2" />
                  <p className="font-mono text-xs">Loading threat reports...</p>
                </td>
              </tr>
            ) : filteredScans.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-400">
                  <p className="font-medium text-slate-600 dark:text-slate-300">No threat scan reports found.</p>
                  <p className="text-xs text-slate-400 mt-1">Run a new scan to evaluate domains.</p>
                </td>
              </tr>
            ) : (
              filteredScans.map((scan) => (
                <tr
                  key={scan.scanId || scan._id}
                  onClick={() => onSelectScan(scan)}
                  className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 cursor-pointer transition-colors group"
                >
                  {/* Domain */}
                  <td className="py-3.5 px-4">
                    <div className="font-mono font-bold text-slate-900 dark:text-slate-100 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">
                      {scan.domain}
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono truncate max-w-xs mt-0.5">
                      {scan.url}
                    </div>
                  </td>

                  {/* Risk */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <RiskBadge level={scan.risk.level} size="sm" />
                      <span className="font-mono font-bold text-slate-700 dark:text-slate-300">
                        {scan.risk.score}/100
                      </span>
                    </div>
                  </td>

                  {/* Probability */}
                  <td className="py-3.5 px-4 whitespace-nowrap font-mono font-semibold text-slate-800 dark:text-slate-200">
                    {Math.round(scan.risk.probability * 100)}%
                  </td>

                  {/* Matched Brand */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    {scan.matchedBrand ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                        {scan.matchedBrand}
                      </span>
                    ) : (
                      <span className="text-slate-400 font-mono text-[11px]">—</span>
                    )}
                  </td>

                  {/* Mode */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                      {scan.mode}
                    </span>
                  </td>

                  {/* Timestamp */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                    {new Date(scan.timestamp || scan.createdAt).toLocaleDateString()}{' '}
                    {new Date(scan.timestamp || scan.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>

                  {/* Actions */}
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectScan(scan);
                      }}
                      className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-lg text-slate-600 dark:text-slate-300 hover:text-cyan-600 dark:hover:text-cyan-400 hover:bg-cyan-500/10 transition-colors"
                    >
                      <Eye size={14} />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
