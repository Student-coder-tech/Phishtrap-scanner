import React from 'react';
import { Sun, Moon, Laptop, Menu, ShieldAlert, Activity, CheckCircle2 } from 'lucide-react';
import { useTheme, Theme } from '../context/ThemeContext';
import { TabType } from './Sidebar';
import { HealthStatus } from '../types';

interface HeaderProps {
  activeTab: TabType;
  setIsOpenMobile: (open: boolean) => void;
  health: HealthStatus | null;
  onQuickScanClick: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setIsOpenMobile,
  health,
  onQuickScanClick,
}) => {
  const { theme, setTheme } = useTheme();

  const tabTitles: Record<TabType, { title: string; subtitle: string }> = {
    overview: {
      title: 'Security Operations Dashboard',
      subtitle: 'Real-time telemetry, threat metrics, and aggregated phishing risk distribution.',
    },
    scanner: {
      title: 'Multi-Signal Domain Scanner',
      subtitle: 'Inspect domains, extract entropy, check brand typosquatting, and score phishing vectors.',
    },
    reports: {
      title: 'Threat Intelligence Reports',
      subtitle: 'Audit log of historical phishing scans with filterable indicators and exports.',
    },
    watchlist: {
      title: 'Monitored Brand Watchlist',
      subtitle: 'Corporate entities and high-value financial targets safeguarded against impersonation.',
    },
    system: {
      title: 'System Architecture & Engine',
      subtitle: 'FastAPI microservice status, signal weights, and REST API specification.',
    },
  };

  const currentMeta = tabTitles[activeTab];

  return (
    <header
      id="phishtrap-header"
      className="sticky top-0 z-30 flex items-center justify-between px-4 sm:px-8 py-4 bg-white/90 dark:bg-slate-950/90 backdrop-blur-md border-b border-slate-200 dark:border-slate-800/80 transition-colors"
    >
      {/* Left: Mobile trigger & Page Info */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setIsOpenMobile(true)}
          className="p-2 rounded-xl text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 lg:hidden"
          aria-label="Open navigation menu"
        >
          <Menu size={20} />
        </button>

        <div>
          <h1 className="text-base sm:text-lg font-bold text-slate-900 dark:text-slate-100 tracking-tight flex items-center gap-2">
            {currentMeta.title}
          </h1>
          <p className="hidden sm:block text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {currentMeta.subtitle}
          </p>
        </div>
      </div>

      {/* Right: Health pill, Quick Scan, Theme Switcher */}
      <div className="flex items-center gap-2.5 sm:gap-4">
        {/* Backend API Health Status */}
        <div
          id="system-health-indicator"
          className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 text-xs font-mono font-medium"
        >
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>
            {health?.status === 'ok' ? 'API Online' : 'Engine Ready'}
          </span>
          <span className="text-[10px] text-emerald-500/80 uppercase">
            ({health?.pythonEngine === 'connected' ? 'FastAPI' : 'Built-in Engine'})
          </span>
        </div>

        {/* Quick Scan Action */}
        {activeTab !== 'scanner' && (
          <button
            onClick={onQuickScanClick}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold font-mono tracking-wide shadow-xs shadow-cyan-500/20 transition-all cursor-pointer"
          >
            <ShieldAlert size={14} />
            <span className="hidden sm:inline">New Scan</span>
          </button>
        )}

        {/* Theme Switcher */}
        <div className="flex items-center p-1 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
          <button
            id="theme-btn-light"
            onClick={() => setTheme('light')}
            title="Switch to Light Theme"
            aria-label="Light theme"
            className={`p-1.5 rounded-lg transition-all cursor-pointer ${
              theme === 'light'
                ? 'bg-white text-amber-600 shadow-xs border border-amber-500/20 font-bold dark:bg-slate-800 dark:text-amber-400'
                : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            <Sun size={15} />
          </button>

          <button
            id="theme-btn-dark"
            onClick={() => setTheme('dark')}
            title="Switch to Dark Theme"
            aria-label="Dark theme"
            className={`p-1.5 rounded-lg transition-all cursor-pointer ${
              theme === 'dark'
                ? 'bg-white text-cyan-600 shadow-xs border border-cyan-500/20 font-bold dark:bg-slate-800 dark:text-cyan-400 dark:border-cyan-500/30'
                : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            <Moon size={15} />
          </button>

          <button
            id="theme-btn-system"
            onClick={() => setTheme('system')}
            title="Sync with System OS Theme"
            aria-label="System theme"
            className={`p-1.5 rounded-lg transition-all cursor-pointer ${
              theme === 'system'
                ? 'bg-white text-indigo-600 shadow-xs border border-indigo-500/20 font-bold dark:bg-slate-800 dark:text-indigo-400 dark:border-indigo-500/30'
                : 'text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            <Laptop size={15} />
          </button>
        </div>
      </div>
    </header>
  );
};
