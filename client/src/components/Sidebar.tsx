import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  FileSpreadsheet,
  BookmarkCheck,
  Server,
  Activity,
  ChevronRight,
  Sparkles
} from 'lucide-react';

export type TabType = 'overview' | 'scanner' | 'reports' | 'watchlist' | 'system';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  isOpenMobile: boolean;
  setIsOpenMobile: (open: boolean) => void;
  reportCount?: number;
  watchlistCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  isOpenMobile,
  setIsOpenMobile,
  reportCount = 0,
  watchlistCount = 0,
}) => {
  const navItems: Array<{
    id: TabType;
    label: string;
    icon: React.ComponentType<{ size?: number; className?: string }>;
    badge?: number | string;
  }> = [
    { id: 'overview', label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'scanner', label: 'Domain Scanner', icon: ShieldAlert },
    { id: 'reports', label: 'Threat Reports', icon: FileSpreadsheet, badge: reportCount > 0 ? reportCount : undefined },
    { id: 'watchlist', label: 'Brand Watchlist', icon: BookmarkCheck, badge: watchlistCount > 0 ? watchlistCount : undefined },
    { id: 'system', label: 'System & Engine', icon: Server },
  ];

  return (
    <>
      {/* Mobile overlay backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-xs lg:hidden"
          onClick={() => setIsOpenMobile(false)}
        />
      )}

      <aside
        id="phishtrap-sidebar"
        className={`fixed top-0 bottom-0 left-0 z-40 w-64 bg-white text-slate-900 border-r border-slate-200 dark:bg-slate-950 dark:text-slate-100 dark:border-slate-800/80 flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-200 dark:border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-600 dark:text-cyan-400">
              <ShieldAlert size={22} className="relative z-10" />
              <span className="absolute inset-0 rounded-xl bg-cyan-500/20 animate-ping opacity-30" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold tracking-wider font-mono text-sm text-slate-900 dark:text-white">
                  PHISHTRAP
                </span>
                <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-cyan-500/10 dark:bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 font-bold border border-cyan-500/30">
                  v1.0
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">
                Cyber Intelligence Engine
              </p>
            </div>
          </div>
        </div>

        {/* Navigation List */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          <div className="px-3 pb-2 text-[10px] font-mono font-bold tracking-widest text-slate-400 dark:text-slate-500 uppercase">
            Security Intelligence
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                id={`nav-item-${item.id}`}
                onClick={() => {
                  setActiveTab(item.id);
                  setIsOpenMobile(false);
                }}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all group ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-700 border border-cyan-500/30 dark:bg-cyan-500/15 dark:text-cyan-300 dark:border-cyan-500/30 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 dark:text-slate-400 dark:hover:text-slate-200 dark:hover:bg-slate-900/80 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    size={17}
                    className={`transition-colors ${
                      isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400 group-hover:text-slate-700 dark:text-slate-500 dark:group-hover:text-slate-300'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>

                {item.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0.5 rounded-md text-[10px] font-mono font-bold ${
                      isActive
                        ? 'bg-cyan-500/20 text-cyan-800 dark:text-cyan-200'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Bottom Engine Specs Widget */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 bg-slate-50/70 dark:bg-slate-950/40">
          <div className="p-3 rounded-xl bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800/90 space-y-2">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5">
                <Activity size={12} className="text-emerald-500 dark:text-emerald-400 animate-pulse" />
                Signals Active
              </span>
              <span className="font-bold text-slate-800 dark:text-slate-200">7 / 7</span>
            </div>
            <div className="w-full bg-slate-200 dark:bg-slate-800 h-1 rounded-full overflow-hidden">
              <div className="bg-emerald-500 h-full w-full rounded-full" />
            </div>
            <p className="text-[10px] text-slate-500 leading-tight">
              Weighted heuristic analysis & typosquatting detection active.
            </p>
          </div>
        </div>
      </aside>
    </>
  );
};
