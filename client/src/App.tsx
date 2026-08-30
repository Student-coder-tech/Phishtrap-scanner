import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ThemeProvider } from './context/ThemeContext';
import { Sidebar, TabType } from './components/Sidebar';
import { Header } from './components/Header';
import { OverviewTab } from './components/OverviewTab';
import { ScannerTab } from './components/ScannerTab';
import { ReportsTab } from './components/ReportsTab';
import { WatchlistTab } from './components/WatchlistTab';
import { SystemTab } from './components/SystemTab';
import { ScanDetailModal } from './components/ScanDetailModal';
import { api } from './services/api';
import { OverviewMetrics, ScanReport, ScanResult, WatchlistBrand, HealthStatus } from './types';

function PhishtrapApp() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [isOpenMobile, setIsOpenMobile] = useState(false);

  // Core data states
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [watchlist, setWatchlist] = useState<WatchlistBrand[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [lastScanResult, setLastScanResult] = useState<ScanResult | null>(null);
  const [selectedScanDetail, setSelectedScanDetail] = useState<ScanReport | null>(null);

  const [isLoading, setIsLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [overviewData, reportsData, watchlistData, healthData] = await Promise.allSettled([
        api.fetchOverview(),
        api.fetchReports(),
        api.fetchWatchlist(),
        api.checkHealth(),
      ]);

      if (overviewData.status === 'fulfilled') setMetrics(overviewData.value);
      if (reportsData.status === 'fulfilled') setReports(reportsData.value);
      if (watchlistData.status === 'fulfilled') setWatchlist(watchlistData.value);
      if (healthData.status === 'fulfilled') setHealth(healthData.value);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      api.checkHealth().then(setHealth).catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleScanCompleted = (result: ScanResult) => {
    setLastScanResult(result);
    // Refresh background metrics and reports list
    loadData();
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-700 dark:selection:text-cyan-300 transition-colors duration-150">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isOpenMobile={isOpenMobile}
        setIsOpenMobile={setIsOpenMobile}
        reportCount={reports.length}
        watchlistCount={watchlist.filter((w) => w.active).length}
      />

      {/* Main Content Area */}
      <div className="lg:pl-64 flex flex-col min-h-screen">
        <Header
          activeTab={activeTab}
          setIsOpenMobile={setIsOpenMobile}
          health={health}
          onQuickScanClick={() => setActiveTab('scanner')}
        />

        <main className="flex-1 p-4 sm:p-8 max-w-7xl w-full mx-auto">
          <AnimatePresence mode="wait">
            {activeTab === 'overview' && (
              <motion.div
                key="overview"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2 }}
              >
                <OverviewTab
                  metrics={metrics}
                  isLoading={isLoading}
                  onNavigateScanner={() => setActiveTab('scanner')}
                  onNavigateReports={() => setActiveTab('reports')}
                  onSelectScan={(scan) => setSelectedScanDetail(scan)}
                />
              </motion.div>
            )}

            {activeTab === 'scanner' && (
              <motion.div
                key="scanner"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2 }}
              >
                <ScannerTab
                  onScanCompleted={handleScanCompleted}
                  lastScanResult={lastScanResult}
                />
              </motion.div>
            )}

            {activeTab === 'reports' && (
              <motion.div
                key="reports"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2 }}
              >
                <ReportsTab
                  reports={reports}
                  isLoading={isLoading}
                  onRefresh={loadData}
                  onSelectScan={(scan) => setSelectedScanDetail(scan)}
                />
              </motion.div>
            )}

            {activeTab === 'watchlist' && (
              <motion.div
                key="watchlist"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2 }}
              >
                <WatchlistTab
                  watchlist={watchlist}
                  isLoading={isLoading}
                  onRefresh={loadData}
                />
              </motion.div>
            )}

            {activeTab === 'system' && (
              <motion.div
                key="system"
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.2 }}
              >
                <SystemTab health={health} />
              </motion.div>
            )}
          </AnimatePresence>
        </main>
      </div>

      {/* Detail Inspection Modal */}
      {selectedScanDetail && (
        <ScanDetailModal
          scan={selectedScanDetail}
          onClose={() => setSelectedScanDetail(null)}
        />
      )}
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <PhishtrapApp />
    </ThemeProvider>
  );
}
