/**
 * PHISHTRAP Central Frontend API Service
 * Manages all communication between React UI and Backend REST APIs.
 */

import { OverviewMetrics, ScanReport, ScanResult, WatchlistBrand, HealthStatus } from '../types';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://phishtrap-scanner-server.vercel.app';

export class ApiError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = 'ApiError';
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  const isJson = res.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await res.json() : null;

  if (!res.ok) {
    const errorMsg = data?.error?.message || data?.detail || `API request failed with status ${res.status}`;
    throw new ApiError(errorMsg, res.status);
  }

  return (data?.data !== undefined ? data.data : data) as T;
}

export const api = {
  /**
   * Health status check
   */
  async checkHealth(): Promise<HealthStatus> {
    try {
      const res = await fetch(`${BASE_URL}/health`);
      return await res.json();
    } catch (err: any) {
      return {
        status: 'error',
        service: 'PHISHTRAP API',
        pythonEngine: 'offline',
        database: 'in-memory-persisted',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
      };
    }
  },

  /**
   * Fetch overview metrics and recent scans
   */
  async fetchOverview(): Promise<OverviewMetrics> {
    const res = await fetch(`${BASE_URL}/overview`);
    return await handleResponse<OverviewMetrics>(res);
  },

  /**
   * Run multi-signal phishing scan on target domain/URL
   */
  async analyzeDomain(domain: string, mode: 'DEMO' | 'LIVE' = 'DEMO'): Promise<ScanResult> {
    const res = await fetch(`${BASE_URL}/scanner/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, mode }),
    });
    return await handleResponse<ScanResult>(res);
  },

  /**
   * Fetch historical scan reports with optional filtering
   */
  async fetchReports(filters?: { search?: string; risk?: string; brand?: string }): Promise<ScanReport[]> {
    const params = new URLSearchParams();
    if (filters?.search) params.append('search', filters.search);
    if (filters?.risk && filters.risk !== 'ALL') params.append('risk', filters.risk);
    if (filters?.brand && filters.brand !== 'ALL') params.append('brand', filters.brand);

    const qs = params.toString();
    const url = `${BASE_URL}/reports${qs ? `?${qs}` : ''}`;
    const res = await fetch(url);
    return await handleResponse<ScanReport[]>(res);
  },

  /**
   * Get active and monitored watchlist brands
   */
  async fetchWatchlist(): Promise<WatchlistBrand[]> {
    const res = await fetch(`${BASE_URL}/watchlist`);
    return await handleResponse<WatchlistBrand[]>(res);
  },

  /**
   * Add a new brand to monitored watchlist
   */
  async addWatchlistBrand(brand: { name: string; domain: string; category?: string }): Promise<WatchlistBrand> {
    const res = await fetch(`${BASE_URL}/watchlist`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(brand),
    });
    return await handleResponse<WatchlistBrand>(res);
  },

  /**
   * Toggle or update a watchlist brand entry
   */
  async toggleWatchlistBrand(id: string, active: boolean): Promise<WatchlistBrand> {
    const res = await fetch(`${BASE_URL}/watchlist/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active }),
    });
    return await handleResponse<WatchlistBrand>(res);
  },

  /**
   * Delete a watchlist brand
   */
  async deleteWatchlistBrand(id: string): Promise<boolean> {
    const res = await fetch(`${BASE_URL}/watchlist/${id}`, {
      method: 'DELETE',
    });
    await handleResponse<{ success: boolean }>(res);
    return true;
  },

  /**
   * URL for direct file export downloads
   */
  getExportUrl(format: 'json' | 'csv'): string {
    return `${BASE_URL}/reports/export/${format}`;
  },
};
