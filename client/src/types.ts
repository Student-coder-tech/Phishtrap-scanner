export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';

export type VerdictType = 'VERIFIED_SAFE' | 'NO_THREATS_DETECTED' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';

export type AnalysisMode = 'DEMO' | 'LIVE';

export interface SignalDetail {
  name: string;
  key: string;
  score: number | null;
  status: 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL' | 'UNAVAILABLE';
  weight: number;
  explanation: string;
  evidence?: Record<string, any>;
  details?: Record<string, any>;
}

export interface SignalScores {
  domainReputation: number | null;
  urlStructure: number | null;
  brandImpersonation: number | null;
  ssl: number | null;
  keywords: number | null;
  redirects: number | null;
  watchlist: number | null;
  punycode?: number | null;
  dns?: number | null;
}

export interface TargetInfo {
  url: string;
  domain: string;
  protocol: string;
  hostname: string;
  port?: string | number;
  path?: string;
  tld?: string;
  subdomainsCount?: number;
  entropy?: number;
  ipAddress?: string;
  resolvedIps?: string[];
  mxRecords?: string[];
  nsRecords?: string[];
  country?: string;
  registrar?: string;
  domainAgeDays?: number | null;
  tlsIssuer?: string;
  tlsValidTo?: string;
  isPunycode?: boolean;
  hasHomoglyphs?: boolean;
  dnsResolved?: boolean;
}

export interface RiskAnalysis {
  score: number;
  level: RiskLevel;
  probability: number;
  confidence?: number;
  verdictType?: VerdictType;
  verdictLabel?: string;
}

export interface ScanResult {
  scanId: string;
  domain: string;
  url: string;
  mode: AnalysisMode;
  risk: RiskAnalysis;
  signals: SignalScores;
  signalDetails?: SignalDetail[];
  targetInfo?: TargetInfo;
  matchedBrand: string | null;
  reasons: string[];
  timestamp: string;
  engineVersion?: string;
  engineUsed?: 'fastapi-microservice' | 'nodejs-multisignal' | 'python-standalone';
}

export interface ScanReport extends ScanResult {
  _id?: string;
  createdAt: string;
}

export interface WatchlistBrand {
  _id?: string;
  id?: string;
  name: string;
  domain: string;
  category: 'Banking' | 'E-commerce' | 'Cloud & SaaS' | 'Social Media' | 'Crypto & FinTech' | 'Government' | 'Other';
  active: boolean;
  matchCount?: number;
  createdAt: string;
  updatedAt: string;
}

export interface OverviewMetrics {
  totalScans: number;
  safe: number;
  suspicious: number;
  highRisk: number;
  critical: number;
  watchlistMatches: number;
  safePercentage: number;
  suspiciousPercentage: number;
  highRiskPercentage: number;
  criticalPercentage: number;
  recentScans: ScanReport[];
}

export interface HealthStatus {
  status: 'ok' | 'degraded' | 'error';
  service: string;
  pythonEngine: 'connected' | 'built-in' | 'offline';
  database: 'mongodb' | 'in-memory-persisted';
  timestamp: string;
  version: string;
}

