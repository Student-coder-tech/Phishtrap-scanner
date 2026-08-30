/**
 * PHISHTRAP Database & Storage Layer
 * Production-ready persistent storage with native MongoDB support and in-memory transactional fallback.
 */

import { MongoClient, Db, Collection } from 'mongodb';
import { WatchlistRecord } from './engine';

export interface StoredScan {
  _id: string;
  scanId: string;
  domain: string;
  url: string;
  mode: 'DEMO' | 'LIVE';
  risk: {
    score: number;
    level: 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';
    probability: number;
    confidence?: number;
    verdictType?: 'VERIFIED_SAFE' | 'NO_THREATS_DETECTED' | 'SUSPICIOUS' | 'HIGH_RISK' | 'CRITICAL';
    verdictLabel?: string;
  };
  signals: {
    domainReputation: number | null;
    urlStructure: number | null;
    brandImpersonation: number | null;
    ssl: number | null;
    keywords: number | null;
    redirects: number | null;
    watchlist: number | null;
    punycode?: number | null;
    dns?: number | null;
  };
  signalDetails?: any[];
  targetInfo?: any;
  matchedBrand: string | null;
  reasons: string[];
  timestamp: string;
  createdAt: string;
  engineUsed?: string;
}

export interface StoredWatchlist extends WatchlistRecord {
  _id: string;
  id: string;
  createdAt: string;
  updatedAt: string;
}

// Pre-seeded realistic cybersecurity watchlist brands
const INITIAL_WATCHLIST: StoredWatchlist[] = [
  {
    _id: 'wl_001',
    id: 'wl_001',
    name: 'Chase Bank',
    domain: 'chase.com',
    category: 'Banking',
    active: true,
    createdAt: new Date(Date.now() - 30 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 30 * 86400000).toISOString(),
  },
  {
    _id: 'wl_002',
    id: 'wl_002',
    name: 'PayPal',
    domain: 'paypal.com',
    category: 'Banking',
    active: true,
    createdAt: new Date(Date.now() - 25 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 25 * 86400000).toISOString(),
  },
  {
    _id: 'wl_003',
    id: 'wl_003',
    name: 'Apple iCloud',
    domain: 'apple.com',
    category: 'Cloud & SaaS',
    active: true,
    createdAt: new Date(Date.now() - 20 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 20 * 86400000).toISOString(),
  },
  {
    _id: 'wl_004',
    id: 'wl_004',
    name: 'Microsoft 365',
    domain: 'microsoft.com',
    category: 'Cloud & SaaS',
    active: true,
    createdAt: new Date(Date.now() - 18 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 18 * 86400000).toISOString(),
  },
  {
    _id: 'wl_005',
    id: 'wl_005',
    name: 'Coinbase',
    domain: 'coinbase.com',
    category: 'Crypto & FinTech',
    active: true,
    createdAt: new Date(Date.now() - 15 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 15 * 86400000).toISOString(),
  },
  {
    _id: 'wl_006',
    id: 'wl_006',
    name: 'Amazon',
    domain: 'amazon.com',
    category: 'E-commerce',
    active: true,
    createdAt: new Date(Date.now() - 12 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 12 * 86400000).toISOString(),
  },
  {
    _id: 'wl_007',
    id: 'wl_007',
    name: 'DocuSign',
    domain: 'docusign.com',
    category: 'Cloud & SaaS',
    active: true,
    createdAt: new Date(Date.now() - 10 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 10 * 86400000).toISOString(),
  },
  {
    _id: 'wl_008',
    id: 'wl_008',
    name: 'Internal Revenue Service (IRS)',
    domain: 'irs.gov',
    category: 'Government',
    active: false,
    createdAt: new Date(Date.now() - 8 * 86400000).toISOString(),
    updatedAt: new Date(Date.now() - 8 * 86400000).toISOString(),
  }
];

// Pre-seeded realistic scan reports
const INITIAL_SCANS: StoredScan[] = [
  {
    _id: 'scn_101',
    scanId: 'scn_101',
    domain: 'chase-security-login-portal.xyz',
    url: 'https://chase-security-login-portal.xyz/auth/verify',
    mode: 'DEMO',
    risk: {
      score: 94,
      level: 'CRITICAL',
      probability: 0.94,
      confidence: 0.95,
      verdictType: 'CRITICAL',
      verdictLabel: 'Critical Phishing Threat',
    },
    signals: { domainReputation: 95, urlStructure: 85, brandImpersonation: 100, ssl: 70, keywords: 95, redirects: 70, watchlist: 100, punycode: 0, dns: 90 },
    matchedBrand: 'Chase Bank',
    reasons: [
      'Domain displays unauthorized impersonation of Chase Bank.',
      'Critical concentration of phishing trigger keywords: login, security, verify',
      'Uses high-abuse top-level domain (.xyz)',
      'Excessive hyphen chaining (3 hyphens)',
      'Matched critical monitored watchlist target: Chase Bank (Banking)'
    ],
    timestamp: new Date(Date.now() - 12 * 60000).toISOString(),
    createdAt: new Date(Date.now() - 12 * 60000).toISOString(),
    engineUsed: 'nodejs-multisignal',
  },
  {
    _id: 'scn_102',
    scanId: 'scn_102',
    domain: 'paypal-account-verification-alert.top',
    url: 'https://paypal-account-verification-alert.top/signin',
    mode: 'DEMO',
    risk: {
      score: 88,
      level: 'CRITICAL',
      probability: 0.88,
      confidence: 0.95,
      verdictType: 'CRITICAL',
      verdictLabel: 'Critical Phishing Threat',
    },
    signals: { domainReputation: 90, urlStructure: 80, brandImpersonation: 95, ssl: 65, keywords: 90, redirects: 70, watchlist: 100, punycode: 0, dns: 80 },
    matchedBrand: 'PayPal',
    reasons: [
      'Domain displays unauthorized impersonation of PayPal.',
      'Critical concentration of phishing trigger keywords: account, verification, alert, signin',
      'Uses high-abuse top-level domain (.top)'
    ],
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
    createdAt: new Date(Date.now() - 45 * 60000).toISOString(),
    engineUsed: 'nodejs-multisignal',
  },
  {
    _id: 'scn_103',
    scanId: 'scn_103',
    domain: 'github.com',
    url: 'https://github.com/security',
    mode: 'LIVE',
    risk: {
      score: 5,
      level: 'SAFE',
      probability: 0.05,
      confidence: 0.95,
      verdictType: 'VERIFIED_SAFE',
      verdictLabel: 'Verified Authentic Endpoint',
    },
    signals: { domainReputation: 5, urlStructure: 5, brandImpersonation: 0, ssl: 0, keywords: 0, redirects: 0, watchlist: 0, punycode: 0, dns: 0 },
    matchedBrand: null,
    reasons: [
      'Multi-signal heuristic scans returned zero critical phishing indicators.',
      'Domain follows verified naming conventions and standard security parameters.'
    ],
    timestamp: new Date(Date.now() - 2 * 3600000).toISOString(),
    createdAt: new Date(Date.now() - 2 * 3600000).toISOString(),
    engineUsed: 'nodejs-multisignal',
  },
  {
    _id: 'scn_104',
    scanId: 'scn_104',
    domain: 'apple-icloud-secure-confirm.info',
    url: 'https://apple-icloud-secure-confirm.info/idmswebauth',
    mode: 'DEMO',
    risk: {
      score: 76,
      level: 'HIGH_RISK',
      probability: 0.76,
      confidence: 0.95,
      verdictType: 'HIGH_RISK',
      verdictLabel: 'High Risk Phishing Candidate',
    },
    signals: { domainReputation: 75, urlStructure: 70, brandImpersonation: 95, ssl: 55, keywords: 75, redirects: 60, watchlist: 100, punycode: 0, dns: 70 },
    matchedBrand: 'Apple iCloud',
    reasons: [
      'Domain displays unauthorized impersonation of Apple iCloud.',
      'Multiple credential/security keywords detected: secure, confirm',
      'High similarity to protected brand Apple iCloud.'
    ],
    timestamp: new Date(Date.now() - 5 * 3600000).toISOString(),
    createdAt: new Date(Date.now() - 5 * 3600000).toISOString(),
    engineUsed: 'nodejs-multisignal',
  },
  {
    _id: 'scn_105',
    scanId: 'scn_105',
    domain: 'microsoft.com',
    url: 'https://microsoft.com',
    mode: 'LIVE',
    risk: {
      score: 0,
      level: 'SAFE',
      probability: 0.0,
      confidence: 0.95,
      verdictType: 'VERIFIED_SAFE',
      verdictLabel: 'Verified Authentic Endpoint',
    },
    signals: { domainReputation: 0, urlStructure: 0, brandImpersonation: 0, ssl: 0, keywords: 0, redirects: 0, watchlist: 0, punycode: 0, dns: 0 },
    matchedBrand: 'Microsoft 365',
    reasons: [
      'Domain is the legitimate authorized endpoint for Microsoft 365.',
      'Multi-signal verification returned zero hostile phishing indicators.'
    ],
    timestamp: new Date(Date.now() - 8 * 3600000).toISOString(),
    createdAt: new Date(Date.now() - 8 * 3600000).toISOString(),
    engineUsed: 'nodejs-multisignal',
  }
];

class DatabaseService {
  private client: MongoClient | null = null;
  private mongoDb: Db | null = null;
  private scansCollection: Collection<StoredScan> | null = null;
  private watchlistCollection: Collection<StoredWatchlist> | null = null;
  private isMongoConnected = false;

  // In-memory fallback structures
  private memoryScans: StoredScan[] = [...INITIAL_SCANS];
  private memoryWatchlist: StoredWatchlist[] = [...INITIAL_WATCHLIST];

  constructor() {
    this.initMongo().catch((err) => {
      console.warn('[PHISHTRAP DB] MongoDB initialization notice: running with transactional memory persistence.', err?.message || err);
    });
  }

  private async initMongo(): Promise<boolean> {
    const uri = process.env.MONGODB_URI;
    if (!uri) {
      return false;
    }

    try {
      this.client = new MongoClient(uri, {
        serverSelectionTimeoutMS: 3000,
        connectTimeoutMS: 3000,
      });

      await this.client.connect();
      this.mongoDb = this.client.db('phishtrap');
      this.scansCollection = this.mongoDb.collection<StoredScan>('scans');
      this.watchlistCollection = this.mongoDb.collection<StoredWatchlist>('watchlist');

      // Create indexes for high-speed queries
      await this.scansCollection.createIndex({ createdAt: -1 });
      await this.scansCollection.createIndex({ scanId: 1 }, { unique: true });
      await this.scansCollection.createIndex({ domain: 1 });
      await this.watchlistCollection.createIndex({ domain: 1 });

      // Seed if empty
      const scanCount = await this.scansCollection.countDocuments();
      if (scanCount === 0) {
        await this.scansCollection.insertMany(INITIAL_SCANS as any);
      }

      const wlCount = await this.watchlistCollection.countDocuments();
      if (wlCount === 0) {
        await this.watchlistCollection.insertMany(INITIAL_WATCHLIST as any);
      }

      this.isMongoConnected = true;
      console.log('[PHISHTRAP DB] Connected successfully to MongoDB enterprise database.');
      return true;
    } catch (err: any) {
      this.isMongoConnected = false;
      console.warn('[PHISHTRAP DB] Could not establish live MongoDB connection. Active store: transactional memory fallback.', err.message);
      return false;
    }
  }

  public async getScans(filters?: { search?: string; risk?: string; brand?: string }): Promise<StoredScan[]> {
    if (this.isMongoConnected && this.scansCollection) {
      try {
        const query: any = {};
        if (filters?.search) {
          const regex = new RegExp(filters.search, 'i');
          query.$or = [{ domain: regex }, { url: regex }, { matchedBrand: regex }];
        }
        if (filters?.risk && filters.risk !== 'ALL') {
          query['risk.level'] = filters.risk;
        }
        if (filters?.brand && filters.brand !== 'ALL') {
          query.matchedBrand = new RegExp(`^${filters.brand}$`, 'i');
        }

        const docs = await this.scansCollection.find(query).sort({ createdAt: -1 }).toArray();
        return docs.map(doc => ({ ...doc, _id: doc._id.toString() }));
      } catch (err) {
        console.error('[PHISHTRAP DB] MongoDB getScans error, falling back to memory:', err);
      }
    }

    // Memory Store Implementation
    let result = [...this.memoryScans];

    if (filters?.search) {
      const q = filters.search.toLowerCase();
      result = result.filter(s =>
        s.domain.toLowerCase().includes(q) ||
        s.url.toLowerCase().includes(q) ||
        (s.matchedBrand && s.matchedBrand.toLowerCase().includes(q))
      );
    }

    if (filters?.risk && filters.risk !== 'ALL') {
      result = result.filter(s => s.risk.level === filters.risk);
    }

    if (filters?.brand && filters.brand !== 'ALL') {
      result = result.filter(s => s.matchedBrand?.toLowerCase() === filters.brand?.toLowerCase());
    }

    return result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  public async getScanById(id: string): Promise<StoredScan | null> {
    if (this.isMongoConnected && this.scansCollection) {
      try {
        const doc = await this.scansCollection.findOne({
          $or: [{ scanId: id }, { _id: id as any }]
        });
        if (doc) return { ...doc, _id: doc._id.toString() };
      } catch (err) {
        console.error('[PHISHTRAP DB] MongoDB getScanById error:', err);
      }
    }
    return this.memoryScans.find(s => s.scanId === id || s._id === id) || null;
  }

  public async saveScan(scanData: Omit<StoredScan, '_id' | 'createdAt'>): Promise<StoredScan> {
    const id = scanData.scanId || 'scn_' + Math.random().toString(36).substring(2, 12);
    const newScan: StoredScan = {
      ...scanData,
      _id: id,
      scanId: id,
      createdAt: scanData.timestamp || new Date().toISOString(),
    };

    if (this.isMongoConnected && this.scansCollection) {
      try {
        await this.scansCollection.insertOne(newScan as any);
      } catch (err) {
        console.error('[PHISHTRAP DB] MongoDB saveScan error:', err);
      }
    }

    // Always maintain in memory store as well
    this.memoryScans.unshift(newScan);
    return newScan;
  }

  public async getOverview() {
    const scans = await this.getScans();
    const totalScans = scans.length;
    const safe = scans.filter(s => s.risk.level === 'SAFE').length;
    const suspicious = scans.filter(s => s.risk.level === 'SUSPICIOUS').length;
    const highRisk = scans.filter(s => s.risk.level === 'HIGH_RISK').length;
    const critical = scans.filter(s => s.risk.level === 'CRITICAL').length;
    const watchlistMatches = scans.filter(s => !!s.matchedBrand).length;

    const safePercentage = totalScans > 0 ? Math.round((safe / totalScans) * 100) : 0;
    const suspiciousPercentage = totalScans > 0 ? Math.round((suspicious / totalScans) * 100) : 0;
    const highRiskPercentage = totalScans > 0 ? Math.round((highRisk / totalScans) * 100) : 0;
    const criticalPercentage = totalScans > 0 ? Math.round((critical / totalScans) * 100) : 0;

    return {
      totalScans,
      safe,
      suspicious,
      highRisk,
      critical,
      watchlistMatches,
      safePercentage,
      suspiciousPercentage,
      highRiskPercentage,
      criticalPercentage,
      recentScans: scans.slice(0, 5),
    };
  }

  public async getWatchlist(): Promise<StoredWatchlist[]> {
    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        const docs = await this.watchlistCollection.find().sort({ createdAt: -1 }).toArray();
        return docs.map(doc => ({ ...doc, _id: doc._id.toString() }));
      } catch (err) {
        console.error('[PHISHTRAP DB] MongoDB getWatchlist error:', err);
      }
    }
    return [...this.memoryWatchlist];
  }

  public async addWatchlistBrand(brand: { name: string; domain: string; category?: string }): Promise<StoredWatchlist> {
    const id = 'wl_' + Math.random().toString(36).substring(2, 10);
    const now = new Date().toISOString();
    const newEntry: StoredWatchlist = {
      _id: id,
      id,
      name: brand.name.trim(),
      domain: brand.domain.trim().toLowerCase(),
      category: brand.category || 'Banking',
      active: true,
      createdAt: now,
      updatedAt: now,
    };

    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        await this.watchlistCollection.insertOne(newEntry as any);
      } catch (err) {
        console.error('[PHISHTRAP DB] MongoDB addWatchlistBrand error:', err);
      }
    }

    this.memoryWatchlist.unshift(newEntry);
    return newEntry;
  }

  public async updateWatchlistBrand(id: string, updates: Partial<StoredWatchlist>): Promise<StoredWatchlist | null> {
    const now = new Date().toISOString();

    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        await this.watchlistCollection.updateOne(
          { $or: [{ id }, { _id: id as any }] },
          { $set: { ...updates, updatedAt: now } }
        );
      } catch (err) {
        console.error('[PHISHTRAP DB] MongoDB updateWatchlistBrand error:', err);
      }
    }

    const idx = this.memoryWatchlist.findIndex(w => w.id === id || w._id === id);
    if (idx === -1) return null;
    this.memoryWatchlist[idx] = {
      ...this.memoryWatchlist[idx],
      ...updates,
      updatedAt: now,
    };
    return this.memoryWatchlist[idx];
  }

  public async deleteWatchlistBrand(id: string): Promise<boolean> {
    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        const res = await this.watchlistCollection.deleteOne({
          $or: [{ id }, { _id: id as any }]
        });
        if (res.deletedCount && res.deletedCount > 0) {
          this.memoryWatchlist = this.memoryWatchlist.filter(w => w.id !== id && w._id !== id);
          return true;
        }
      } catch (err) {
        console.error('[PHISHTRAP DB] MongoDB deleteWatchlistBrand error:', err);
      }
    }

    const initLen = this.memoryWatchlist.length;
    this.memoryWatchlist = this.memoryWatchlist.filter(w => w.id !== id && w._id !== id);
    return this.memoryWatchlist.length < initLen;
  }

  public isConnectedToMongo(): boolean {
    return this.isMongoConnected;
  }
}

export const db = new DatabaseService();
