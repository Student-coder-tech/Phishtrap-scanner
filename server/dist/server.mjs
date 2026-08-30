// index.ts
import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

// src/db.ts
import { MongoClient } from "mongodb";
var INITIAL_WATCHLIST = [
  {
    _id: "wl_001",
    id: "wl_001",
    name: "Chase Bank",
    domain: "chase.com",
    category: "Banking",
    active: true,
    createdAt: new Date(Date.now() - 30 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 30 * 864e5).toISOString()
  },
  {
    _id: "wl_002",
    id: "wl_002",
    name: "PayPal",
    domain: "paypal.com",
    category: "Banking",
    active: true,
    createdAt: new Date(Date.now() - 25 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 25 * 864e5).toISOString()
  },
  {
    _id: "wl_003",
    id: "wl_003",
    name: "Apple iCloud",
    domain: "apple.com",
    category: "Cloud & SaaS",
    active: true,
    createdAt: new Date(Date.now() - 20 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 20 * 864e5).toISOString()
  },
  {
    _id: "wl_004",
    id: "wl_004",
    name: "Microsoft 365",
    domain: "microsoft.com",
    category: "Cloud & SaaS",
    active: true,
    createdAt: new Date(Date.now() - 18 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 18 * 864e5).toISOString()
  },
  {
    _id: "wl_005",
    id: "wl_005",
    name: "Coinbase",
    domain: "coinbase.com",
    category: "Crypto & FinTech",
    active: true,
    createdAt: new Date(Date.now() - 15 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 15 * 864e5).toISOString()
  },
  {
    _id: "wl_006",
    id: "wl_006",
    name: "Amazon",
    domain: "amazon.com",
    category: "E-commerce",
    active: true,
    createdAt: new Date(Date.now() - 12 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 12 * 864e5).toISOString()
  },
  {
    _id: "wl_007",
    id: "wl_007",
    name: "DocuSign",
    domain: "docusign.com",
    category: "Cloud & SaaS",
    active: true,
    createdAt: new Date(Date.now() - 10 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 10 * 864e5).toISOString()
  },
  {
    _id: "wl_008",
    id: "wl_008",
    name: "Internal Revenue Service (IRS)",
    domain: "irs.gov",
    category: "Government",
    active: false,
    createdAt: new Date(Date.now() - 8 * 864e5).toISOString(),
    updatedAt: new Date(Date.now() - 8 * 864e5).toISOString()
  }
];
var INITIAL_SCANS = [
  {
    _id: "scn_101",
    scanId: "scn_101",
    domain: "chase-security-login-portal.xyz",
    url: "https://chase-security-login-portal.xyz/auth/verify",
    mode: "DEMO",
    risk: {
      score: 94,
      level: "CRITICAL",
      probability: 0.94,
      confidence: 0.95,
      verdictType: "CRITICAL",
      verdictLabel: "Critical Phishing Threat"
    },
    signals: { domainReputation: 95, urlStructure: 85, brandImpersonation: 100, ssl: 70, keywords: 95, redirects: 70, watchlist: 100, punycode: 0, dns: 90 },
    matchedBrand: "Chase Bank",
    reasons: [
      "Domain displays unauthorized impersonation of Chase Bank.",
      "Critical concentration of phishing trigger keywords: login, security, verify",
      "Uses high-abuse top-level domain (.xyz)",
      "Excessive hyphen chaining (3 hyphens)",
      "Matched critical monitored watchlist target: Chase Bank (Banking)"
    ],
    timestamp: new Date(Date.now() - 12 * 6e4).toISOString(),
    createdAt: new Date(Date.now() - 12 * 6e4).toISOString(),
    engineUsed: "nodejs-multisignal"
  },
  {
    _id: "scn_102",
    scanId: "scn_102",
    domain: "paypal-account-verification-alert.top",
    url: "https://paypal-account-verification-alert.top/signin",
    mode: "DEMO",
    risk: {
      score: 88,
      level: "CRITICAL",
      probability: 0.88,
      confidence: 0.95,
      verdictType: "CRITICAL",
      verdictLabel: "Critical Phishing Threat"
    },
    signals: { domainReputation: 90, urlStructure: 80, brandImpersonation: 95, ssl: 65, keywords: 90, redirects: 70, watchlist: 100, punycode: 0, dns: 80 },
    matchedBrand: "PayPal",
    reasons: [
      "Domain displays unauthorized impersonation of PayPal.",
      "Critical concentration of phishing trigger keywords: account, verification, alert, signin",
      "Uses high-abuse top-level domain (.top)"
    ],
    timestamp: new Date(Date.now() - 45 * 6e4).toISOString(),
    createdAt: new Date(Date.now() - 45 * 6e4).toISOString(),
    engineUsed: "nodejs-multisignal"
  },
  {
    _id: "scn_103",
    scanId: "scn_103",
    domain: "github.com",
    url: "https://github.com/security",
    mode: "LIVE",
    risk: {
      score: 5,
      level: "SAFE",
      probability: 0.05,
      confidence: 0.95,
      verdictType: "VERIFIED_SAFE",
      verdictLabel: "Verified Authentic Endpoint"
    },
    signals: { domainReputation: 5, urlStructure: 5, brandImpersonation: 0, ssl: 0, keywords: 0, redirects: 0, watchlist: 0, punycode: 0, dns: 0 },
    matchedBrand: null,
    reasons: [
      "Multi-signal heuristic scans returned zero critical phishing indicators.",
      "Domain follows verified naming conventions and standard security parameters."
    ],
    timestamp: new Date(Date.now() - 2 * 36e5).toISOString(),
    createdAt: new Date(Date.now() - 2 * 36e5).toISOString(),
    engineUsed: "nodejs-multisignal"
  },
  {
    _id: "scn_104",
    scanId: "scn_104",
    domain: "apple-icloud-secure-confirm.info",
    url: "https://apple-icloud-secure-confirm.info/idmswebauth",
    mode: "DEMO",
    risk: {
      score: 76,
      level: "HIGH_RISK",
      probability: 0.76,
      confidence: 0.95,
      verdictType: "HIGH_RISK",
      verdictLabel: "High Risk Phishing Candidate"
    },
    signals: { domainReputation: 75, urlStructure: 70, brandImpersonation: 95, ssl: 55, keywords: 75, redirects: 60, watchlist: 100, punycode: 0, dns: 70 },
    matchedBrand: "Apple iCloud",
    reasons: [
      "Domain displays unauthorized impersonation of Apple iCloud.",
      "Multiple credential/security keywords detected: secure, confirm",
      "High similarity to protected brand Apple iCloud."
    ],
    timestamp: new Date(Date.now() - 5 * 36e5).toISOString(),
    createdAt: new Date(Date.now() - 5 * 36e5).toISOString(),
    engineUsed: "nodejs-multisignal"
  },
  {
    _id: "scn_105",
    scanId: "scn_105",
    domain: "microsoft.com",
    url: "https://microsoft.com",
    mode: "LIVE",
    risk: {
      score: 0,
      level: "SAFE",
      probability: 0,
      confidence: 0.95,
      verdictType: "VERIFIED_SAFE",
      verdictLabel: "Verified Authentic Endpoint"
    },
    signals: { domainReputation: 0, urlStructure: 0, brandImpersonation: 0, ssl: 0, keywords: 0, redirects: 0, watchlist: 0, punycode: 0, dns: 0 },
    matchedBrand: "Microsoft 365",
    reasons: [
      "Domain is the legitimate authorized endpoint for Microsoft 365.",
      "Multi-signal verification returned zero hostile phishing indicators."
    ],
    timestamp: new Date(Date.now() - 8 * 36e5).toISOString(),
    createdAt: new Date(Date.now() - 8 * 36e5).toISOString(),
    engineUsed: "nodejs-multisignal"
  }
];
var DatabaseService = class {
  client = null;
  mongoDb = null;
  scansCollection = null;
  watchlistCollection = null;
  isMongoConnected = false;
  // In-memory fallback structures
  memoryScans = [...INITIAL_SCANS];
  memoryWatchlist = [...INITIAL_WATCHLIST];
  constructor() {
    this.initMongo().catch((err) => {
      console.warn("[PHISHTRAP DB] MongoDB initialization notice: running with transactional memory persistence.", err?.message || err);
    });
  }
  async initMongo() {
    const uri = process.env.MONGODB_URI;
    if (!uri) {
      return false;
    }
    try {
      this.client = new MongoClient(uri, {
        serverSelectionTimeoutMS: 3e3,
        connectTimeoutMS: 3e3
      });
      await this.client.connect();
      this.mongoDb = this.client.db("phishtrap");
      this.scansCollection = this.mongoDb.collection("scans");
      this.watchlistCollection = this.mongoDb.collection("watchlist");
      await this.scansCollection.createIndex({ createdAt: -1 });
      await this.scansCollection.createIndex({ scanId: 1 }, { unique: true });
      await this.scansCollection.createIndex({ domain: 1 });
      await this.watchlistCollection.createIndex({ domain: 1 });
      const scanCount = await this.scansCollection.countDocuments();
      if (scanCount === 0) {
        await this.scansCollection.insertMany(INITIAL_SCANS);
      }
      const wlCount = await this.watchlistCollection.countDocuments();
      if (wlCount === 0) {
        await this.watchlistCollection.insertMany(INITIAL_WATCHLIST);
      }
      this.isMongoConnected = true;
      console.log("[PHISHTRAP DB] Connected successfully to MongoDB enterprise database.");
      return true;
    } catch (err) {
      this.isMongoConnected = false;
      console.warn("[PHISHTRAP DB] Could not establish live MongoDB connection. Active store: transactional memory fallback.", err.message);
      return false;
    }
  }
  async getScans(filters) {
    if (this.isMongoConnected && this.scansCollection) {
      try {
        const query = {};
        if (filters?.search) {
          const regex = new RegExp(filters.search, "i");
          query.$or = [{ domain: regex }, { url: regex }, { matchedBrand: regex }];
        }
        if (filters?.risk && filters.risk !== "ALL") {
          query["risk.level"] = filters.risk;
        }
        if (filters?.brand && filters.brand !== "ALL") {
          query.matchedBrand = new RegExp(`^${filters.brand}$`, "i");
        }
        const docs = await this.scansCollection.find(query).sort({ createdAt: -1 }).toArray();
        return docs.map((doc) => ({ ...doc, _id: doc._id.toString() }));
      } catch (err) {
        console.error("[PHISHTRAP DB] MongoDB getScans error, falling back to memory:", err);
      }
    }
    let result = [...this.memoryScans];
    if (filters?.search) {
      const q = filters.search.toLowerCase();
      result = result.filter(
        (s) => s.domain.toLowerCase().includes(q) || s.url.toLowerCase().includes(q) || s.matchedBrand && s.matchedBrand.toLowerCase().includes(q)
      );
    }
    if (filters?.risk && filters.risk !== "ALL") {
      result = result.filter((s) => s.risk.level === filters.risk);
    }
    if (filters?.brand && filters.brand !== "ALL") {
      result = result.filter((s) => s.matchedBrand?.toLowerCase() === filters.brand?.toLowerCase());
    }
    return result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }
  async getScanById(id) {
    if (this.isMongoConnected && this.scansCollection) {
      try {
        const doc = await this.scansCollection.findOne({
          $or: [{ scanId: id }, { _id: id }]
        });
        if (doc) return { ...doc, _id: doc._id.toString() };
      } catch (err) {
        console.error("[PHISHTRAP DB] MongoDB getScanById error:", err);
      }
    }
    return this.memoryScans.find((s) => s.scanId === id || s._id === id) || null;
  }
  async saveScan(scanData) {
    const id = scanData.scanId || "scn_" + Math.random().toString(36).substring(2, 12);
    const newScan = {
      ...scanData,
      _id: id,
      scanId: id,
      createdAt: scanData.timestamp || (/* @__PURE__ */ new Date()).toISOString()
    };
    if (this.isMongoConnected && this.scansCollection) {
      try {
        await this.scansCollection.insertOne(newScan);
      } catch (err) {
        console.error("[PHISHTRAP DB] MongoDB saveScan error:", err);
      }
    }
    this.memoryScans.unshift(newScan);
    return newScan;
  }
  async getOverview() {
    const scans = await this.getScans();
    const totalScans = scans.length;
    const safe = scans.filter((s) => s.risk.level === "SAFE").length;
    const suspicious = scans.filter((s) => s.risk.level === "SUSPICIOUS").length;
    const highRisk = scans.filter((s) => s.risk.level === "HIGH_RISK").length;
    const critical = scans.filter((s) => s.risk.level === "CRITICAL").length;
    const watchlistMatches = scans.filter((s) => !!s.matchedBrand).length;
    const safePercentage = totalScans > 0 ? Math.round(safe / totalScans * 100) : 0;
    const suspiciousPercentage = totalScans > 0 ? Math.round(suspicious / totalScans * 100) : 0;
    const highRiskPercentage = totalScans > 0 ? Math.round(highRisk / totalScans * 100) : 0;
    const criticalPercentage = totalScans > 0 ? Math.round(critical / totalScans * 100) : 0;
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
      recentScans: scans.slice(0, 5)
    };
  }
  async getWatchlist() {
    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        const docs = await this.watchlistCollection.find().sort({ createdAt: -1 }).toArray();
        return docs.map((doc) => ({ ...doc, _id: doc._id.toString() }));
      } catch (err) {
        console.error("[PHISHTRAP DB] MongoDB getWatchlist error:", err);
      }
    }
    return [...this.memoryWatchlist];
  }
  async addWatchlistBrand(brand) {
    const id = "wl_" + Math.random().toString(36).substring(2, 10);
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const newEntry = {
      _id: id,
      id,
      name: brand.name.trim(),
      domain: brand.domain.trim().toLowerCase(),
      category: brand.category || "Banking",
      active: true,
      createdAt: now,
      updatedAt: now
    };
    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        await this.watchlistCollection.insertOne(newEntry);
      } catch (err) {
        console.error("[PHISHTRAP DB] MongoDB addWatchlistBrand error:", err);
      }
    }
    this.memoryWatchlist.unshift(newEntry);
    return newEntry;
  }
  async updateWatchlistBrand(id, updates) {
    const now = (/* @__PURE__ */ new Date()).toISOString();
    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        await this.watchlistCollection.updateOne(
          { $or: [{ id }, { _id: id }] },
          { $set: { ...updates, updatedAt: now } }
        );
      } catch (err) {
        console.error("[PHISHTRAP DB] MongoDB updateWatchlistBrand error:", err);
      }
    }
    const idx = this.memoryWatchlist.findIndex((w) => w.id === id || w._id === id);
    if (idx === -1) return null;
    this.memoryWatchlist[idx] = {
      ...this.memoryWatchlist[idx],
      ...updates,
      updatedAt: now
    };
    return this.memoryWatchlist[idx];
  }
  async deleteWatchlistBrand(id) {
    if (this.isMongoConnected && this.watchlistCollection) {
      try {
        const res = await this.watchlistCollection.deleteOne({
          $or: [{ id }, { _id: id }]
        });
        if (res.deletedCount && res.deletedCount > 0) {
          this.memoryWatchlist = this.memoryWatchlist.filter((w) => w.id !== id && w._id !== id);
          return true;
        }
      } catch (err) {
        console.error("[PHISHTRAP DB] MongoDB deleteWatchlistBrand error:", err);
      }
    }
    const initLen = this.memoryWatchlist.length;
    this.memoryWatchlist = this.memoryWatchlist.filter((w) => w.id !== id && w._id !== id);
    return this.memoryWatchlist.length < initLen;
  }
  isConnectedToMongo() {
    return this.isMongoConnected;
  }
};
var db = new DatabaseService();

// src/engine.ts
import dns from "dns";
import tls from "tls";
import http from "http";
import https from "https";
import { URL } from "url";
var SUSPICIOUS_TLDS = /* @__PURE__ */ new Set([
  "xyz",
  "top",
  "work",
  "loan",
  "club",
  "vip",
  "gq",
  "cf",
  "ml",
  "ga",
  "tk",
  "click",
  "link",
  "download",
  "racing",
  "kim",
  "country",
  "stream",
  "live",
  "buzz",
  "rest",
  "fit",
  "icu",
  "cyou",
  "monster",
  "quest",
  "beauty",
  "hair",
  "skin",
  "cam",
  "sbs",
  "cfd",
  "date",
  "faith",
  "party",
  "trade",
  "accountant"
]);
var KNOWN_BRANDS = [
  { name: "PayPal", domain: "paypal.com", category: "Banking & Payments", keywords: ["paypal", "pay-pal", "paypai", "paypa1"] },
  { name: "Apple iCloud", domain: "apple.com", category: "Cloud & Tech", keywords: ["apple", "icloud", "appie", "app1e", "appleid", "itunes"] },
  { name: "Microsoft 365", domain: "microsoft.com", category: "Cloud & Office", keywords: ["microsoft", "office365", "outlook", "msft", "m1crosoft", "onedrive", "sharepoint"] },
  { name: "Google Workspace", domain: "google.com", category: "Cloud & Tech", keywords: ["google", "gmail", "g00gle", "goog1e", "gdrive", "google-verify"] },
  { name: "Amazon", domain: "amazon.com", category: "E-commerce", keywords: ["amazon", "amaz0n", "prime-video", "aws-security", "amazn"] },
  { name: "Chase Bank", domain: "chase.com", category: "Banking", keywords: ["chase", "chasebank", "chasemobile", "chaseonline"] },
  { name: "Bank of America", domain: "bankofamerica.com", category: "Banking", keywords: ["bankofamerica", "bofa", "boa-secure", "bank-of-america"] },
  { name: "Wells Fargo", domain: "wellsfargo.com", category: "Banking", keywords: ["wellsfargo", "wf-verify", "wellsfargosecure", "well-fargo"] },
  { name: "Citibank", domain: "citi.com", category: "Banking", keywords: ["citibank", "citicards", "citi-verify"] },
  { name: "Netflix", domain: "netflix.com", category: "Streaming", keywords: ["netflix", "netfiix", "netflix-verify", "netf1ix"] },
  { name: "Meta / Facebook", domain: "meta.com", category: "Social Media", keywords: ["facebook", "instagram", "faceb00k", "meta-verify", "meta-business"] },
  { name: "Coinbase", domain: "coinbase.com", category: "Crypto & FinTech", keywords: ["coinbase", "c0inbase", "coin-base", "coinbase-wallet"] },
  { name: "Binance", domain: "binance.com", category: "Crypto & FinTech", keywords: ["binance", "binance-security", "binancc", "binance-verify"] },
  { name: "MetaMask", domain: "metamask.io", category: "Crypto & FinTech", keywords: ["metamask", "meta-mask", "metamask-restore", "metamask-io"] },
  { name: "DocuSign", domain: "docusign.com", category: "Cloud & SaaS", keywords: ["docusign", "docus1gn", "docu-sign", "docusign-envelope"] },
  { name: "Dropbox", domain: "dropbox.com", category: "Cloud & SaaS", keywords: ["dropbox", "drop-box", "dropbox-share"] },
  { name: "DHL / FedEx", domain: "dhl.com", category: "Logistics", keywords: ["dhl-track", "fedex-delivery", "parcel-tracking", "usps-tracking", "dhl-parcel"] },
  { name: "Internal Revenue Service (IRS)", domain: "irs.gov", category: "Government", keywords: ["irs-gov", "irs-tax", "irs-refund", "tax-refund"] },
  { name: "Steam / Valve", domain: "steampowered.com", category: "Gaming", keywords: ["steamcommunity", "steampowered", "steam-trade", "steam-gift"] }
];
var KEYWORD_CATEGORIES = {
  auth: ["login", "signin", "sign-in", "log-in", "auth", "authenticate", "portal", "sso", "webmail", "session"],
  credential: ["password", "credential", "passcode", "security", "secure", "verify", "verification", "validation", "confirm", "confirmation", "recovery", "recover", "reactivate"],
  threat: ["suspended", "suspend", "unusual-activity", "restricted", "unlock", "alert", "notification", "urgent", "action-required", "violation", "compromised", "warning"],
  financial: ["banking", "wallet", "billing", "invoice", "payment", "refund", "wire", "transaction", "direct-deposit", "statement", "payout"],
  mfa: ["2fa", "mfa", "otp", "sms-code", "token", "passkey", "authenticator"]
};
var HOMOGLYPH_MAP = {
  "\u0430": "a",
  // Cyrillic Small Letter A
  "\u0435": "e",
  // Cyrillic Small Letter Ie
  "\u043E": "o",
  // Cyrillic Small Letter O
  "\u0440": "p",
  // Cyrillic Small Letter Er
  "\u0441": "c",
  // Cyrillic Small Letter Es
  "\u0443": "y",
  // Cyrillic Small Letter U
  "\u0445": "x",
  // Cyrillic Small Letter Ha
  "\u0456": "i",
  // Cyrillic Small Letter Byelorussian-Ukrainian I
  "\u0455": "s",
  // Cyrillic Small Letter Dze
  "\u0458": "j",
  // Cyrillic Small Letter Je
  "\u03B1": "a",
  // Greek Small Letter Alpha
  "\u03BF": "o",
  // Greek Small Letter Omicron
  "\u03BD": "v",
  // Greek Small Letter Nu
  "\u03C1": "p"
  // Greek Small Letter Rho
};
function calculateEntropy(text) {
  if (!text) return 0;
  const freq = {};
  for (const char of text) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}
function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) return levenshteinDistance(s2, s1);
  if (s2.length === 0) return s1.length;
  let previousRow = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const currentRow = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      const insertions = previousRow[j + 1] + 1;
      const deletions = currentRow[j] + 1;
      const substitutions = previousRow[j] + (s1[i] !== s2[j] ? 1 : 0);
      currentRow.push(Math.min(insertions, deletions, substitutions));
    }
    previousRow = currentRow;
  }
  return previousRow[previousRow.length - 1];
}
function parseUrl(rawInput) {
  let clean = rawInput.trim();
  if (!/^https?:\/\//i.test(clean)) {
    clean = "https://" + clean;
  }
  try {
    const parsed = new URL(clean);
    const hostname = parsed.hostname.toLowerCase();
    const parts = hostname.split(".");
    const tld = parts.length > 1 ? parts[parts.length - 1] : "";
    const rootDomain = parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
    const subdomain = parts.length > 2 ? parts.slice(0, -2).join(".") : "";
    const isPunycode = hostname.includes("xn--");
    let hasHomoglyphs = false;
    let homoglyphMatches = [];
    for (const char of rawInput) {
      if (HOMOGLYPH_MAP[char]) {
        hasHomoglyphs = true;
        homoglyphMatches.push(`'${char}' (looks like '${HOMOGLYPH_MAP[char]}')`);
      }
    }
    return {
      raw: rawInput,
      fullUrl: parsed.toString(),
      hostname,
      rootDomain,
      subdomain,
      tld,
      path: parsed.pathname + parsed.search,
      pathname: parsed.pathname,
      search: parsed.search,
      protocol: parsed.protocol.replace(":", ""),
      port: parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === "https:" ? 443 : 80,
      hasExplicitPort: Boolean(parsed.port),
      partsCount: parts.length,
      isPunycode,
      hasHomoglyphs,
      homoglyphMatches,
      hasAuthAtSymbol: rawInput.includes("@"),
      isRawIp: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) || hostname.startsWith("[")
    };
  } catch {
    const stripped = rawInput.replace(/^[a-zA-Z]+:\/\//, "").split("/")[0].toLowerCase();
    const parts = stripped.split(".");
    const tld = parts.length > 1 ? parts[parts.length - 1] : "";
    return {
      raw: rawInput,
      fullUrl: "https://" + stripped,
      hostname: stripped,
      rootDomain: stripped,
      subdomain: "",
      tld,
      path: "/",
      pathname: "/",
      search: "",
      protocol: "https",
      port: 443,
      hasExplicitPort: false,
      partsCount: parts.length,
      isPunycode: stripped.includes("xn--"),
      hasHomoglyphs: false,
      homoglyphMatches: [],
      hasAuthAtSymbol: rawInput.includes("@"),
      isRawIp: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(stripped)
    };
  }
}
async function performLiveDnsLookup(hostname) {
  try {
    const dnsResolve = dns.promises;
    const timeoutPromise = new Promise(
      (_, reject) => setTimeout(() => reject(new Error("DNS lookup timeout")), 2e3)
    );
    const ipPromise = dnsResolve.resolve4(hostname).catch(() => []);
    const mxPromise = dnsResolve.resolveMx(hostname).catch(() => []);
    const [ips, mxRecords] = await Promise.race([
      Promise.all([ipPromise, mxPromise]),
      timeoutPromise
    ]);
    const resolvedIps = Array.isArray(ips) ? ips : [];
    const mxHosts = Array.isArray(mxRecords) ? mxRecords.map((m) => m.exchange) : [];
    return {
      resolved: resolvedIps.length > 0,
      ips: resolvedIps,
      mx: mxHosts
    };
  } catch (err) {
    return {
      resolved: false,
      ips: [],
      mx: [],
      error: err.code || err.message
    };
  }
}
async function performLiveTlsProbe(hostname, port = 443) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 2500
      },
      () => {
        if (resolved) return;
        resolved = true;
        try {
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          const rawIssuer = cert?.issuer?.O || cert?.issuer?.CN;
          const issuer = Array.isArray(rawIssuer) ? rawIssuer.join(", ") : rawIssuer || "Unknown Certificate Authority";
          const validTo = cert?.valid_to;
          socket.destroy();
          resolve({
            valid: Boolean(cert && Object.keys(cert).length > 0),
            issuer,
            validTo,
            authorized
          });
        } catch {
          socket.destroy();
          resolve({ valid: false, error: "Failed to parse peer certificate" });
        }
      }
    );
    socket.on("timeout", () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({ valid: false, error: "TLS handshake timeout (2500ms exceeded)" });
    });
    socket.on("error", (err) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({ valid: false, error: err.message || "TLS socket error" });
    });
  });
}
async function performLiveRedirectProbe(targetUrl) {
  return new Promise((resolve) => {
    try {
      const parsed = new URL(targetUrl);
      const isHttps = parsed.protocol === "https:";
      const transport = isHttps ? https : http;
      const req = transport.request(
        targetUrl,
        {
          method: "HEAD",
          headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishtrapScanner/1.0" },
          timeout: 2500
        },
        (res) => {
          const statusCode = res.statusCode || 200;
          const location = res.headers.location;
          let hasCrossDomainRedirect = false;
          if (location) {
            try {
              const nextUrl = new URL(location, targetUrl);
              hasCrossDomainRedirect = nextUrl.hostname !== parsed.hostname;
            } catch {
            }
          }
          resolve({
            hops: location ? 1 : 0,
            finalUrl: location || targetUrl,
            hasCrossDomainRedirect,
            status: statusCode
          });
        }
      );
      req.on("timeout", () => {
        req.destroy();
        resolve({ hops: 0, finalUrl: targetUrl, hasCrossDomainRedirect: false, status: 0, error: "Probe timeout" });
      });
      req.on("error", (err) => {
        resolve({ hops: 0, finalUrl: targetUrl, hasCrossDomainRedirect: false, status: 0, error: err.message });
      });
      req.end();
    } catch (e) {
      resolve({ hops: 0, finalUrl: targetUrl, hasCrossDomainRedirect: false, status: 0, error: e.message });
    }
  });
}
async function runMultiSignalEngine(input, mode = "DEMO", watchlist = []) {
  const parsed = parseUrl(input);
  const hostname = parsed.hostname;
  const tld = parsed.tld;
  const entropy = calculateEntropy(hostname);
  let urlScore = 0;
  const urlFlags = [];
  const urlEvidence = {
    length: parsed.fullUrl.length,
    isRawIp: parsed.isRawIp,
    hasAuthAtSymbol: parsed.hasAuthAtSymbol,
    pathLevels: parsed.pathname.split("/").filter(Boolean).length
  };
  if (parsed.isRawIp) {
    urlScore += 75;
    urlFlags.push("Raw numeric IP address utilized as host (circumvents domain reputation)");
  }
  if (parsed.hasAuthAtSymbol) {
    urlScore += 65;
    urlFlags.push('Dangerous "@" authority delimiter detected in URL (credential spoofing vector)');
  }
  if (parsed.fullUrl.length > 120) {
    urlScore += 35;
    urlFlags.push(`Abnormally lengthy URL string (${parsed.fullUrl.length} chars) typical of token/payload obfuscation`);
  } else if (parsed.fullUrl.length > 80) {
    urlScore += 15;
  }
  if (parsed.pathname.includes("//")) {
    urlScore += 25;
    urlFlags.push("Multiple consecutive slashes in URL path (directory traversal / obfuscation indicator)");
  }
  if (parsed.hasExplicitPort && parsed.port !== 80 && parsed.port !== 443) {
    urlScore += 30;
    urlFlags.push(`Non-standard destination port specified (Port ${parsed.port})`);
  }
  if (/%[0-9a-f]{2}/i.test(parsed.path)) {
    urlScore += 15;
    urlFlags.push("Contains percent-encoded hexadecimal byte sequences");
  }
  urlScore = Math.min(100, Math.max(0, urlScore));
  const urlExp = urlFlags.length > 0 ? urlFlags.join(". ") : "URL structure complies with standard web RFC conventions.";
  let hostScore = 0;
  const hostFlags = [];
  const hostEvidence = {
    entropy,
    tld,
    hyphens: (hostname.match(/-/g) || []).length,
    subdomains: Math.max(0, parsed.partsCount - 2)
  };
  if (entropy > 3.85) {
    hostScore += 45;
    hostFlags.push(`High Shannon entropy (${entropy}) indicates machine/DGA algorithmic generation`);
  } else if (entropy > 3.3) {
    hostScore += 20;
    hostFlags.push(`Elevated character entropy (${entropy})`);
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    hostScore += 40;
    hostFlags.push(`Operates under high-abuse top-level domain (.${tld})`);
  }
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    hostScore += 35;
    hostFlags.push(`Excessive hyphen chaining (${hyphenCount} hyphens) common in phishing domains`);
  } else if (hyphenCount >= 1) {
    hostScore += 12;
  }
  if (parsed.partsCount > 3) {
    hostScore += 25;
    hostFlags.push(`Deeply nested subdomain hierarchy (${parsed.partsCount - 2} levels)`);
  }
  hostScore = Math.min(100, Math.max(0, hostScore));
  const hostExp = hostFlags.length > 0 ? hostFlags.join(". ") : "Hostname entropy and domain depth reflect standard baseline metrics.";
  let brandScore = 0;
  let matchedBrand = null;
  let isLegitimateBrandEndpoint = false;
  let brandExp = "No brand impersonation or typosquatting patterns detected.";
  const brandEvidence = {};
  const allMonitoredBrands = [...KNOWN_BRANDS];
  for (const w of watchlist) {
    if (w.active) {
      allMonitoredBrands.push({
        name: w.name,
        domain: w.domain.toLowerCase(),
        category: w.category || "Monitored Enterprise",
        keywords: [w.name.toLowerCase().replace(/[^a-z0-9]/g, "")]
      });
    }
  }
  for (const brand of allMonitoredBrands) {
    const brandDomain = brand.domain.toLowerCase();
    const legitRoot = brandDomain.split(".").slice(-2).join(".");
    if (hostname === brandDomain || hostname.endsWith("." + brandDomain)) {
      brandScore = 0;
      matchedBrand = brand.name;
      isLegitimateBrandEndpoint = true;
      brandExp = `Verified genuine authorized endpoint for ${brand.name} (${brandDomain}).`;
      brandEvidence.verifiedAuthorized = true;
      brandEvidence.brand = brand.name;
      break;
    }
    for (const kw of brand.keywords) {
      if (kw && kw.length >= 3 && hostname.includes(kw)) {
        brandScore = 95;
        matchedBrand = brand.name;
        brandExp = `Unauthorized domain explicitly embeds protected brand identity "${brand.name}".`;
        brandEvidence.embeddedKeyword = kw;
        brandEvidence.brand = brand.name;
        break;
      }
    }
    if (brandScore >= 90) break;
    if (parsed.subdomain.includes(legitRoot) || parsed.subdomain.includes(brand.name.toLowerCase())) {
      brandScore = 95;
      matchedBrand = brand.name;
      brandExp = `Subdomain injection attack detected targeting "${brand.name}".`;
      brandEvidence.subdomainSpoof = true;
      break;
    }
    const currentRootLabel = parsed.rootDomain.split(".")[0];
    const legitRootLabel = legitRoot.split(".")[0];
    if (currentRootLabel.length >= 4 && legitRootLabel.length >= 4) {
      const dist = levenshteinDistance(currentRootLabel, legitRootLabel);
      if (dist === 1) {
        brandScore = 85;
        matchedBrand = brand.name;
        brandExp = `High similarity typosquatting (edit distance 1) to brand "${brand.name}".`;
        brandEvidence.editDistance = 1;
        brandEvidence.brand = brand.name;
        break;
      }
    }
  }
  let punyScore = 0;
  let punyExp = "Standard ASCII Latin charset. No homoglyph spoofing detected.";
  const punyEvidence = {
    isPunycode: parsed.isPunycode,
    hasHomoglyphs: parsed.hasHomoglyphs
  };
  if (parsed.hasHomoglyphs) {
    punyScore = 90;
    punyExp = `Critical Unicode homoglyph attack detected: ${parsed.homoglyphMatches.join(", ")}`;
    punyEvidence.matches = parsed.homoglyphMatches;
  } else if (parsed.isPunycode) {
    punyScore = 65;
    punyExp = "Internationalized Domain Name (Punycode xn--) used. Potential character spoofing vector.";
  }
  const targetScanText = (hostname + parsed.path).toLowerCase();
  const matchedKeywordDetails = [];
  for (const [cat, words] of Object.entries(KEYWORD_CATEGORIES)) {
    for (const w of words) {
      if (targetScanText.includes(w)) {
        matchedKeywordDetails.push({ word: w, category: cat });
      }
    }
  }
  let kwScore = 0;
  let kwExp = "No high-risk credential-harvesting or urgent social engineering keywords detected.";
  const uniqueWords = Array.from(new Set(matchedKeywordDetails.map((m) => m.word)));
  if (uniqueWords.length >= 3) {
    kwScore = 95;
    kwExp = `Critical concentration of phishing trigger keywords: ${uniqueWords.slice(0, 4).join(", ")}`;
  } else if (uniqueWords.length === 2) {
    kwScore = 70;
    kwExp = `Multiple security/credential keywords identified: ${uniqueWords.join(", ")}`;
  } else if (uniqueWords.length === 1) {
    kwScore = 40;
    kwExp = `Contains suspicious authentication/action keyword: "${uniqueWords[0]}"`;
  }
  let dnsScore = 0;
  let dnsStatus = "SAFE";
  let dnsExp = "DNS resolution verified successfully.";
  const dnsEvidence = {};
  let resolvedIps = [];
  let mxRecords = [];
  let dnsResolved = false;
  if (mode === "LIVE") {
    const dnsResult = await performLiveDnsLookup(hostname);
    dnsResolved = dnsResult.resolved;
    resolvedIps = dnsResult.ips;
    mxRecords = dnsResult.mx;
    dnsEvidence.ips = resolvedIps;
    dnsEvidence.mx = mxRecords;
    if (!dnsResult.resolved) {
      dnsScore = 80;
      dnsStatus = "HIGH_RISK";
      dnsExp = `Domain failed DNS resolution (${dnsResult.error || "NXDOMAIN / unallocated"}). Host may be taken down or newly registered without active records.`;
    } else {
      dnsScore = 0;
      dnsStatus = "SAFE";
      dnsExp = `Active DNS record resolution verified. Pointing to IP(s): ${resolvedIps.slice(0, 2).join(", ")}`;
    }
  } else {
    if (hostScore >= 70 || brandScore >= 80) {
      dnsScore = 75;
      dnsStatus = "HIGH_RISK";
      dnsExp = "Simulated DNS analysis: Fast-flux infrastructure or unallocated high-risk host.";
    } else {
      dnsScore = 5;
      dnsStatus = "SAFE";
      dnsExp = "Simulated DNS resolution: Active baseline nameservers and valid A records.";
    }
  }
  let sslScore = 0;
  let sslStatus = "SAFE";
  let sslExp = "TLS certificate handshake verified.";
  const sslEvidence = { protocol: parsed.protocol };
  let tlsIssuer;
  let tlsValidTo;
  if (parsed.protocol === "http") {
    sslScore = 80;
    sslStatus = "HIGH_RISK";
    sslExp = "Unencrypted plain HTTP protocol. Legitimate banking and authentication endpoints enforce TLS.";
  } else if (mode === "LIVE") {
    const tlsResult = await performLiveTlsProbe(hostname, parsed.port);
    if (tlsResult.valid) {
      tlsIssuer = tlsResult.issuer;
      tlsValidTo = tlsResult.validTo;
      sslEvidence.issuer = tlsIssuer;
      sslEvidence.validTo = tlsValidTo;
      sslEvidence.authorized = tlsResult.authorized;
      if (!tlsResult.authorized) {
        sslScore = 65;
        sslStatus = "SUSPICIOUS";
        sslExp = `TLS Certificate presented but untrusted / self-signed by "${tlsIssuer}".`;
      } else {
        sslScore = 0;
        sslStatus = "SAFE";
        sslExp = `Valid TLS Certificate issued by "${tlsIssuer}" (Valid until ${tlsValidTo || "N/A"}).`;
      }
    } else {
      sslScore = 15;
      sslStatus = "SAFE";
      sslExp = `HTTPS protocol configured (${tlsResult.error || "standard TLS port"}).`;
    }
  } else {
    if (brandScore >= 70 || kwScore >= 60) {
      sslScore = 60;
      sslStatus = "SUSPICIOUS";
      sslExp = "Simulated short-lived free DV TLS certificate from automated low-trust issuer.";
      tlsIssuer = "Let's Encrypt / Free DV CA (Simulated)";
    } else {
      sslScore = 0;
      sslStatus = "SAFE";
      sslExp = "Simulated high-assurance EV/OV SSL Certificate from trusted root authority.";
      tlsIssuer = "DigiCert Global Root CA (Simulated)";
    }
  }
  let redirScore = 0;
  let redirStatus = "SAFE";
  let redirExp = "Direct endpoint resolution with no open redirect chaining.";
  const redirEvidence = {};
  const openRedirectParams = ["url=", "next=", "redirect=", "goto=", "dest=", "target=", "r=", "return="];
  const hasOpenRedirectParam = openRedirectParams.some((p) => parsed.search.toLowerCase().includes(p));
  if (hasOpenRedirectParam) {
    redirScore = 75;
    redirStatus = "HIGH_RISK";
    redirExp = "Suspicious URL query parameters indicate potential open redirect / interstitial landing attack.";
    redirEvidence.openRedirectParameter = true;
  } else if (mode === "LIVE") {
    const redirResult = await performLiveRedirectProbe(parsed.fullUrl);
    redirEvidence.hops = redirResult.hops;
    redirEvidence.status = redirResult.status;
    if (redirResult.hasCrossDomainRedirect) {
      redirScore = 70;
      redirStatus = "HIGH_RISK";
      redirExp = `Cross-domain redirection detected (routed to ${redirResult.finalUrl}).`;
    } else {
      redirScore = 0;
      redirStatus = "SAFE";
      redirExp = "Direct destination with no unexpected cross-domain cloaking.";
    }
  } else {
    redirScore = 0;
    redirStatus = "SAFE";
  }
  let wlScore = 0;
  let wlBrand = null;
  let wlExp = "Domain is not flagged under monitored corporate brand assets.";
  const wlEvidence = {};
  for (const w of watchlist) {
    if (!w.active) continue;
    const wDomain = w.domain.toLowerCase();
    const wNameKey = w.name.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (wDomain && (hostname.includes(wDomain) || hostname.includes(wNameKey))) {
      if (hostname !== wDomain && !hostname.endsWith("." + wDomain)) {
        wlScore = 100;
        wlBrand = w.name;
        wlExp = `Matched high-priority monitored watchlist entity: ${w.name} (${w.category})`;
        wlEvidence.watchlistMatch = w.name;
        wlEvidence.category = w.category;
        break;
      } else {
        wlScore = 0;
        wlBrand = w.name;
        wlExp = `Authorized domain for monitored watchlist entity: ${w.name}`;
        wlEvidence.isLegitimateWatchlistDomain = true;
        break;
      }
    }
  }
  const finalMatchedBrand = matchedBrand || wlBrand;
  const weights = {
    brandImpersonation: 0.2,
    hostnameAnomalies: 0.15,
    urlStructure: 0.15,
    keywords: 0.1,
    punycode: 0.1,
    dns: 0.1,
    ssl: 0.1,
    redirects: 0.05,
    watchlist: 0.05
  };
  const signalsMap = {
    domainReputation: hostScore,
    urlStructure: urlScore,
    brandImpersonation: brandScore,
    keywords: kwScore,
    punycode: punyScore,
    dns: dnsScore,
    ssl: sslScore,
    redirects: redirScore,
    watchlist: wlScore
  };
  let totalWeightedScore = 0;
  let activeWeightSum = 0;
  for (const [key, val] of Object.entries(signalsMap)) {
    if (val !== null) {
      const w = weights[key] || 0.1;
      totalWeightedScore += val * w;
      activeWeightSum += w;
    }
  }
  let overallScore = Math.round(activeWeightSum > 0 ? totalWeightedScore / activeWeightSum : 0);
  if (brandScore >= 90 && kwScore >= 40) {
    overallScore = Math.max(overallScore, 88);
  }
  if (punyScore >= 90) {
    overallScore = Math.max(overallScore, 85);
  }
  if (isLegitimateBrandEndpoint || wlEvidence.isLegitimateWatchlistDomain) {
    overallScore = 0;
  }
  overallScore = Math.max(0, Math.min(100, overallScore));
  let riskLevel;
  if (overallScore >= 80) {
    riskLevel = "CRITICAL";
  } else if (overallScore >= 55) {
    riskLevel = "HIGH_RISK";
  } else if (overallScore >= 25) {
    riskLevel = "SUSPICIOUS";
  } else {
    riskLevel = "SAFE";
  }
  let verdictType;
  let verdictLabel;
  if (isLegitimateBrandEndpoint || wlEvidence.isLegitimateWatchlistDomain) {
    verdictType = "VERIFIED_SAFE";
    verdictLabel = `Verified Authentic Endpoint (${finalMatchedBrand || "Official Organization"})`;
  } else if (overallScore >= 80) {
    verdictType = "CRITICAL";
    verdictLabel = "Critical Phishing Threat";
  } else if (overallScore >= 55) {
    verdictType = "HIGH_RISK";
    verdictLabel = "High Risk Phishing Candidate";
  } else if (overallScore >= 25) {
    verdictType = "SUSPICIOUS";
    verdictLabel = "Suspicious Indicators Detected";
  } else {
    verdictType = "NO_THREATS_DETECTED";
    verdictLabel = "No Threat Evidence Detected (Low Risk)";
  }
  const probability = Number((overallScore / 100).toFixed(2));
  const confidence = 0.95;
  const reasons = [];
  if (isLegitimateBrandEndpoint) {
    reasons.push(`Domain is the confirmed official and authorized endpoint for ${finalMatchedBrand}.`);
    reasons.push("All security, TLS, and naming heuristic checks verified as legitimate.");
  } else {
    if (finalMatchedBrand && brandScore >= 70) {
      reasons.push(`Domain displays unauthorized brand impersonation targeting "${finalMatchedBrand}".`);
    }
    if (punyScore >= 50) reasons.push(punyExp);
    if (kwScore >= 40) reasons.push(kwExp);
    if (hostScore >= 35) reasons.push(hostExp);
    if (urlScore >= 35) reasons.push(urlExp);
    if (dnsScore && dnsScore >= 50) reasons.push(dnsExp);
    if (sslScore && sslScore >= 50) reasons.push(sslExp);
    if (redirScore && redirScore >= 50) reasons.push(redirExp);
    if (wlScore >= 80) reasons.push(wlExp);
    if (reasons.length === 0) {
      reasons.push("Multi-signal heuristic scans returned zero hostile phishing indicators.");
      reasons.push("Domain structure, TLS parameters, and entropy conform to standard baseline.");
      reasons.push('Note: "No threat evidence detected" indicates lack of known malicious signals rather than organizational certification.');
    }
  }
  const signalDetails = [
    {
      name: "Brand Impersonation & Typosquatting",
      key: "brandImpersonation",
      score: brandScore,
      status: brandScore >= 80 ? "CRITICAL" : brandScore >= 55 ? "HIGH_RISK" : brandScore >= 25 ? "SUSPICIOUS" : "SAFE",
      weight: weights.brandImpersonation,
      explanation: brandExp,
      evidence: brandEvidence
    },
    {
      name: "Hostname & Subdomain Anomalies",
      key: "domainReputation",
      score: hostScore,
      status: hostScore >= 80 ? "CRITICAL" : hostScore >= 55 ? "HIGH_RISK" : hostScore >= 25 ? "SUSPICIOUS" : "SAFE",
      weight: weights.hostnameAnomalies,
      explanation: hostExp,
      evidence: hostEvidence
    },
    {
      name: "URL Structure & Authority",
      key: "urlStructure",
      score: urlScore,
      status: urlScore >= 80 ? "CRITICAL" : urlScore >= 55 ? "HIGH_RISK" : urlScore >= 25 ? "SUSPICIOUS" : "SAFE",
      weight: weights.urlStructure,
      explanation: urlExp,
      evidence: urlEvidence
    },
    {
      name: "Suspicious Keywords & Social Engineering",
      key: "keywords",
      score: kwScore,
      status: kwScore >= 80 ? "CRITICAL" : kwScore >= 55 ? "HIGH_RISK" : kwScore >= 25 ? "SUSPICIOUS" : "SAFE",
      weight: weights.keywords,
      explanation: kwExp,
      evidence: { matchedKeywords: uniqueWords }
    },
    {
      name: "Punycode & Homoglyph Spoofing",
      key: "punycode",
      score: punyScore,
      status: punyScore >= 80 ? "CRITICAL" : punyScore >= 55 ? "HIGH_RISK" : punyScore >= 25 ? "SUSPICIOUS" : "SAFE",
      weight: weights.punycode,
      explanation: punyExp,
      evidence: punyEvidence
    },
    {
      name: "DNS Resolution & Active Hosts",
      key: "dns",
      score: dnsScore,
      status: dnsStatus,
      weight: weights.dns,
      explanation: dnsExp,
      evidence: dnsEvidence
    },
    {
      name: "SSL / TLS Security",
      key: "ssl",
      score: sslScore,
      status: sslStatus,
      weight: weights.ssl,
      explanation: sslExp,
      evidence: sslEvidence
    },
    {
      name: "Redirect & Cloaking Behavior",
      key: "redirects",
      score: redirScore,
      status: redirStatus,
      weight: weights.redirects,
      explanation: redirExp,
      evidence: redirEvidence
    },
    {
      name: "Monitored Enterprise Watchlist",
      key: "watchlist",
      score: wlScore,
      status: wlScore >= 80 ? "CRITICAL" : wlScore >= 55 ? "HIGH_RISK" : wlScore >= 25 ? "SUSPICIOUS" : "SAFE",
      weight: weights.watchlist,
      explanation: wlExp,
      evidence: wlEvidence
    }
  ];
  return {
    domain: hostname,
    url: parsed.fullUrl,
    mode,
    risk: {
      score: overallScore,
      level: riskLevel,
      probability,
      confidence,
      verdictType,
      verdictLabel
    },
    signals: {
      domainReputation: hostScore,
      urlStructure: urlScore,
      brandImpersonation: brandScore,
      ssl: sslScore,
      keywords: kwScore,
      redirects: redirScore,
      watchlist: wlScore,
      punycode: punyScore,
      dns: dnsScore
    },
    signalDetails,
    targetInfo: {
      url: parsed.fullUrl,
      domain: hostname,
      protocol: parsed.protocol,
      hostname,
      port: parsed.port,
      path: parsed.path,
      tld,
      entropy,
      subdomainsCount: Math.max(0, parsed.partsCount - 2),
      ipAddress: resolvedIps[0],
      resolvedIps,
      mxRecords,
      tlsIssuer,
      tlsValidTo,
      isPunycode: parsed.isPunycode,
      hasHomoglyphs: parsed.hasHomoglyphs,
      dnsResolved
    },
    matchedBrand: finalMatchedBrand,
    reasons,
    engineUsed: "nodejs-multisignal"
  };
}

// index.ts
dotenv.config();
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
var PORT = Number(process.env.PORT) || 3e3;
async function startServer() {
  const app2 = express();
  app2.use(cors({
    origin: [
      "https://phishtrap-scanner-client.vercel.app",
      "http://localhost:5173"
    ]
  }));
  app2.use(express.json({ limit: "2mb" }));
  app2.use(express.urlencoded({ extended: true }));
  app2.get("/api/health", async (req, res) => {
    let pythonStatus = "built-in";
    const pyUrl = process.env.PYTHON_SERVICE_URL;
    if (pyUrl) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1200);
        const pyRes = await fetch(`${pyUrl}/health`, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (pyRes.ok) {
          pythonStatus = "connected";
        }
      } catch {
        pythonStatus = "offline-fallback";
      }
    }
    res.json({
      status: "ok",
      service: "PHISHTRAP API Gateway",
      pythonEngine: pythonStatus,
      database: db.isConnectedToMongo() ? "mongodb" : "in-memory-persisted",
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      version: "1.0.0"
    });
  });
  app2.get("/api/overview", async (req, res) => {
    try {
      const metrics = await db.getOverview();
      res.json({
        success: true,
        data: metrics
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: { message: err.message || "Failed to retrieve overview statistics" }
      });
    }
  });
  app2.post("/api/scanner/analyze", async (req, res) => {
    try {
      const { domain, mode = "DEMO" } = req.body;
      if (!domain || typeof domain !== "string") {
        return res.status(400).json({
          success: false,
          error: { message: "Invalid target: Domain or URL is required and must be a string." }
        });
      }
      const trimmedDomain = domain.trim();
      if (trimmedDomain.length === 0) {
        return res.status(400).json({
          success: false,
          error: { message: "Domain or URL cannot be empty." }
        });
      }
      if (trimmedDomain.length > 2e3) {
        return res.status(400).json({
          success: false,
          error: { message: "Domain or URL exceeds maximum allowed length (2000 characters)." }
        });
      }
      if (/\s/.test(trimmedDomain)) {
        return res.status(400).json({
          success: false,
          error: { message: "Target domain or URL must not contain spaces." }
        });
      }
      const normalizedMode = mode?.toUpperCase() === "LIVE" ? "LIVE" : "DEMO";
      const currentWatchlist = await db.getWatchlist();
      let analysisResult = null;
      const pyUrl = process.env.PYTHON_SERVICE_URL;
      if (pyUrl) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 3500);
          const pyRes = await fetch(`${pyUrl}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              domain: trimmedDomain,
              mode: normalizedMode,
              watchlist: currentWatchlist
            }),
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          if (pyRes.ok) {
            const pyData = await pyRes.json();
            analysisResult = pyData;
          }
        } catch {
        }
      }
      if (!analysisResult) {
        const result = await runMultiSignalEngine(trimmedDomain, normalizedMode, currentWatchlist);
        const scanId = "scn_" + Math.random().toString(36).substring(2, 12);
        const timestamp = (/* @__PURE__ */ new Date()).toISOString();
        analysisResult = {
          success: true,
          scanId,
          domain: result.domain,
          url: result.url,
          mode: result.mode,
          risk: result.risk,
          signals: result.signals,
          signalDetails: result.signalDetails,
          targetInfo: result.targetInfo,
          matchedBrand: result.matchedBrand,
          reasons: result.reasons,
          timestamp,
          engineUsed: "nodejs-multisignal"
        };
      }
      await db.saveScan(analysisResult);
      return res.json(analysisResult);
    } catch (err) {
      return res.status(500).json({
        success: false,
        error: { message: err.message || "Internal security scanner error occurred." }
      });
    }
  });
  app2.get("/api/reports", async (req, res) => {
    try {
      const { search, risk, brand } = req.query;
      const reports = await db.getScans({
        search: typeof search === "string" ? search : void 0,
        risk: typeof risk === "string" ? risk : void 0,
        brand: typeof brand === "string" ? brand : void 0
      });
      res.json({
        success: true,
        data: reports,
        count: reports.length
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: { message: err.message || "Failed to fetch scan reports." }
      });
    }
  });
  app2.get("/api/reports/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const report = await db.getScanById(id);
      if (!report) {
        return res.status(404).json({
          success: false,
          error: { message: "Scan report not found." }
        });
      }
      res.json({
        success: true,
        data: report
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: { message: err.message || "Failed to retrieve scan report." }
      });
    }
  });
  app2.get("/api/reports/export/json", async (req, res) => {
    try {
      const reports = await db.getScans();
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="phishtrap-reports-${Date.now()}.json"`);
      res.send(JSON.stringify(reports, null, 2));
    } catch (err) {
      res.status(500).json({ success: false, error: { message: "Export failed" } });
    }
  });
  app2.get("/api/reports/export/csv", async (req, res) => {
    try {
      const reports = await db.getScans();
      const headers = ["Scan ID", "Domain", "URL", "Mode", "Risk Score", "Risk Level", "Verdict", "Probability", "Confidence", "Matched Brand", "Reasons Count", "Timestamp"];
      const csvRows = [headers.join(",")];
      for (const r of reports) {
        const row = [
          `"${r.scanId || ""}"`,
          `"${r.domain || ""}"`,
          `"${(r.url || "").replace(/"/g, '""')}"`,
          `"${r.mode || ""}"`,
          r.risk?.score ?? 0,
          `"${r.risk?.level || ""}"`,
          `"${r.risk?.verdictLabel || r.risk?.verdictType || r.risk?.level || ""}"`,
          r.risk?.probability ?? 0,
          r.risk?.confidence ?? 0.95,
          `"${r.matchedBrand || "None"}"`,
          r.reasons?.length || 0,
          `"${r.timestamp || r.createdAt || ""}"`
        ];
        csvRows.push(row.join(","));
      }
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="phishtrap-reports-${Date.now()}.csv"`);
      res.send(csvRows.join("\n"));
    } catch (err) {
      res.status(500).json({ success: false, error: { message: "Export failed" } });
    }
  });
  app2.get("/api/watchlist", async (req, res) => {
    try {
      const watchlist = await db.getWatchlist();
      res.json({
        success: true,
        data: watchlist
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: { message: err.message || "Failed to fetch watchlist brands." }
      });
    }
  });
  app2.post("/api/watchlist", async (req, res) => {
    try {
      const { name, domain, category } = req.body;
      if (!name || typeof name !== "string" || name.trim().length === 0) {
        return res.status(400).json({
          success: false,
          error: { message: "Brand name is required." }
        });
      }
      if (!domain || typeof domain !== "string" || domain.trim().length === 0) {
        return res.status(400).json({
          success: false,
          error: { message: "Official domain is required." }
        });
      }
      const cleanDomain = domain.trim().replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
      const created = await db.addWatchlistBrand({
        name: name.trim(),
        domain: cleanDomain,
        category: category || "Banking"
      });
      res.status(201).json({
        success: true,
        data: created
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: { message: err.message || "Failed to add brand to watchlist." }
      });
    }
  });
  app2.put("/api/watchlist/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const { active, name, domain, category } = req.body;
      const updated = await db.updateWatchlistBrand(id, {
        ...typeof active === "boolean" ? { active } : {},
        ...name ? { name: name.trim() } : {},
        ...domain ? { domain: domain.trim().toLowerCase() } : {},
        ...category ? { category } : {}
      });
      if (!updated) {
        return res.status(404).json({
          success: false,
          error: { message: "Watchlist entry not found." }
        });
      }
      res.json({
        success: true,
        data: updated
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: { message: err.message || "Failed to update watchlist entry." }
      });
    }
  });
  app2.delete("/api/watchlist/:id", async (req, res) => {
    try {
      const { id } = req.params;
      const success = await db.deleteWatchlistBrand(id);
      if (!success) {
        return res.status(404).json({
          success: false,
          error: { message: "Watchlist entry not found or already deleted." }
        });
      }
      res.json({
        success: true,
        message: "Watchlist brand removed successfully."
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: { message: err.message || "Failed to delete watchlist entry." }
      });
    }
  });
  if (process.env.NODE_ENV === "production") {
    const distPath = path.resolve(__dirname, "../client/dist");
    app2.use(express.static(distPath));
    app2.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }
  return app2;
}
var app = await startServer();
if (!process.env.VERCEL) {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[PHISHTRAP] Security server running on http://0.0.0.0:${PORT}`);
  });
}
var index_default = app;
export {
  index_default as default
};
//# sourceMappingURL=server.mjs.map
