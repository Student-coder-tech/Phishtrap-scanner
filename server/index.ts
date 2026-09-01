import express, { Request, Response } from 'express';
import cors from 'cors';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { db } from './src/db';
import { runMultiSignalEngine } from './src/engine';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT) || 3000;

async function startServer() {
  const app = express();

  // Standard middleware
  const configuredOrigins = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  const allowedOrigins = new Set([
    'https://phishtrap-scanner-client.vercel.app',
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    ...configuredOrigins,
  ]);

  app.use(cors({
    origin: (origin, callback) => {
      // Non-browser requests and same-origin browser requests do not send an Origin header.
      if (!origin || allowedOrigins.has(origin)) {
        callback(null, true);
        return;
      }
      callback(null, false);
    },
  }));
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true }));

  // ----------------------------------------------------
  // API ROUTES
  // ----------------------------------------------------

  // 1. Health check
  app.get('/api/health', async (req: Request, res: Response) => {
    let pythonStatus = 'built-in';
    const pyUrl = process.env.PYTHON_SERVICE_URL;

    if (pyUrl) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1200);
        const pyRes = await fetch(`${pyUrl}/health`, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (pyRes.ok) {
          pythonStatus = 'connected';
        }
      } catch {
        pythonStatus = 'offline';
      }
    }

    res.json({
      status: 'ok',
      service: 'PHISHTRAP API Gateway',
      pythonEngine: pythonStatus,
      database: db.isConnectedToMongo() ? 'mongodb' : 'in-memory-persisted',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    });
  });

  // 2. Overview metrics
  app.get('/api/overview', async (req: Request, res: Response) => {
    try {
      const metrics = await db.getOverview();
      res.json({
        success: true,
        data: metrics,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: { message: err.message || 'Failed to retrieve overview statistics' },
      });
    }
  });

  // 3. Scanner analyze
  app.post('/api/scanner/analyze', async (req: Request, res: Response) => {
    try {
      const { domain, mode = 'DEMO' } = req.body;

      // Validation
      if (!domain || typeof domain !== 'string') {
        return res.status(400).json({
          success: false,
          error: { message: 'Invalid target: Domain or URL is required and must be a string.' },
        });
      }

      const trimmedDomain = domain.trim();
      if (trimmedDomain.length === 0) {
        return res.status(400).json({
          success: false,
          error: { message: 'Domain or URL cannot be empty.' },
        });
      }

      if (trimmedDomain.length > 2000) {
        return res.status(400).json({
          success: false,
          error: { message: 'Domain or URL exceeds maximum allowed length (2000 characters).' },
        });
      }

      if (/\s/.test(trimmedDomain)) {
        return res.status(400).json({
          success: false,
          error: { message: 'Target domain or URL must not contain spaces.' },
        });
      }

      const normalizedMode = mode?.toUpperCase() === 'LIVE' ? 'LIVE' : 'DEMO';
      const normalizedTarget = /^https?:\/\//i.test(trimmedDomain)
        ? trimmedDomain
        : `https://${trimmedDomain}`;

      try {
        const targetUrl = new URL(normalizedTarget);
        if (!targetUrl.hostname || !['http:', 'https:'].includes(targetUrl.protocol)) {
          throw new Error('Unsupported URL protocol');
        }
      } catch {
        return res.status(400).json({
          success: false,
          error: { message: 'Invalid target: provide a valid domain or an HTTP(S) URL.' },
        });
      }

      // Retrieve active watchlist for cross-referencing
      const currentWatchlist = await db.getWatchlist();

      let analysisResult: any = null;
      const pyUrl = process.env.PYTHON_SERVICE_URL;

      // Attempt FastAPI microservice if configured
      if (pyUrl) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 3500);
          const pyRes = await fetch(`${pyUrl}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              domain: normalizedTarget,
              mode: normalizedMode,
              watchlist: currentWatchlist,
            }),
            signal: controller.signal,
          });
          clearTimeout(timeoutId);

          if (pyRes.ok) {
            const pyData = await pyRes.json();
            analysisResult = pyData;
          }
        } catch {
          // Fallback to built-in TypeScript engine seamlessly
        }
      }

      // If python service wasn't used or failed, run built-in node engine
      if (!analysisResult) {
        const result = await runMultiSignalEngine(normalizedTarget, normalizedMode, currentWatchlist);
        const scanId = 'scn_' + Math.random().toString(36).substring(2, 12);
        const timestamp = new Date().toISOString();

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
          engineUsed: 'nodejs-multisignal',
        };
      }

      // Persist scan report to store
      await db.saveScan(analysisResult);

      return res.json(analysisResult);
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        error: { message: err.message || 'Internal security scanner error occurred.' },
      });
    }
  });

  // 4. Reports list with query filters
  app.get('/api/reports', async (req: Request, res: Response) => {
    try {
      const { search, risk, brand } = req.query;
      const reports = await db.getScans({
        search: typeof search === 'string' ? search : undefined,
        risk: typeof risk === 'string' ? risk : undefined,
        brand: typeof brand === 'string' ? brand : undefined,
      });

      res.json({
        success: true,
        data: reports,
        count: reports.length,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: { message: err.message || 'Failed to fetch scan reports.' },
      });
    }
  });

  // 4.1 Single report by ID
  app.get('/api/reports/:id', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const report = await db.getScanById(id);
      if (!report) {
        return res.status(404).json({
          success: false,
          error: { message: 'Scan report not found.' },
        });
      }
      res.json({
        success: true,
        data: report,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: { message: err.message || 'Failed to retrieve scan report.' },
      });
    }
  });

  // 5. Export JSON
  app.get('/api/reports/export/json', async (req: Request, res: Response) => {
    try {
      const reports = await db.getScans();
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="phishtrap-reports-${Date.now()}.json"`);
      res.send(JSON.stringify(reports, null, 2));
    } catch (err: any) {
      res.status(500).json({ success: false, error: { message: 'Export failed' } });
    }
  });

  // 6. Export CSV
  app.get('/api/reports/export/csv', async (req: Request, res: Response) => {
    try {
      const reports = await db.getScans();
      const headers = ['Scan ID', 'Domain', 'URL', 'Mode', 'Risk Score', 'Risk Level', 'Verdict', 'Probability', 'Confidence', 'Matched Brand', 'Reasons Count', 'Timestamp'];

      const csvRows = [headers.join(',')];
      for (const r of reports) {
        const row = [
          `"${r.scanId || ''}"`,
          `"${r.domain || ''}"`,
          `"${(r.url || '').replace(/"/g, '""')}"`,
          `"${r.mode || ''}"`,
          r.risk?.score ?? 0,
          `"${r.risk?.level || ''}"`,
          `"${r.risk?.verdictLabel || r.risk?.verdictType || r.risk?.level || ''}"`,
          r.risk?.probability ?? 0,
          r.risk?.confidence ?? 0.95,
          `"${r.matchedBrand || 'None'}"`,
          r.reasons?.length || 0,
          `"${r.timestamp || r.createdAt || ''}"`,
        ];
        csvRows.push(row.join(','));
      }

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="phishtrap-reports-${Date.now()}.csv"`);
      res.send(csvRows.join('\n'));
    } catch (err: any) {
      res.status(500).json({ success: false, error: { message: 'Export failed' } });
    }
  });

  // 7. Watchlist: GET
  app.get('/api/watchlist', async (req: Request, res: Response) => {
    try {
      const watchlist = await db.getWatchlist();
      res.json({
        success: true,
        data: watchlist,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: { message: err.message || 'Failed to fetch watchlist brands.' },
      });
    }
  });

  // 8. Watchlist: POST
  app.post('/api/watchlist', async (req: Request, res: Response) => {
    try {
      const { name, domain, category } = req.body;

      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          success: false,
          error: { message: 'Brand name is required.' },
        });
      }

      if (!domain || typeof domain !== 'string' || domain.trim().length === 0) {
        return res.status(400).json({
          success: false,
          error: { message: 'Official domain is required.' },
        });
      }

      const cleanDomain = domain.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();

      const created = await db.addWatchlistBrand({
        name: name.trim(),
        domain: cleanDomain,
        category: category || 'Banking',
      });

      res.status(201).json({
        success: true,
        data: created,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: { message: err.message || 'Failed to add brand to watchlist.' },
      });
    }
  });

  // 9. Watchlist: PUT (toggle active / update)
  app.put('/api/watchlist/:id', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const { active, name, domain, category } = req.body;

      const updated = await db.updateWatchlistBrand(id, {
        ...(typeof active === 'boolean' ? { active } : {}),
        ...(name ? { name: name.trim() } : {}),
        ...(domain ? { domain: domain.trim().replace(/^https?:\/\//i, '').split('/')[0].toLowerCase() } : {}),
        ...(category ? { category } : {}),
      });

      if (!updated) {
        return res.status(404).json({
          success: false,
          error: { message: 'Watchlist entry not found.' },
        });
      }

      res.json({
        success: true,
        data: updated,
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: { message: err.message || 'Failed to update watchlist entry.' },
      });
    }
  });

  // 10. Watchlist: DELETE
  app.delete('/api/watchlist/:id', async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const success = await db.deleteWatchlistBrand(id);

      if (!success) {
        return res.status(404).json({
          success: false,
          error: { message: 'Watchlist entry not found or already deleted.' },
        });
      }

      res.json({
        success: true,
        message: 'Watchlist brand removed successfully.',
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: { message: err.message || 'Failed to delete watchlist entry.' },
      });
    }
  });

  // ----------------------------------------------------
  // Static serving of the built client (production only)
  // In development, run the client's own Vite dev server
  // separately (see client/vite.config.ts) — it proxies
  // /api requests to this server.
  // ----------------------------------------------------
  if (process.env.NODE_ENV === 'production') {
    const candidateDistPaths = [
      path.resolve(__dirname, '../../client/dist'),
      path.resolve(__dirname, '../client/dist'),
    ];
    const distPath = candidateDistPaths.find((candidate) => existsSync(candidate)) || candidateDistPaths[0];
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  return app;
}

const app = await startServer();

// Only listen when running directly (not on Vercel)
if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PHISHTRAP] Security server running on http://0.0.0.0:${PORT}`);
  });
}

export default app;
