# PHISHTRAP — Multi-Signal Phishing Detection Engine

Production-quality cybersecurity platform analyzing URLs and domains across
multiple intelligence signals to detect phishing attacks in real time.

The project is split into two independent apps:

```
phishtrap/
├── client/              React + Vite frontend
│   ├── index.html
│   ├── src/
│   │   ├── components/  UI components
│   │   ├── context/     ThemeContext
│   │   ├── services/    api.ts — calls the server's /api routes
│   │   ├── types.ts
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── vite.config.ts   dev-server proxies /api → server (localhost:3000)
│   ├── tsconfig.json
│   └── package.json
│
├── server/              Express + TypeScript API
│   ├── src/
│   │   ├── index.ts     Express app / all /api routes (entry point)
│   │   ├── db.ts        Mongo-backed / in-memory persistence
│   │   └── engine.ts    Built-in Node multi-signal detection engine
│   ├── python/          Optional FastAPI microservice (drop-in alternative engine)
│   │   ├── main.py
│   │   ├── engine.py
│   │   └── requirements.txt
│   ├── tsconfig.json
│   ├── .env.example
│   └── package.json
│
└── package.json         Root workspace orchestrator (npm workspaces)
```

## Run Locally

**Prerequisites:** Node.js 18+ (Python 3.10+ only if you want the optional FastAPI engine).

1. Install all dependencies (root + both workspaces):
   ```
   npm install
   ```
2. Copy the server env file and fill in any values you need:
   ```
   cp server/.env.example server/.env
   ```
3. Start both apps together (server on :3000, client on :5173, with `/api`
   auto-proxied from client → server):
   ```
   npm run dev
   ```
   Or run them separately in two terminals:
   ```
   npm run dev:server
   npm run dev:client
   ```
4. Open the client at http://localhost:5173

### Optional: Python microservice

The Node server automatically falls back to its built-in TypeScript engine.
To use the FastAPI microservice instead:

```
cd server/python
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then set `PYTHON_SERVICE_URL=http://127.0.0.1:8000` in `server/.env`.

## Production build

```
npm run build   # builds client/dist, then bundles server/dist/server.mjs
npm start       # NODE_ENV=production node server, serving client/dist statically
```
