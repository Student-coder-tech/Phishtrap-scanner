"""
PHISHTRAP — Python Microservice Entry Point
Provides high-performance REST APIs for multi-signal phishing detection.
Includes FastAPI app with fallback to built-in Python http.server for zero-dependency execution.
"""

import sys
import os
import json
import uuid
from datetime import datetime, timezone

# Ensure local engine module can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from engine import analyze_phishing_target
except ImportError:
    from server.python.engine import analyze_phishing_target

# Try importing FastAPI & Pydantic
try:
    from fastapi import FastAPI, HTTPException, status, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field

    app = FastAPI(
        title="PHISHTRAP Phishing Analysis Microservice",
        description="Multi-signal cybersecurity intelligence engine analyzing domains and URLs for phishing threats.",
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health_check():
        return {
            "status": "ok",
            "service": "PHISHTRAP Python Engine",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @app.post("/analyze")
    async def analyze_endpoint(request: Request):
        try:
            body = await request.json()
            domain = body.get("domain", "").strip()
            mode = body.get("mode", "DEMO")
            watchlist = body.get("watchlist", [])

            if not domain:
                raise HTTPException(status_code=400, detail="Target domain or URL is required.")

            result = analyze_phishing_target(domain, mode, watchlist)
            result["scanId"] = "scn_" + uuid.uuid4().hex[:12]
            result["timestamp"] = datetime.now(timezone.utc).isoformat()
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Phishing analysis error: {str(e)}")

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    app = None

# Built-in Standard Library HTTP Server for zero-dependency standalone execution
def run_builtin_server(port=8000):
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class PhishtrapHandler(BaseHTTPRequestHandler):
        def _send_cors_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

        def do_OPTIONS(self):
            self.send_response(204)
            self._send_cors_headers()
            self.end_headers()

        def do_GET(self):
            if self.path == "/health" or self.path == "/api/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                res = {
                    "status": "ok",
                    "service": "PHISHTRAP Python Engine (Built-in)",
                    "version": "1.0.0",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                self.wfile.write(json.dumps(res).encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path == "/analyze" or self.path == "/api/scanner/analyze":
                content_len = int(self.headers.get("Content-Length", 0))
                post_body = self.rfile.read(content_len)
                try:
                    data = json.loads(post_body.decode("utf-8"))
                    domain = data.get("domain", "").strip()
                    mode = data.get("mode", "DEMO")
                    watchlist = data.get("watchlist", [])

                    if not domain:
                        self.send_response(400)
                        self.send_header("Content-Type", "application/json")
                        self._send_cors_headers()
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "domain is required"}).encode("utf-8"))
                        return

                    result = analyze_phishing_target(domain, mode, watchlist)
                    result["scanId"] = "scn_" + uuid.uuid4().hex[:12]
                    result["timestamp"] = datetime.now(timezone.utc).isoformat()

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps(result).encode("utf-8"))
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self._send_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

    server = HTTPServer(("127.0.0.1", port), PhishtrapHandler)
    print(f"[PHISHTRAP Python] Microservice running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    if HAS_FASTAPI:
        try:
            import uvicorn
            uvicorn.run(app, host="127.0.0.1", port=8000)
        except Exception:
            run_builtin_server(8000)
    else:
        run_builtin_server(8000)
