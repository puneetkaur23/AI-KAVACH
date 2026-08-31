"""
api/main.py — AI Kavach CRS REST API Server.

Provides a FastAPI backend for the AI Kavach Cyber-Reasoning System.
This is a thin layer over the existing CLI pipeline — no security
logic is duplicated here.

Usage:
    py -3 -m api.main                          # Default: localhost:8000
    py -3 -m api.main --host 0.0.0.0 --port 9000

Environment:
    KAVACH_API_HOST       API bind host (default: 127.0.0.1)
    KAVACH_API_PORT       API bind port (default: 8000)
    KAVACH_CORS_ORIGINS   Comma-separated allowed origins (default: http://localhost:3000,http://localhost:5173)
"""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

# Ensure project root is on Python path
_project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, _project_root)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import health, targets, scans, findings
from api.services.scan_service import ScanService

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("kavach.api")

# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    log.info("🛡️  AI Kavach API starting up...")

    # Initialize scan service and inject into routes
    scan_service = ScanService()
    scans.set_scan_service(scan_service)

    # Ensure output directories exist
    os.makedirs("output/reports", exist_ok=True)

    log.info("✓ Scan service initialized")
    yield
    log.info("AI Kavach API shutting down...")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Kavach — Cyber-Reasoning System API",
    description=(
        "REST API for autonomous vulnerability discovery, root-cause reasoning, "
        "evidence-based classification, patch generation, and proof-of-fix reporting."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

_cors_origins_str = os.getenv(
    "KAVACH_CORS_ORIGINS",
    "http://localhost:3000,http://localhost:5173,http://localhost:8080,http://127.0.0.1:3000,http://127.0.0.1:5173,http://127.0.0.1:8080,http://localhost:8000,http://127.0.0.1:8000"
)
_cors_origins = [o.strip() for o in _cors_origins_str.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all to return structured errors, never bare 500s."""
    log.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "details": {"exception": str(exc)},
            }
        },
    )

# ---------------------------------------------------------------------------
# Mount routes
# ---------------------------------------------------------------------------

app.include_router(health.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)


@app.get("/", tags=["System"])
async def root(request: Request):
    """
    API root — serves AI Kavach Frontend UI for browsers/default requests,
    or returns API metadata JSON for explicit JSON API clients.
    """
    accept = request.headers.get("accept", "")
    # If explicitly requesting JSON without HTML, return API metadata
    if "application/json" in accept and "text/html" not in accept:
        return {
            "name": "AI Kavach CRS API",
            "version": "1.0.0",
            "ui": "/",
            "docs": "/docs",
            "health": "/health",
            "endpoints": {
                "targets": "/api/v1/targets",
                "scans": "/api/v1/scans",
                "findings": "/api/v1/findings/{id}",
            },
        }

    # Serve the frontend terminal HTML
    ui_index = os.path.join(_project_root, "frontend", "index.html")
    if os.path.isfile(ui_index):
        with open(ui_index, "r", encoding="utf-8") as f:
            from fastapi.responses import HTMLResponse
            return HTMLResponse(content=f.read())

    return {
        "name": "AI Kavach CRS API",
        "version": "1.0.0",
        "ui": "/ui",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "targets": "/api/v1/targets",
            "scans": "/api/v1/scans",
            "findings": "/api/v1/findings/{id}",
        },
    }


# Mount static UI at /ui as well for convenience
from fastapi.staticfiles import StaticFiles
_frontend_dir = os.path.join(_project_root, "frontend")
if os.path.isdir(_frontend_dir):
    app.mount("/ui", StaticFiles(directory=_frontend_dir, html=True), name="ui")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """Run the API server."""
    import uvicorn

    host = os.getenv("KAVACH_API_HOST", "127.0.0.1")
    port = int(os.getenv("KAVACH_API_PORT", "8000"))

    log.info("Starting AI Kavach API on %s:%d", host, port)
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
