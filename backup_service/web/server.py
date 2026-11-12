"""Enterprise Backup & Disaster Recovery Web Server.

Adheres strictly to OWASP Security Principles:
- Anti-Clickjacking headers (X-Frame-Options)
- MIME Sniffing protection (X-Content-Type-Options)
- Content Security Policy (CSP)
- Role-Based Access Control on every API and UI route
"""

import os
import argparse
import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from backup_service.security.vault import CredentialVault, get_or_create_master_secret
from backup_service.security.db import DatabaseManager
from backup_service.security.audit import AuditLogger
from backup_service.core.scheduler import BackupScheduler
from backup_service.storage.local_storage import LocalStorageProvider

from backup_service.web.routes import (
    auth_routes, client_routes, storage_routes, explorer_routes,
    backup_routes, restore_routes, system_routes
)

from urllib.parse import urlparse

logger = logging.getLogger("backup_service.web")
WEB_DIR = Path(__file__).parent.resolve()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """OWASP Compliant Security Headers Injection Middleware."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        response.headers["Server"] = "TechLIMS-Security-Gateway"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "img-src 'self' data: https:; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none';"
        )

        # Anti-Caching for sensitive APIs and Authentication endpoints (CWE-524)
        path = request.url.path
        if path.startswith("/api/") or path in ("/login", "/logout"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"

        return response


class CSRFOriginMiddleware(BaseHTTPMiddleware):
    """OWASP Anti-CSRF Origin and Referer Header Verification Middleware.
    
    Validates that state-mutating requests (POST, PUT, DELETE, PATCH) originate
    from the genuine application host and not third-party malicious sites.
    """

    MUTATING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    async def dispatch(self, request: Request, call_next):
        if request.method in self.MUTATING_METHODS:
            host_header = request.headers.get("host", "").split(":")[0].lower()
            origin = request.headers.get("origin")
            referer = request.headers.get("referer")

            if origin:
                origin_host = urlparse(origin).hostname
                if origin_host and origin_host.lower() != host_header:
                    # Allow localhost <-> 127.0.0.1 interchangeability in development
                    if not (host_header in ("127.0.0.1", "localhost") and origin_host in ("127.0.0.1", "localhost")):
                        logger.warning(
                            "CSRF Origin mismatch blocked: Origin=%s, Host=%s from %s",
                            origin, host_header, request.client.host if request.client else "unknown"
                        )
                        return Response(
                            content='{"detail": "CSRF validation failed: Origin header mismatch"}',
                            status_code=403,
                            media_type="application/json"
                        )
            elif referer:
                referer_host = urlparse(referer).hostname
                if referer_host and referer_host.lower() != host_header:
                    if not (host_header in ("127.0.0.1", "localhost") and referer_host in ("127.0.0.1", "localhost")):
                        logger.warning(
                            "CSRF Referer mismatch blocked: Referer=%s, Host=%s from %s",
                            referer, host_header, request.client.host if request.client else "unknown"
                        )
                        return Response(
                            content='{"detail": "CSRF validation failed: Referer header mismatch"}',
                            status_code=403,
                            media_type="application/json"
                        )

        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown lifecycle."""
    logger.info("Initializing Enterprise Backup Web Service...")
    # Initialize Core Security & State Subsystems
    app.state.master_secret = get_or_create_master_secret()
    app.state.vault = CredentialVault(app.state.master_secret)
    app.state.db_manager = DatabaseManager(os.environ.get("METADATA_DB_PATH", "./metadata.sqlite"))
    app.state.audit_logger = AuditLogger(app.state.db_manager)
    app.state.default_storage_provider = LocalStorageProvider("./local_cloud_backup")

    # Start Background Scheduler
    def _scheduled_backup_callback(client_db_id: int):
        backup_routes._execute_backup_task(app.state, client_db_id, trigger_type="scheduled")

    app.state.scheduler = BackupScheduler(app.state.db_manager, _scheduled_backup_callback)
    app.state.scheduler.start()

    yield

    logger.info("Shutting down background workers...")
    app.state.scheduler.shutdown()


def create_app() -> FastAPI:
    """FastAPI Application Factory."""
    app = FastAPI(
        title="Enterprise Backup & Disaster Recovery Management Platform",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan
    )

    # Mount Middleware
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CSRFOriginMiddleware)

    # Static Assets & Templates
    static_dir = WEB_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    templates_dir = WEB_DIR / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.state.templates = Jinja2Templates(directory=str(templates_dir))

    from fastapi.responses import FileResponse
    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon_route():
        fav_path = static_dir / "favicon.ico"
        if fav_path.is_file():
            return FileResponse(fav_path)
        return Response(status_code=404)

    # Register Routers
    app.include_router(auth_routes.router)
    app.include_router(client_routes.router)
    app.include_router(storage_routes.router)
    app.include_router(explorer_routes.router)
    app.include_router(backup_routes.router)
    app.include_router(restore_routes.router)
    app.include_router(system_routes.router)

    return app


app = create_app()


def main():
    parser = argparse.ArgumentParser(description="Start Enterprise Backup Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for dev")
    args = parser.parse_args()

    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    print(f"\n[+] Starting Enterprise Backup Management Console on http://{args.host}:{args.port}")
    uvicorn.run("backup_service.web.server:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
