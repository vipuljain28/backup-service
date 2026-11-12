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
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "img-src 'self' data: https:;"
        )
        return response


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

    # Static Assets & Templates
    static_dir = WEB_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    templates_dir = WEB_DIR / "templates"
    templates_dir.mkdir(parents=True, exist_ok=True)

    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    app.state.templates = Jinja2Templates(directory=str(templates_dir))

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
