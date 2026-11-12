"""System Diagnostics, Health, Audit Logs & GitHub Update Routes."""

from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional

from backup_service.web.routes.auth_routes import require_auth, require_admin
from backup_service.core.updater import GitHubUpdater

router = APIRouter(tags=["System & Operations"])


@router.get("/")
async def dashboard_page(request: Request, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    clients = db.list_clients()
    recent_jobs = db.list_backup_jobs(limit=10)
    restore_jobs = db.list_restore_jobs(limit=5)
    storage_configs = db.list_storage_configs()

    # Calculate metrics
    total_clients = len(clients)
    successful_jobs = sum(1 for j in recent_jobs if j["status"] == "success")
    total_volume_bytes = sum(j.get("total_bytes", 0) for j in recent_jobs)

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "clients": clients,
            "recent_jobs": recent_jobs,
            "restore_jobs": restore_jobs,
            "storage_configs": storage_configs,
            "total_clients": total_clients,
            "successful_jobs": successful_jobs,
            "total_volume_bytes": total_volume_bytes,
            "active_tab": "dashboard"
        }
    )


@router.get("/system")
async def system_page(request: Request, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    updater = GitHubUpdater()
    version_info = updater.check_for_updates()

    with db.connection() as conn:
        audit_rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50"
        ).fetchall()
        audit_logs = [dict(r) for r in audit_rows]

    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="system.html",
        context={
            "user": user,
            "version_info": version_info,
            "audit_logs": audit_logs,
            "active_tab": "system"
        }
    )


@router.get("/api/v1/system/health")
async def health_check(request: Request):
    """System health check endpoint for monitoring."""
    db = request.app.state.db_manager
    try:
        with db.connection() as conn:
            conn.execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "status": "HEALTHY" if db_ok else "UNHEALTHY",
        "database_connected": db_ok,
        "scheduler_running": request.app.state.scheduler.scheduler.running if hasattr(request.app.state, "scheduler") else False
    }


@router.get("/api/v1/system/check-update")
async def check_update_api(user: dict = Depends(require_auth)):
    updater = GitHubUpdater()
    return updater.check_for_updates()


@router.post("/api/v1/system/update")
async def trigger_update_api(request: Request, user: dict = Depends(require_admin)):
    updater = GitHubUpdater()
    result = updater.perform_git_pull()
    request.app.state.audit_logger.log(
        action="SYSTEM_GIT_UPDATE",
        user_id=user["id"],
        username=user["username"],
        status="SUCCESS" if result.get("success") else "FAILED",
        details=result
    )
    return result


@router.get("/branding")
@router.get("/about")
async def branding_page(request: Request):
    """Public Google OAuth Branding & Disclosure Page for Google Cloud Console Verification."""
    templates = request.app.state.templates
    return templates.TemplateResponse(request=request, name="branding.html", context={})


@router.get("/privacy")
async def privacy_page():
    """Public Privacy Policy redirect for Google OAuth verification."""
    return RedirectResponse(url="/branding#privacy", status_code=303)


@router.get("/terms")
async def terms_page():
    """Public Terms of Service redirect for Google OAuth verification."""
    return RedirectResponse(url="/branding#terms", status_code=303)
