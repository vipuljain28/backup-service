"""Disaster Recovery & Point-in-Time Restore Routes."""

import json
from fastapi import APIRouter, Request, Depends, HTTPException, Form, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional

from backup_service.web.routes.auth_routes import require_auth
from backup_service.security.auth import Role
from backup_service.core.restore import RestorationEngine
from backup_service.core.reconnect import ArchiveReconnector
from backup_service.storage.factory import StorageProviderFactory
from backup_service.config.settings import SSHConfig

router = APIRouter(tags=["Disaster Recovery & Restore"])


def _execute_restore_worker(
    app_state,
    restore_job_id: int,
    client_id_slug: str,
    snapshot_date: str,
    target_mode: str,
    target_ssh_cfg: Optional[SSHConfig],
    target_path: Optional[str],
    target_db_name: Optional[str],
    target_db_engine: Optional[str],
    target_db_host: Optional[str],
    target_db_port: Optional[int],
    target_db_user: Optional[str],
    target_db_pass: Optional[str],
    restore_scope: str
):
    """Background worker executing point-in-time restore."""
    db = app_state.db_manager
    storage = app_state.default_storage_provider
    engine = RestorationEngine(storage)

    result = engine.execute_restore(
        client_id=client_id_slug,
        snapshot_date=snapshot_date,
        target_mode=target_mode,
        target_ssh_config=target_ssh_cfg,
        target_file_directory=target_path,
        target_database_engine=target_db_engine,
        target_database_host=target_db_host,
        target_database_port=target_db_port,
        target_database_user=target_db_user,
        target_database_password=target_db_pass,
        target_database_name=target_db_name,
        restore_scope=restore_scope
    )

    db.update_restore_job(
        job_id=restore_job_id,
        status="success" if result["status"] == "SUCCESS" else "failed",
        logs=result.get("logs", "")
    )


@router.get("/restores")
async def restores_page(request: Request, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    restore_jobs = db.list_restore_jobs(limit=30)
    backup_jobs = db.list_backup_jobs(limit=50)
    clients = db.list_clients()
    storage_configs = db.list_storage_configs()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="restore.html",
        context={
            "user": user,
            "restore_jobs": restore_jobs,
            "backup_jobs": backup_jobs,
            "clients": clients,
            "storage_configs": storage_configs,
            "active_tab": "restore"
        }
    )


@router.post("/restores/trigger")
async def trigger_restore(
    request: Request,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_auth),
    backup_job_id: int = Form(...),
    target_location_type: str = Form("original"), # "original" or "new"
    target_server_id: Optional[int] = Form(None),
    target_path: Optional[str] = Form(""),
    target_db_name: Optional[str] = Form(""),
    restore_scope: str = Form("all")
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    vault = request.app.state.vault

    with db.connection() as conn:
        job = conn.execute("SELECT * FROM backup_jobs WHERE id = ?", (backup_job_id,)).fetchone()
        if not job:
            raise HTTPException(status_code=404, detail="Backup snapshot not found")
        client = conn.execute("SELECT * FROM clients WHERE id = ?", (job["client_id"],)).fetchone()

    client_id_slug = client["client_id"]
    snapshot_date = job["run_date"]

    # Resolve target server parameters
    target_mode = "local"
    target_ssh_cfg = None

    if target_server_id:
        with db.connection() as conn:
            srv = conn.execute("SELECT * FROM server_connections WHERE id = ?", (target_server_id,)).fetchone()
            if srv and srv["mode"] == "ssh":
                target_mode = "ssh"
                secret = vault.decrypt(srv["encrypted_secret"]) if srv["encrypted_secret"] else None
                target_ssh_cfg = SSHConfig(
                    host=srv["host"],
                    port=srv["port"] or 22,
                    user=srv["username"],
                    key_path=secret if srv["auth_type"] != "password" else None,
                    password=secret if srv["auth_type"] == "password" else None
                )

    restore_job_id = db.record_restore_job(
        backup_job_id=backup_job_id,
        client_id=client["id"],
        target_server_id=target_server_id,
        target_path=target_path,
        target_db_name=target_db_name,
        restore_scope=restore_scope
    )

    background_tasks.add_task(
        _execute_restore_worker,
        request.app.state,
        restore_job_id,
        client_id_slug,
        snapshot_date,
        target_mode,
        target_ssh_cfg,
        target_path,
        target_db_name,
        "mysql",
        "127.0.0.1",
        3306,
        "root",
        None,
        restore_scope
    )

    request.app.state.audit_logger.log(
        action="TRIGGER_RESTORE",
        user_id=user["id"],
        username=user["username"],
        resource_type="restore_job",
        resource_id=str(restore_job_id),
        details={"client_id": client_id_slug, "date": snapshot_date, "scope": restore_scope}
    )
    return RedirectResponse(url="/restores", status_code=303)


@router.post("/restores/reconnect")
async def reconnect_existing_storage(
    request: Request,
    user: dict = Depends(require_auth),
    storage_config_id: int = Form(...)
):
    """Scan existing backup folder and reconstitute past backup archives."""
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    vault = request.app.state.vault

    storage_row = db.get_storage_config(storage_config_id)
    if not storage_row:
        raise HTTPException(status_code=404, detail="Storage configuration not found")

    creds_json = vault.decrypt(storage_row["encrypted_credentials"])
    credentials = json.loads(creds_json)

    provider = StorageProviderFactory.create_provider(storage_row["provider_type"], credentials)
    reconnector = ArchiveReconnector(provider, db)

    report = reconnector.scan_and_reconnect(storage_config_id)

    request.app.state.audit_logger.log(
        action="RECONNECT_EXISTING_STORAGE",
        user_id=user["id"],
        username=user["username"],
        resource_type="storage_config",
        resource_id=str(storage_config_id),
        details=report
    )
    return RedirectResponse(url="/restores", status_code=303)
