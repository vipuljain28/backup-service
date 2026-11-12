"""Backup Execution, Scheduling & Monitoring Routes."""

import json
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Depends, HTTPException, Form, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse, PlainTextResponse
from typing import Optional

from backup_service.web.routes.auth_routes import require_auth
from backup_service.security.auth import Role
from backup_service.config.settings import (
    AppConfig, ClientConfig, DatabaseConfig, FileSourceConfig, SSHConfig
)
from backup_service.core.orchestrator import BackupOrchestrator

router = APIRouter(tags=["Backup Operations"])


def _execute_backup_task(app_state, client_id_num: int, trigger_type: str = "manual", dry_run: bool = False):
    """Background worker executing backup workflow."""
    db = app_state.db_manager
    vault = app_state.vault
    client_data = db.get_client(client_id_num)
    if not client_data:
        return

    # Build ClientConfig
    databases = []
    for db_row in client_data.get("databases", []):
        decrypted_pwd = vault.decrypt(db_row["encrypted_password"]) if db_row.get("encrypted_password") else None
        dump_opts = json.loads(db_row.get("dump_options") or "[]")
        databases.append(DatabaseConfig(
            name=db_row["name"],
            engine=db_row["engine"],
            host=db_row["host"],
            port=db_row["port"],
            user=db_row["username"],
            password=decrypted_pwd,
            db_name=db_row["db_name"],
            dump_options=dump_opts or ["--single-transaction", "--quick"]
        ))

    file_sources = []
    for f_row in client_data.get("folders", []):
        patterns = json.loads(f_row.get("exclude_patterns") or "[]")
        file_sources.append(FileSourceConfig(
            id=f_row["source_slug"],
            path=f_row["absolute_path"],
            exclude_patterns=patterns
        ))

    # Determine connection mode & SSH config
    conn_mode = "local"
    ssh_cfg = None
    servers = client_data.get("servers", [])
    if servers:
        srv = servers[0]
        if srv["mode"] == "ssh":
            conn_mode = "ssh"
            decrypted_secret = vault.decrypt(srv["encrypted_secret"]) if srv.get("encrypted_secret") else None
            key_path = decrypted_secret if srv["auth_type"] != "password" else None
            password = decrypted_secret if srv["auth_type"] == "password" else None
            ssh_cfg = SSHConfig(
                host=srv["host"],
                port=srv["port"] or 22,
                user=srv["username"],
                key_path=key_path,
                password=password
            )

    client_cfg = ClientConfig(
        client_id=client_data["client_id"],
        display_name=client_data["display_name"],
        connection_mode=conn_mode,
        ssh=ssh_cfg,
        databases=databases,
        file_sources=file_sources,
        retention_days=client_data.get("retention_days", 10)
    )

    # Resolve storage provider
    storage_type = "local"
    if client_data.get("storage_config_id"):
        storage_row = db.get_storage_config(client_data["storage_config_id"])
        if storage_row:
            storage_type = storage_row["provider_type"]

    app_cfg = AppConfig(
        storage_provider="local" if storage_type == "local" else "gdrive",
        clients=[client_cfg]
    )

    orchestrator = BackupOrchestrator(app_cfg)

    # Initial record in backup_jobs
    now_utc = datetime.now(timezone.utc)
    job_id = db.record_backup_job(
        client_id=client_id_num,
        trigger_type=trigger_type,
        status="running",
        run_date=now_utc.strftime("%Y-%m-%d"),
        run_timestamp=now_utc.strftime("%Y-%m-%d %H:%M:%S")
    )

    try:
        report = orchestrator.run_backup_for_client(client_cfg, dry_run=dry_run)
        with db.connection() as conn:
            conn.execute(
                """
                UPDATE backup_jobs SET
                    status = 'success',
                    files_added = ?,
                    files_updated = ?,
                    files_deleted = ?,
                    dbs_dumped = ?,
                    total_bytes = ?,
                    duration_seconds = ?,
                    manifest_json = ?
                WHERE id = ?
                """,
                (
                    report.added_count,
                    report.updated_count,
                    report.deleted_count,
                    len(report.databases),
                    report.total_incremental_bytes,
                    report.duration_seconds,
                    json.dumps(report.generate_json()),
                    job_id
                )
            )
    except Exception as exc:
        with db.connection() as conn:
            conn.execute(
                "UPDATE backup_jobs SET status = 'failed', error_message = ? WHERE id = ?",
                (str(exc), job_id)
            )


@router.get("/backups")
async def backups_page(request: Request, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    jobs = db.list_backup_jobs(limit=50)
    clients = db.list_clients()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "backups.html",
        {
            "request": request,
            "user": user,
            "jobs": jobs,
            "clients": clients,
            "active_tab": "backups"
        }
    )


@router.post("/backups/trigger")
async def trigger_backup(
    request: Request,
    background_tasks: BackgroundTasks,
    client_id: int = Form(...),
    dry_run: bool = Form(False),
    user: dict = Depends(require_auth)
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    background_tasks.add_task(_execute_backup_task, request.app.state, client_id, "manual", dry_run)
    request.app.state.audit_logger.log(
        action="TRIGGER_BACKUP",
        user_id=user["id"],
        username=user["username"],
        resource_type="client",
        resource_id=str(client_id),
        details={"dry_run": dry_run}
    )
    return RedirectResponse(url="/backups", status_code=303)


@router.get("/api/v1/backups/jobs/{job_id}/manifest")
async def get_job_manifest(job_id: int, request: Request, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    with db.connection() as conn:
        row = conn.execute("SELECT manifest_json, run_date, client_id FROM backup_jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Backup job not found")

    manifest_raw = row["manifest_json"]
    if not manifest_raw:
        return {"message": "No manifest available for this run."}

    return json.loads(manifest_raw)
