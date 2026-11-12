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
    all_servers = db.list_all_servers()
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
            "all_servers": all_servers,
            "active_tab": "restore"
        }
    )


@router.post("/restores/trigger")
async def trigger_restore(
    request: Request,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_auth),
    backup_job_id: int = Form(...),
    target_location_type: str = Form("original"), # "original", "existing_server", or "new"
    # Target server selection (if existing_server)
    target_server_id: Optional[int] = Form(None),
    # New Server Credentials (if new)
    new_server_mode: str = Form("ssh"), # "ssh" or "local"
    new_server_name: Optional[str] = Form(""),
    new_server_host: Optional[str] = Form(""),
    new_server_port: Optional[int] = Form(22),
    new_server_user: Optional[str] = Form(""),
    new_server_auth_type: Optional[str] = Form("password"), # "password" or "key"
    new_server_secret: Optional[str] = Form(""),
    save_new_server: bool = Form(False),
    # File restoration directory
    target_path: Optional[str] = Form(""),
    # Database restoration credentials
    target_db_engine: str = Form("mysql"),
    target_db_host: str = Form("127.0.0.1"),
    target_db_port: int = Form(3306),
    target_db_user: str = Form("root"),
    target_db_pass: Optional[str] = Form(""),
    target_db_name: Optional[str] = Form(""),
    save_new_db: bool = Form(False),
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
        if job["is_dry_run"]:
            raise HTTPException(
                status_code=400,
                detail="Cannot restore from a Dry Run snapshot. Dry runs are non-destructive simulations and do not create storage archives."
            )
        client = conn.execute("SELECT * FROM clients WHERE id = ?", (job["client_id"],)).fetchone()

    client_id_slug = client["client_id"]
    snapshot_date = job["run_date"]

    # Resolve target server and database parameters
    target_mode = "local"
    target_ssh_cfg = None

    if target_location_type == "original":
        # Resolve original client server connection
        with db.connection() as conn:
            srv = conn.execute("SELECT * FROM server_connections WHERE client_id = ? ORDER BY id ASC LIMIT 1", (client["id"],)).fetchone()
            if srv:
                target_server_id = srv["id"]
                if srv["mode"] == "ssh":
                    target_mode = "ssh"
                    secret = vault.decrypt(srv["encrypted_secret"]) if srv["encrypted_secret"] else None
                    target_ssh_cfg = SSHConfig(
                        host=srv["host"],
                        port=srv["port"] or 22,
                        user=srv["username"],
                        key_path=secret if srv["auth_type"] != "password" else None,
                        password=secret if srv["auth_type"] == "password" else None
                    )

            folder_row = conn.execute("SELECT * FROM folder_sources WHERE client_id = ? ORDER BY id ASC LIMIT 1", (client["id"],)).fetchone()
            if folder_row and not target_path:
                target_path = folder_row["absolute_path"]

            db_row = conn.execute("SELECT * FROM database_targets WHERE client_id = ? ORDER BY id ASC LIMIT 1", (client["id"],)).fetchone()
            if db_row:
                target_db_engine = db_row["engine"]
                target_db_host = db_row["host"]
                target_db_port = db_row["port"]
                target_db_user = db_row["username"]
                target_db_pass = vault.decrypt(db_row["encrypted_password"]) if db_row["encrypted_password"] else ""
                target_db_name = target_db_name or db_row["db_name"]

    elif target_location_type == "existing_server":
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

    elif target_location_type == "new":
        if new_server_mode == "ssh":
            if not new_server_host or not new_server_user:
                raise HTTPException(status_code=400, detail="New SSH Server requires Host and Username")
            target_mode = "ssh"
            target_ssh_cfg = SSHConfig(
                host=new_server_host.strip(),
                port=int(new_server_port or 22),
                user=new_server_user.strip(),
                key_path=new_server_secret if new_server_auth_type != "password" else None,
                password=new_server_secret if new_server_auth_type == "password" else None
            )

            if save_new_server:
                enc_secret = vault.encrypt(new_server_secret) if new_server_secret else ""
                s_name = (new_server_name or f"DR Server ({new_server_host})").strip()
                target_server_id = db.add_server_connection(
                    client_id=client["id"],
                    name=s_name,
                    mode="ssh",
                    host=new_server_host.strip(),
                    port=int(new_server_port or 22),
                    username=new_server_user.strip(),
                    auth_type=new_server_auth_type or "password",
                    encrypted_secret=enc_secret
                )
        else:
            target_mode = "local"
            target_ssh_cfg = None

        if save_new_db and target_db_name:
            enc_pass = vault.encrypt(target_db_pass) if target_db_pass else ""
            db.add_database_target(
                client_id=client["id"],
                server_id=target_server_id,
                name=f"DR DB ({target_db_name})",
                engine=target_db_engine,
                host=target_db_host,
                port=int(target_db_port or 3306),
                username=target_db_user,
                encrypted_password=enc_pass,
                db_name=target_db_name,
                ssl_enabled=False
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
        target_db_engine,
        target_db_host,
        target_db_port,
        target_db_user,
        target_db_pass,
        restore_scope
    )

    request.app.state.audit_logger.log(
        action="TRIGGER_RESTORE",
        user_id=user["id"],
        username=user["username"],
        resource_type="restore_job",
        resource_id=str(restore_job_id),
        details={"client_id": client_id_slug, "date": snapshot_date, "scope": restore_scope, "destination": target_location_type}
    )
    return RedirectResponse(url="/restores", status_code=303)


@router.post("/api/v1/restores/test-server")
async def test_restore_server_api(
    request: Request,
    user: dict = Depends(require_auth),
    mode: str = Form("ssh"),
    host: Optional[str] = Form(None),
    port: int = Form(22),
    username: Optional[str] = Form(None),
    auth_type: str = Form("password"),
    secret: Optional[str] = Form(None),
    server_id: Optional[int] = Form(None)
):
    """Test server credentials prior to triggering disaster recovery."""
    from backup_service.config.settings import SSHConfig
    from backup_service.drivers.ssh_driver import SSHDriver

    vault = request.app.state.vault
    db = request.app.state.db_manager

    if server_id:
        srv = db.get_server(server_id)
        if not srv:
            return {"success": False, "message": "Server ID not found"}
        mode = srv["mode"]
        host = srv["host"]
        port = srv["port"] or 22
        username = srv["username"]
        auth_type = srv["auth_type"]
        secret = vault.decrypt(srv["encrypted_secret"]) if srv["encrypted_secret"] else None

    if mode == "local":
        return {"success": True, "message": "Local host environment verified."}

    if not host or not username:
        return {"success": False, "message": "Host and Username are required for SSH test."}

    try:
        ssh_cfg = SSHConfig(
            host=host.strip(),
            port=port,
            user=username.strip(),
            key_path=secret if auth_type != "password" else None,
            password=secret if auth_type == "password" else None,
            timeout_seconds=8
        )
        drv = SSHDriver(ssh_cfg)
        cl = drv._get_client()
        stdin, stdout, stderr = cl.exec_command("uname -a || ver", timeout=5)
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        drv.close()
        return {
            "success": True,
            "message": f"SSH connection verified successfully!\nRemote Host: {out[:120]}"
        }
    except Exception as exc:
        return {
            "success": False,
            "message": f"SSH Connection Failed: {str(exc)}"
        }


@router.post("/api/v1/restores/test-db")
async def test_restore_database_api(
    request: Request,
    user: dict = Depends(require_auth),
    server_id: Optional[int] = Form(None),
    ssh_host: Optional[str] = Form(None),
    ssh_port: int = Form(22),
    ssh_user: Optional[str] = Form(None),
    ssh_auth_type: str = Form("password"),
    ssh_secret: Optional[str] = Form(None),
    engine: str = Form("mysql"),
    host: str = Form("127.0.0.1"),
    port: int = Form(3306),
    username: str = Form("root"),
    password: Optional[str] = Form(None),
    db_name: Optional[str] = Form(None)
):
    """Test database credentials on the restore target host."""
    from backup_service.config.settings import SSHConfig
    from backup_service.drivers.ssh_driver import SSHDriver
    from backup_service.drivers.db_checker import DatabaseChecker

    vault = request.app.state.vault
    db = request.app.state.db_manager

    if server_id:
        srv = db.get_server(server_id)
        if srv and srv["mode"] == "ssh":
            ssh_host = srv["host"]
            ssh_port = srv["port"] or 22
            ssh_user = srv["username"]
            ssh_auth_type = srv["auth_type"]
            ssh_secret = vault.decrypt(srv["encrypted_secret"]) if srv["encrypted_secret"] else None

    if ssh_host and ssh_user:
        try:
            ssh_cfg = SSHConfig(
                host=ssh_host.strip(),
                port=ssh_port,
                user=ssh_user.strip(),
                key_path=ssh_secret if ssh_auth_type != "password" else None,
                password=ssh_secret if ssh_auth_type == "password" else None,
                timeout_seconds=8
            )
            drv = SSHDriver(ssh_cfg)
            cl = drv._get_client()
            pwd_flag = f"-p'{password}'" if password else ""
            db_flag = db_name if db_name else ""
            cmd = f"mysql -h {host} -P {port} -u {username} {pwd_flag} {db_flag} -e 'SELECT 1;' 2>&1"
            stdin, stdout, stderr = cl.exec_command(cmd, timeout=8)
            out = stdout.read().decode("utf-8", errors="ignore").strip()
            drv.close()

            if "ERROR " in out or "Access denied" in out:
                return {"success": False, "message": f"Database Test Failed on remote host:\n{out}"}
            return {"success": True, "message": f"Database connection successfully verified on remote host '{ssh_host}'!"}
        except Exception as exc:
            return {"success": False, "message": f"SSH Database connection error: {str(exc)}"}
    else:
        result = DatabaseChecker.test_connection(
            engine=engine,
            host=host,
            port=port,
            user=username,
            password=password or "",
            db_name=db_name or "",
            ssl_enabled=False
        )
        return {
            "success": result["connected"],
            "message": result["message"] or ("Connected successfully to local database!" if result["connected"] else "Connection failed.")
        }


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
