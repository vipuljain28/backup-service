"""Client Tenants, Servers, Databases & Folders Management Routes."""

import json
import shlex
from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional, List

from backup_service.web.routes.auth_routes import require_auth
from backup_service.security.auth import Role

router = APIRouter(tags=["Clients & Targets"])


@router.get("/clients")
async def clients_page(request: Request, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    clients = db.list_clients()
    storage_configs = db.list_storage_configs()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="clients.html",
        context={
            "user": user,
            "clients": clients,
            "storage_configs": storage_configs,
            "active_tab": "clients"
        }
    )


@router.get("/api/v1/clients")
async def list_clients_api(user: dict = Depends(require_auth), request: Request = None):
    db = request.app.state.db_manager
    clients = db.list_clients()
    return clients


@router.get("/api/v1/clients/{client_id}")
async def get_client_api(client_id: int, user: dict = Depends(require_auth), request: Request = None):
    db = request.app.state.db_manager
    client = db.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.post("/clients/create")
async def create_client(
    request: Request,
    user: dict = Depends(require_auth),
    client_id: str = Form(...),
    display_name: str = Form(...),
    retention_days: int = Form(10),
    storage_config_id: Optional[int] = Form(None)
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    client_slug = client_id.strip().lower().replace(" ", "_")
    new_id = db.create_client(client_slug, display_name.strip(), retention_days, storage_config_id)

    request.app.state.audit_logger.log(
        action="CREATE_CLIENT",
        user_id=user["id"],
        username=user["username"],
        resource_type="client",
        resource_id=str(new_id),
        details={"client_id": client_slug, "name": display_name}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/edit")
async def edit_client(
    client_id: int,
    request: Request,
    user: dict = Depends(require_auth),
    display_name: str = Form(...),
    retention_days: int = Form(10),
    storage_config_id: Optional[str] = Form(None)
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    storage_id = int(storage_config_id) if storage_config_id and storage_config_id.strip() else None
    db.update_client(client_id, display_name.strip(), retention_days, storage_id)

    request.app.state.audit_logger.log(
        action="UPDATE_CLIENT",
        user_id=user["id"],
        username=user["username"],
        resource_type="client",
        resource_id=str(client_id),
        details={"name": display_name, "retention_days": retention_days, "storage_config_id": storage_id}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/servers/add")
async def add_server(
    client_id: int,
    request: Request,
    user: dict = Depends(require_auth),
    name: str = Form(...),
    mode: str = Form("local"),
    host: Optional[str] = Form(""),
    port: int = Form(22),
    username: Optional[str] = Form(""),
    auth_type: str = Form("password"),
    secret: Optional[str] = Form("")
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    vault = request.app.state.vault

    # Encrypt SSH password or private key at rest using AES-256-GCM
    encrypted_secret = vault.encrypt(secret) if secret else ""

    srv_id = db.add_server_connection(
        client_id=client_id,
        name=name.strip(),
        mode=mode.strip().lower(),
        host=host.strip(),
        port=port,
        username=username.strip(),
        auth_type=auth_type,
        encrypted_secret=encrypted_secret
    )

    request.app.state.audit_logger.log(
        action="ADD_SERVER",
        user_id=user["id"],
        username=user["username"],
        resource_type="server_connection",
        resource_id=str(srv_id),
        details={"client_id": client_id, "mode": mode, "host": host}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/databases/add")
async def add_database(
    client_id: int,
    request: Request,
    user: dict = Depends(require_auth),
    server_id: int = Form(...),
    name: str = Form(...),
    engine: str = Form("mysql"),
    host: str = Form("127.0.0.1"),
    port: int = Form(3306),
    username: str = Form("root"),
    password: Optional[str] = Form(""),
    db_name: str = Form(...),
    ssl_enabled: bool = Form(False)
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    vault = request.app.state.vault

    # Encrypt database password at rest using AES-256-GCM
    encrypted_password = vault.encrypt(password) if password else ""

    db_id = db.add_database_target(
        client_id=client_id,
        server_id=server_id,
        name=name.strip(),
        engine=engine.strip().lower(),
        host=host.strip(),
        port=port,
        username=username.strip(),
        encrypted_password=encrypted_password,
        db_name=db_name.strip(),
        ssl_enabled=ssl_enabled
    )

    request.app.state.audit_logger.log(
        action="ADD_DATABASE",
        user_id=user["id"],
        username=user["username"],
        resource_type="database_target",
        resource_id=str(db_id),
        details={"client_id": client_id, "engine": engine, "db": db_name, "ssl": ssl_enabled}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/folders/add")
async def add_folder(
    client_id: int,
    request: Request,
    user: dict = Depends(require_auth),
    server_id: int = Form(...),
    source_slug: str = Form(...),
    absolute_path: str = Form(...),
    exclude_patterns: str = Form("*.tmp, *.log")
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    patterns = [p.strip() for p in exclude_patterns.split(",") if p.strip()]

    folder_id = db.add_folder_source(
        client_id=client_id,
        server_id=server_id,
        source_slug=source_slug.strip().lower().replace(" ", "_"),
        absolute_path=absolute_path.strip(),
        exclude_patterns=json.dumps(patterns)
    )

    request.app.state.audit_logger.log(
        action="ADD_FOLDER",
        user_id=user["id"],
        username=user["username"],
        resource_type="folder_source",
        resource_id=str(folder_id),
        details={"client_id": client_id, "path": absolute_path}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/api/v1/servers/{server_id}/test")
async def test_server_connection(server_id: int, request: Request, user: dict = Depends(require_auth)):
    """Test connectivity for a configured server connection (Local process or SSH handshake)."""
    db = request.app.state.db_manager
    vault = request.app.state.vault

    with db.connection() as conn:
        row = conn.execute("SELECT * FROM server_connections WHERE id = ?", (server_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Server connection not found")
        server = dict(row)

    if server["mode"] == "local":
        return {
            "success": True,
            "server_id": server_id,
            "mode": "local",
            "message": "Local server execution environment is active and ready."
        }

    try:
        from backup_service.config.settings import SSHConfig
        from backup_service.drivers.ssh_driver import SSHDriver

        decrypted_secret = vault.decrypt(server["encrypted_secret"]) if server["encrypted_secret"] else None
        key_path = None
        password = None

        if server["auth_type"] == "password":
            password = decrypted_secret
        else:
            key_path = decrypted_secret

        ssh_cfg = SSHConfig(
            host=server["host"],
            port=server["port"] or 22,
            user=server["username"],
            key_path=key_path,
            password=password,
            timeout_seconds=10
        )

        driver = SSHDriver(ssh_cfg)
        client = driver._get_client()
        stdin, stdout, stderr = client.exec_command("uname -a || ver", timeout=5)
        out = stdout.read().decode("utf-8", errors="ignore").strip()
        driver.close()

        return {
            "success": True,
            "server_id": server_id,
            "mode": "ssh",
            "host": f"{server['username']}@{server['host']}:{server['port']}",
            "message": f"SSH connection verified successfully! Remote Host: {out[:100]}"
        }
    except Exception as exc:
        return {
            "success": False,
            "server_id": server_id,
            "mode": "ssh",
            "host": f"{server['username']}@{server['host']}:{server['port']}",
            "message": f"SSH Connection Failed: {str(exc)}"
        }


@router.post("/clients/{client_id}/servers/{server_id}/delete")
async def delete_server(client_id: int, server_id: int, request: Request, user: dict = Depends(require_auth)):
    """Delete a server connection from a client."""
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    with db.connection() as conn:
        conn.execute("DELETE FROM server_connections WHERE id = ? AND client_id = ?", (server_id, client_id))

    request.app.state.audit_logger.log(
        action="DELETE_SERVER",
        user_id=user["id"],
        username=user["username"],
        resource_type="server_connection",
        resource_id=str(server_id),
        details={"client_id": client_id}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/databases/{db_id}/delete")
async def delete_database(client_id: int, db_id: int, request: Request, user: dict = Depends(require_auth)):
    """Delete a database target from a client."""
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    with db.connection() as conn:
        conn.execute("DELETE FROM database_targets WHERE id = ? AND client_id = ?", (db_id, client_id))

    request.app.state.audit_logger.log(
        action="DELETE_DATABASE",
        user_id=user["id"],
        username=user["username"],
        resource_type="database_target",
        resource_id=str(db_id),
        details={"client_id": client_id}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/folders/{folder_id}/delete")
async def delete_folder(client_id: int, folder_id: int, request: Request, user: dict = Depends(require_auth)):
    """Delete a folder source from a client."""
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    with db.connection() as conn:
        conn.execute("DELETE FROM folder_sources WHERE id = ? AND client_id = ?", (folder_id, client_id))

    request.app.state.audit_logger.log(
        action="DELETE_FOLDER",
        user_id=user["id"],
        username=user["username"],
        resource_type="folder_source",
        resource_id=str(folder_id),
        details={"client_id": client_id}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/folders/{folder_id}/edit")
async def edit_folder(
    client_id: int,
    folder_id: int,
    request: Request,
    user: dict = Depends(require_auth),
    server_id: int = Form(...),
    source_slug: str = Form(...),
    absolute_path: str = Form(...),
    exclude_patterns: str = Form("*.tmp, *.log")
):
    """Edit an existing folder source configuration."""
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    patterns = [p.strip() for p in exclude_patterns.split(",") if p.strip()]

    db.update_folder_source(
        folder_id=folder_id,
        client_id=client_id,
        server_id=server_id,
        source_slug=source_slug.strip().lower().replace(" ", "_"),
        absolute_path=absolute_path.strip(),
        exclude_patterns=json.dumps(patterns)
    )

    request.app.state.audit_logger.log(
        action="EDIT_FOLDER",
        user_id=user["id"],
        username=user["username"],
        resource_type="folder_source",
        resource_id=str(folder_id),
        details={"client_id": client_id, "path": absolute_path}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.post("/clients/{client_id}/databases/{db_id}/edit")
async def edit_database(
    client_id: int,
    db_id: int,
    request: Request,
    user: dict = Depends(require_auth),
    server_id: int = Form(...),
    name: str = Form(...),
    engine: str = Form(...),
    host: str = Form(...),
    port: int = Form(3306),
    username: str = Form(...),
    password: Optional[str] = Form(None),
    db_name: str = Form(...),
    ssl_enabled: bool = Form(False)
):
    """Edit an existing database target configuration."""
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    db = request.app.state.db_manager
    vault = request.app.state.vault

    encrypted_password = vault.encrypt(password) if password else None

    db.update_database_target(
        db_id=db_id,
        client_id=client_id,
        server_id=server_id,
        name=name.strip(),
        engine=engine.strip().lower(),
        host=host.strip(),
        port=port,
        username=username.strip(),
        encrypted_password=encrypted_password,
        db_name=db_name.strip(),
        ssl_enabled=ssl_enabled
    )

    request.app.state.audit_logger.log(
        action="EDIT_DATABASE",
        user_id=user["id"],
        username=user["username"],
        resource_type="database_target",
        resource_id=str(db_id),
        details={"client_id": client_id, "engine": engine, "db": db_name}
    )
    return RedirectResponse(url="/clients", status_code=303)


@router.get("/api/v1/folders/{folder_id}/inspect")
async def inspect_folder_api(folder_id: int, request: Request, user: dict = Depends(require_auth)):
    """Inspect files, extensions, and metadata inside a configured folder source."""
    from backup_service.drivers.explorer import DirectoryExplorer

    db = request.app.state.db_manager
    vault = request.app.state.vault

    folder = db.get_folder_source(folder_id)
    if not folder:
        raise HTTPException(status_code=404, detail="Folder source not found")

    server_data = {
        "id": folder.get("server_id"),
        "name": folder.get("server_name"),
        "mode": folder.get("server_mode", "local"),
        "host": folder.get("server_host"),
        "port": folder.get("server_port") or 22,
        "username": folder.get("server_username"),
        "auth_type": folder.get("server_auth_type"),
        "encrypted_secret": folder.get("server_encrypted_secret")
    }

    inspection = DirectoryExplorer.inspect_folder(
        server=server_data,
        vault=vault,
        folder_path=folder["absolute_path"]
    )
    inspection["folder_id"] = folder_id
    inspection["source_slug"] = folder["source_slug"]
    inspection["exclude_patterns"] = json.loads(folder.get("exclude_patterns") or "[]")
    return inspection


@router.post("/api/v1/databases/{db_id}/test")
async def test_configured_database_api(db_id: int, request: Request, user: dict = Depends(require_auth)):
    """Test connection directly on the configured database target (SSH remote or local)."""
    from backup_service.config.settings import SSHConfig
    from backup_service.drivers.ssh_driver import SSHDriver
    from backup_service.drivers.db_checker import DatabaseChecker

    db = request.app.state.db_manager
    vault = request.app.state.vault

    target = db.get_database_target(db_id)
    if not target:
        raise HTTPException(status_code=404, detail="Database target not found")

    decrypted_pwd = vault.decrypt(target["encrypted_password"]) if target.get("encrypted_password") else ""
    server_mode = target.get("server_mode", "local")

    if server_mode == "ssh":
        server_secret = vault.decrypt(target["server_encrypted_secret"]) if target.get("server_encrypted_secret") else None
        key_path = server_secret if target.get("server_auth_type") != "password" else None
        server_pwd = server_secret if target.get("server_auth_type") == "password" else None

        ssh_cfg = SSHConfig(
            host=target["server_host"],
            port=target.get("server_port") or 22,
            user=target["server_username"],
            key_path=key_path,
            password=server_pwd,
            timeout_seconds=10
        )
        try:
            driver = SSHDriver(ssh_cfg)
            client = driver._get_client()

            pwd_flag = f"--password={shlex.quote(decrypted_pwd)}" if decrypted_pwd else ""
            db_name = target["db_name"]
            # Check connection and query table count with strict shell parameter escaping
            cmd = (
                f"mysql -h {shlex.quote(str(target['host']))} -P {target['port']} -u {shlex.quote(target['username'])} "
                f"{pwd_flag} {shlex.quote(db_name)} -e {shlex.quote(f'SELECT count(*) FROM information_schema.tables WHERE table_schema=\"{db_name}\";')} 2>&1"
            )
            stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
            output = stdout.read().decode("utf-8", errors="ignore").strip()
            driver.close()

            if "ERROR " in output or "Access denied" in output:
                return {
                    "success": False,
                    "message": f"Remote Database Connection Failed:\n{output}"
                }
            
            lines = [l.strip() for l in output.splitlines() if l.strip()]
            table_count = lines[-1] if len(lines) > 1 else "0"
            return {
                "success": True,
                "message": f"Connected successfully over SSH to MySQL on '{target['server_host']}'!\nFound {table_count} tables in database '{db_name}'."
            }
        except Exception as exc:
            return {
                "success": False,
                "message": f"SSH Database connection error: {str(exc)}"
            }
    else:
        # Local connection
        result = DatabaseChecker.test_connection(
            engine=target["engine"],
            host=target["host"],
            port=target["port"],
            user=target["username"],
            password=decrypted_pwd,
            db_name=target["db_name"],
            ssl_enabled=bool(target.get("ssl_enabled"))
        )
        return {
            "success": result["connected"],
            "message": result["message"] or ("Connected successfully to local database!" if result["connected"] else "Connection failed.")
        }
