"""Interactive Directory Browser and Database Connectivity Test Routes."""

from fastapi import APIRouter, Request, Depends, HTTPException, Query
from typing import Optional

from backup_service.web.routes.auth_routes import require_auth
from backup_service.drivers.explorer import DirectoryExplorer
from backup_service.drivers.db_checker import DatabaseChecker
from backup_service.config.settings import SSHConfig

router = APIRouter(tags=["Directory Explorer & Diagnostics"])


@router.get("/api/v1/servers/{server_id}/browse")
async def browse_server_directory(
    server_id: int,
    request: Request,
    path: str = Query("/", description="Target directory to explore"),
    user: dict = Depends(require_auth)
):
    """Browse server filesystem interactively with OWASP traversal protection."""
    db = request.app.state.db_manager
    vault = request.app.state.vault

    with db.connection() as conn:
        row = conn.execute("SELECT * FROM server_connections WHERE id = ?", (server_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Server connection not found")
        server = dict(row)

    if server["mode"] == "local":
        result = DirectoryExplorer.explore_local(path)
        return result

    elif server["mode"] == "ssh":
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
            timeout_seconds=15
        )
        result = DirectoryExplorer.explore_remote_ssh(ssh_cfg, path)
        return result

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported server mode: {server['mode']}")


@router.post("/api/v1/databases/test")
async def test_database_connection(
    request: Request,
    body: dict,
    user: dict = Depends(require_auth)
):
    """Test database connectivity and SSL negotiation."""
    engine = body.get("engine", "mysql")
    host = body.get("host", "127.0.0.1")
    port = int(body.get("port", 3306))
    username = body.get("username", "root")
    password = body.get("password")
    db_name = body.get("db_name", "")
    ssl_enabled = bool(body.get("ssl_enabled", False))

    result = DatabaseChecker.test_connection(
        engine=engine,
        host=host,
        port=port,
        user=username,
        password=password,
        db_name=db_name,
        ssl_enabled=ssl_enabled
    )
    return result
