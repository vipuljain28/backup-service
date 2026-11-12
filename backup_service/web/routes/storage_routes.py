"""Multi-Cloud Storage Configuration & Testing Routes."""

import json
from pathlib import Path
from fastapi import APIRouter, Request, Depends, HTTPException, Form
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional

from backup_service.web.routes.auth_routes import require_auth
from backup_service.storage.factory import StorageProviderFactory
from backup_service.security.auth import Role

router = APIRouter(tags=["Storage Providers"])


@router.get("/storage")
async def storage_page(request: Request, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    storage_configs = db.list_storage_configs()
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request=request,
        name="storage.html",
        context={
            "user": user,
            "storage_configs": storage_configs,
            "active_tab": "storage"
        }
    )


@router.post("/storage/create")
async def create_storage(
    request: Request,
    user: dict = Depends(require_auth),
    name: str = Form(...),
    provider_type: str = Form(...),
    is_default: bool = Form(False),
    # Google Drive fields
    gdrive_auth_mode: str = Form("service_account"),
    gdrive_sa_file: Optional[str] = Form(None),
    gdrive_oauth_file: Optional[str] = Form(None),
    gdrive_token_file: Optional[str] = Form("token.json"),
    gdrive_root_folder: Optional[str] = Form("STAR_Enterprise_Backups"),
    # OneDrive fields
    onedrive_tenant_id: Optional[str] = Form(None),
    onedrive_client_id: Optional[str] = Form(None),
    onedrive_client_secret: Optional[str] = Form(None),
    onedrive_user_email: Optional[str] = Form(None),
    onedrive_root_folder: Optional[str] = Form("STAR_Enterprise_Backups"),
    # S3 / TeraBox fields
    s3_endpoint_url: Optional[str] = Form(None),
    s3_access_key: Optional[str] = Form(None),
    s3_secret_key: Optional[str] = Form(None),
    s3_bucket_name: Optional[str] = Form(None),
    # Local storage fields
    local_root_dir: Optional[str] = Form("./local_cloud_backup")
):
    if user.get("role") == Role.AUDITOR:
        raise HTTPException(status_code=403, detail="Auditor role is read-only")

    p_type = provider_type.strip().lower()
    credentials = {}

    if p_type == "gdrive":
        credentials = {
            "auth_mode": gdrive_auth_mode,
            "service_account_file": gdrive_sa_file,
            "oauth_client_file": gdrive_oauth_file or "./client_secret.json",
            "oauth_token_file": gdrive_token_file or "./token.json",
            "root_folder_name": gdrive_root_folder or "STAR_Enterprise_Backups"
        }
    elif p_type == "onedrive":
        credentials = {
            "tenant_id": (onedrive_tenant_id or "").strip(),
            "client_id": (onedrive_client_id or "").strip(),
            "client_secret": (onedrive_client_secret or "").strip(),
            "user_email": (onedrive_user_email or "").strip(),
            "root_folder_name": (onedrive_root_folder or "STAR_Enterprise_Backups").strip()
        }
    elif p_type in ("s3", "terabox", "s3_terabox"):
        credentials = {
            "endpoint_url": s3_endpoint_url,
            "access_key": s3_access_key,
            "secret_key": s3_secret_key,
            "bucket_name": s3_bucket_name,
            "root_prefix": "Enterprise_Backups"
        }
    elif p_type == "local":
        credentials = {
            "root_dir": local_root_dir or "./local_cloud_backup"
        }

    # Encrypt credentials via Vault
    vault = request.app.state.vault
    encrypted_creds = vault.encrypt(json.dumps(credentials))

    db = request.app.state.db_manager
    cfg_id = db.save_storage_config(
        name=name.strip(),
        provider_type=p_type,
        encrypted_credentials=encrypted_creds,
        is_default=is_default
    )

    request.app.state.audit_logger.log(
        action="CREATE_STORAGE_CONFIG",
        user_id=user["id"],
        username=user["username"],
        resource_type="storage_config",
        resource_id=str(cfg_id),
        details={"name": name, "provider": p_type}
    )
    return RedirectResponse(url="/storage", status_code=303)


@router.post("/api/v1/storage/test")
async def test_storage_api(request: Request, body: dict, user: dict = Depends(require_auth)):
    provider_type = body.get("provider_type", "local")
    credentials = body.get("credentials", {})

    try:
        provider = StorageProviderFactory.create_provider(provider_type, credentials)
        if hasattr(provider, "verify_connection_detailed"):
            res = provider.verify_connection_detailed()
            connected = res.get("connected", False)
            message = res.get("message", "")
            if not connected and res.get("suggestion"):
                message += f"\nRecommendation: {res['suggestion']}"
        else:
            connected = provider.verify_connection()
            message = "Storage connection successful and verified." if connected else "Storage connection test failed."

        return {
            "provider_type": provider_type,
            "connected": connected,
            "needs_oauth": res.get("stage") == "oauth_action_required" if hasattr(provider, "verify_connection_detailed") else False,
            "auth_url": res.get("auth_url") if hasattr(provider, "verify_connection_detailed") else None,
            "message": message
        }
    except Exception as exc:
        return {
            "provider_type": provider_type,
            "connected": False,
            "message": f"Storage connection error: {exc}"
        }


@router.post("/api/v1/storage/{config_id}/test")
async def test_configured_storage_api(request: Request, config_id: int, user: dict = Depends(require_auth)):
    db = request.app.state.db_manager
    cfg = db.get_storage_config(config_id)
    if not cfg:
        raise HTTPException(status_code=404, detail="Storage configuration not found")

    vault = request.app.state.vault
    p_type = cfg["provider_type"]

    try:
        creds_json = vault.decrypt(cfg["encrypted_credentials"])
        credentials = json.loads(creds_json)
        provider = StorageProviderFactory.create_provider(p_type, credentials)
        if hasattr(provider, "verify_connection_detailed"):
            res = provider.verify_connection_detailed()
            connected = res.get("connected", False)
            message = res.get("message", "")
            if not connected and res.get("suggestion"):
                message += f"\nRecommendation: {res['suggestion']}"
        else:
            connected = provider.verify_connection()
            message = f"Storage '{cfg['name']}' ({p_type.upper()}) verified successfully!" if connected else f"Storage '{cfg['name']}' connection check failed."

        return {
            "config_id": config_id,
            "provider_type": p_type,
            "connected": connected,
            "needs_oauth": res.get("stage") == "oauth_action_required" if hasattr(provider, "verify_connection_detailed") else False,
            "auth_url": res.get("auth_url") if hasattr(provider, "verify_connection_detailed") else None,
            "message": message
        }
    except Exception as exc:
        return {
            "config_id": config_id,
            "provider_type": p_type,
            "connected": False,
            "message": f"Storage verification error: {str(exc)}"
        }


@router.post("/api/v1/storage/upload-key")
async def upload_key_api(request: Request, user: dict = Depends(require_auth)):
    """Upload or paste a Google Cloud JSON key (Service Account or OAuth Client)."""
    body = await request.json()
    json_text = body.get("json_content", "").strip()
    config_id = body.get("config_id")

    if not json_text:
        raise HTTPException(status_code=400, detail="No JSON content provided.")

    try:
        data = json.loads(json_text)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON format: {exc}")

    keys_dir = Path("keys")
    keys_dir.mkdir(parents=True, exist_ok=True)

    db = request.app.state.db_manager
    vault = request.app.state.vault

    if data.get("type") == "service_account":
        target_file = keys_dir / "service_account.json"
        target_file.write_text(json_text, encoding="utf-8")
        client_email = data.get("client_email", "Unknown")
        project_id = data.get("project_id", "Unknown")

        if config_id:
            cfg = db.get_storage_config(config_id)
            if cfg and cfg["provider_type"] == "gdrive":
                creds = json.loads(vault.decrypt(cfg["encrypted_credentials"]))
                creds["auth_mode"] = "service_account"
                creds["service_account_file"] = "./keys/service_account.json"
                enc = vault.encrypt(json.dumps(creds))
                with db.connection() as conn:
                    conn.execute("UPDATE storage_configs SET encrypted_credentials = ? WHERE id = ?", (enc, config_id))

        return {
            "status": "success",
            "key_type": "service_account",
            "file_path": "./keys/service_account.json",
            "client_email": client_email,
            "project_id": project_id,
            "message": f"Service Account key saved successfully! Identity: {client_email}. Remember to share your Google Drive folder with this email as Editor."
        }

    elif "installed" in data or "web" in data:
        target_file = keys_dir / "client_secret.json"
        target_file.write_text(json_text, encoding="utf-8")
        client_obj = data.get("installed") or data.get("web") or {}
        client_id = client_obj.get("client_id", "Unknown")

        if config_id:
            cfg = db.get_storage_config(config_id)
            if cfg and cfg["provider_type"] == "gdrive":
                creds = json.loads(vault.decrypt(cfg["encrypted_credentials"]))
                creds["auth_mode"] = "oauth_user"
                creds["oauth_client_file"] = "./keys/client_secret.json"
                creds["oauth_token_file"] = "./keys/token.json"
                enc = vault.encrypt(json.dumps(creds))
                with db.connection() as conn:
                    conn.execute("UPDATE storage_configs SET encrypted_credentials = ? WHERE id = ?", (enc, config_id))

        return {
            "status": "success",
            "key_type": "oauth_user",
            "file_path": "./keys/client_secret.json",
            "client_id": client_id,
            "message": "OAuth 2.0 Client ID secret saved successfully! Switched mode to OAuth2 Client Flow."
        }
    else:
        raise HTTPException(status_code=400, detail="Unrecognized Google JSON key format. Must be either a Service Account JSON or an OAuth 2.0 Client ID JSON.")


@router.post("/api/v1/storage/gdrive/start-oauth")
async def start_oauth_api(request: Request, user: dict = Depends(require_auth)):
    """Launch Google OAuth consent flow with an ephemeral listener in a background thread."""
    import threading
    import webbrowser
    import wsgiref.simple_server
    from google_auth_oauthlib.flow import (
        InstalledAppFlow,
        _RedirectWSGIApp,
        _ExclusiveWSGIServer,
        _WSGIRequestHandler
    )

    client_path = Path("keys/client_secret.json")
    if not client_path.is_file():
        raise HTTPException(status_code=400, detail="keys/client_secret.json not found on server.")

    SCOPES = ["https://www.googleapis.com/auth/drive"]
    flow = InstalledAppFlow.from_client_secrets_file(str(client_path), SCOPES)

    # Spin up ephemeral WSGI server matching Google loopback strategy
    wsgi_app = _RedirectWSGIApp("Authentication successful! You can now close this tab and return to the Backup Service console.")
    local_server = wsgiref.simple_server.make_server(
        "localhost",
        0,
        wsgi_app,
        server_class=_ExclusiveWSGIServer,
        handler_class=_WSGIRequestHandler
    )
    port = local_server.server_port
    flow.redirect_uri = f"http://localhost:{port}/"
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")

    def _listen():
        try:
            local_server.timeout = 180
            local_server.handle_request()
            if hasattr(wsgi_app, "last_request_uri") and wsgi_app.last_request_uri:
                auth_resp = wsgi_app.last_request_uri.replace("http:", "https:")
                flow.fetch_token(authorization_response=auth_resp)
                creds = flow.credentials
                token_text = creds.to_json()
                keys_dir = Path("keys")
                keys_dir.mkdir(parents=True, exist_ok=True)
                for tf in [keys_dir / "token.json", keys_dir / "vipuljain2806token.json"]:
                    tf.write_text(token_text, encoding="utf-8")
        except Exception as exc:
            logger.warning(f"OAuth background callback error: {exc}")
        finally:
            try:
                local_server.server_close()
            except Exception:
                pass

    threading.Thread(target=_listen, daemon=True).start()

    # Automatically trigger user browser
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    return {
        "status": "started",
        "auth_url": auth_url,
        "port": port,
        "message": "Google Authorization consent screen has opened in your browser. If it did not open, click the button below."
    }


@router.get("/api/v1/storage/gdrive/oauth-status")
async def check_oauth_status(request: Request, user: dict = Depends(require_auth)):
    """Check if token.json has been generated and is valid."""
    keys_dir = Path("keys")
    token_1 = keys_dir / "token.json"
    token_2 = keys_dir / "vipuljain2806token.json"
    is_authorized = token_1.is_file() or token_2.is_file()
    active_token = str(token_1 if token_1.is_file() else (token_2 if token_2.is_file() else ""))
    return {
        "authorized": is_authorized,
        "token_file": active_token if is_authorized else None
    }


@router.get("/storage/gdrive/authorize")
async def gdrive_authorize(request: Request, user: dict = Depends(require_auth)):
    """Initiate interactive Google OAuth2 consent screen redirect."""
    from google_auth_oauthlib.flow import InstalledAppFlow
    SCOPES = ["https://www.googleapis.com/auth/drive"]

    client_path = Path("keys/client_secret.json")
    if not client_path.is_file():
        raise HTTPException(status_code=400, detail="OAuth client_secret.json not found in keys/ directory.")

    flow = InstalledAppFlow.from_client_secrets_file(
        str(client_path), SCOPES, redirect_uri="http://localhost:8080/storage/gdrive/callback"
    )
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
    return RedirectResponse(auth_url, status_code=303)


@router.get("/storage/gdrive/callback")
async def gdrive_callback(request: Request, code: Optional[str] = None, error: Optional[str] = None):
    """Handle Google OAuth2 redirect callback and persist token.json."""
    if error:
        raise HTTPException(status_code=400, detail=f"Google OAuth authorization denied: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code from Google.")

    from google_auth_oauthlib.flow import InstalledAppFlow
    SCOPES = ["https://www.googleapis.com/auth/drive"]

    client_path = Path("keys/client_secret.json")
    if not client_path.is_file():
        raise HTTPException(status_code=400, detail="OAuth client_secret.json not found in keys/ directory.")

    flow = InstalledAppFlow.from_client_secrets_file(
        str(client_path), SCOPES, redirect_uri="http://localhost:8080/storage/gdrive/callback"
    )
    flow.fetch_token(code=code)
    creds = flow.credentials

    keys_dir = Path("keys")
    keys_dir.mkdir(parents=True, exist_ok=True)
    token_path = keys_dir / "token.json"
    token_path.write_text(creds.to_json(), encoding="utf-8")

    return RedirectResponse(url="/storage?oauth_status=authorized", status_code=303)


