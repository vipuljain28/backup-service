"""Multi-Cloud Storage Configuration & Testing Routes."""

import json
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
            "tenant_id": onedrive_tenant_id,
            "client_id": onedrive_client_id,
            "client_secret": onedrive_client_secret,
            "root_folder_name": "Enterprise_Backups"
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
        connected = provider.verify_connection()
        return {
            "provider_type": provider_type,
            "connected": connected,
            "message": "Storage connection successful and verified." if connected else "Storage connection test failed."
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
        connected = provider.verify_connection()
        return {
            "config_id": config_id,
            "provider_type": p_type,
            "connected": connected,
            "message": f"Storage '{cfg['name']}' ({p_type.upper()}) verified successfully!" if connected else f"Storage '{cfg['name']}' connection check failed."
        }
    except Exception as exc:
        return {
            "config_id": config_id,
            "provider_type": p_type,
            "connected": False,
            "message": f"Storage verification error: {str(exc)}"
        }
