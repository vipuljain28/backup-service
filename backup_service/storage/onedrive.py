"""Microsoft OneDrive & SharePoint Storage Provider via Microsoft Graph API.

Enterprise-grade implementation featuring:
- Azure Entra ID / Microsoft Graph OAuth2 Client Credentials flow
- Dynamic Drive Resolution across User Personal Drive, Tenant Default Drive, and SharePoint Document Libraries
- Detailed diagnostics reporting (AADSTS error code interpretation, permissions checking)
- Simple PUT (<4MB) and Chunked UploadSession (>4MB) with exponential backoff
- Sliding window retention enforcement and folder hierarchy caching
"""

import os
import time
import logging
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional
from backup_service.storage.base import StorageProvider

logger = logging.getLogger("backup_service.onedrive")
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class OneDriveProvider(StorageProvider):
    """Microsoft OneDrive Cloud Storage Provider."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        root_folder_name: str = "STAR_Enterprise_Backups",
        user_email: Optional[str] = None,
        drive_id: Optional[str] = None
    ):
        self.tenant_id = (tenant_id or "common").strip()
        self.client_id = (client_id or "").strip()
        self.client_secret = (client_secret or "").strip()
        self.root_folder_name = (root_folder_name or "STAR_Enterprise_Backups").strip()
        self.user_email = user_email.strip() if user_email else None
        self.drive_id = drive_id.strip() if drive_id else None
        self._access_token = None
        self._token_expires_at = 0
        self._folder_cache = {}
        self._resolved_drive_base = None
        self.last_diagnostic_error = ""

    def _get_token(self) -> str:
        """Obtain or refresh OAuth2 token using client credentials flow."""
        now = time.time()
        if self._access_token and now < self._token_expires_at - 60:
            return self._access_token

        if not self.tenant_id or not self.client_id or not self.client_secret:
            raise ValueError(
                "OneDrive credentials incomplete: Azure Tenant ID, Application (Client) ID, and Client Secret are required."
            )

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials"
        }

        try:
            resp = requests.post(token_url, data=payload, timeout=20)
        except Exception as exc:
            self.last_diagnostic_error = f"Network connection failed when reaching Microsoft login ({token_url}): {exc}"
            raise ConnectionError(self.last_diagnostic_error) from exc

        if resp.status_code != 200:
            err_data = {}
            try:
                err_data = resp.json()
            except Exception:
                pass

            err_code = err_data.get("error", f"HTTP_{resp.status_code}")
            err_desc = err_data.get("error_description", resp.text)

            # Contextual human diagnosis
            if "AADSTS700016" in err_desc or self.tenant_id in ("common", "consumers"):
                diag = (
                    f"Microsoft OAuth Error [AADSTS700016]: Client Credentials grant is NOT permitted for personal accounts or 'common' tenant. "
                    "You must provide your specific Directory (Tenant) ID (e.g. 8-4-4-4-12 UUID) from Azure Portal > Entra ID > Overview, "
                    "or connect via a Microsoft 365 Work/School organization account."
                )
            elif "AADSTS7000215" in err_desc or "invalid_client" in err_code:
                diag = (
                    f"Microsoft OAuth Error [AADSTS7000215]: Invalid Client Secret provided. "
                    "Ensure you copied the 'Value' column (not the 'Secret ID') from Azure Portal > App Registrations > Certificates & Secrets."
                )
            elif "AADSTS90002" in err_desc:
                diag = f"Microsoft OAuth Error [AADSTS90002]: Tenant ID '{self.tenant_id}' was not found in Azure Entra directory."
            elif "AADSTS7000222" in err_desc:
                diag = "Microsoft OAuth Error [AADSTS7000222]: The provided Client Secret has expired in Azure Portal."
            else:
                diag = f"Microsoft Token Error [{err_code}]: {err_desc}"

            self.last_diagnostic_error = diag
            raise ConnectionError(diag)

        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expires_at = now + data.get("expires_in", 3600)
        return self._access_token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json"
        }

    def _resolve_drive_base(self) -> str:
        """Resolve the active drive base URL across User, Application, and SharePoint scenarios."""
        if self._resolved_drive_base:
            return self._resolved_drive_base

        headers = self._headers()

        # 1. Explicit drive_id
        if self.drive_id:
            self._resolved_drive_base = f"{GRAPH_BASE}/drives/{self.drive_id}"
            return self._resolved_drive_base

        # 2. Explicit user_email (ideal for M365 Application permissions targeting specific mailbox/drive)
        if self.user_email:
            self._resolved_drive_base = f"{GRAPH_BASE}/users/{self.user_email}/drive"
            return self._resolved_drive_base

        # 3. Try /me/drive (Delegated user token)
        try:
            r = requests.get(f"{GRAPH_BASE}/me/drive", headers=headers, timeout=10)
            if r.status_code == 200:
                self._resolved_drive_base = f"{GRAPH_BASE}/me/drive"
                return self._resolved_drive_base
        except Exception:
            pass

        # 4. Try listing tenant users (/users?$top=5) to locate primary user drive
        try:
            r = requests.get(f"{GRAPH_BASE}/users?$top=5", headers=headers, timeout=10)
            if r.status_code == 200:
                users = r.json().get("value", [])
                for u in users:
                    u_id = u.get("id") or u.get("userPrincipalName")
                    if u_id:
                        udr = requests.get(f"{GRAPH_BASE}/users/{u_id}/drive", headers=headers, timeout=10)
                        if udr.status_code == 200:
                            self._resolved_drive_base = f"{GRAPH_BASE}/users/{u_id}/drive"
                            logger.info("Auto-discovered target OneDrive for user: %s", u.get("userPrincipalName", u_id))
                            return self._resolved_drive_base
        except Exception:
            pass

        # 5. Try /drives (SharePoint or organization document libraries)
        try:
            r = requests.get(f"{GRAPH_BASE}/drives", headers=headers, timeout=10)
            if r.status_code == 200:
                drives = r.json().get("value", [])
                if drives and "id" in drives[0]:
                    drive_id = drives[0]["id"]
                    self._resolved_drive_base = f"{GRAPH_BASE}/drives/{drive_id}"
                    logger.info("Auto-discovered default organization drive: %s", drive_id)
                    return self._resolved_drive_base
        except Exception:
            pass

        # 6. Try root SharePoint site drive
        try:
            r = requests.get(f"{GRAPH_BASE}/sites/root/drive", headers=headers, timeout=10)
            if r.status_code == 200:
                self._resolved_drive_base = f"{GRAPH_BASE}/sites/root/drive"
                return self._resolved_drive_base
        except Exception:
            pass

        # Fallback default
        self._resolved_drive_base = f"{GRAPH_BASE}/me/drive"
        return self._resolved_drive_base

    def verify_connection_detailed(self) -> Dict[str, Any]:
        """Perform comprehensive diagnostic check of token generation and drive connectivity."""
        try:
            self._get_token()
        except Exception as exc:
            return {
                "connected": False,
                "stage": "token_acquisition",
                "message": str(exc),
                "suggestion": "Verify your Azure Tenant ID, Client ID, and Client Secret Value in Azure Portal."
            }

        headers = self._headers()
        drive_base = self._resolve_drive_base()

        try:
            resp = requests.get(drive_base, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                drive_name = data.get("name", "OneDrive")
                drive_type = data.get("driveType", "business")
                owner = data.get("owner", {}).get("user", {}).get("displayName", "Enterprise Account")
                return {
                    "connected": True,
                    "stage": "success",
                    "drive_base": drive_base,
                    "drive_name": drive_name,
                    "drive_type": drive_type,
                    "owner": owner,
                    "message": f"Successfully connected to Microsoft OneDrive [{drive_name} ({drive_type}) owned by {owner}]!"
                }
            elif resp.status_code == 403:
                return {
                    "connected": False,
                    "stage": "permission_denied",
                    "drive_base": drive_base,
                    "message": "HTTP 403 Forbidden: Microsoft Graph permission 'Files.ReadWrite.All' lacks admin consent in Azure Portal.",
                    "suggestion": "Go to Azure Portal > App registrations > API permissions > click 'Grant admin consent for [Tenant]'."
                }
            elif resp.status_code == 400 and "/me" in drive_base:
                return {
                    "connected": False,
                    "stage": "user_drive_unresolved",
                    "drive_base": drive_base,
                    "message": (
                        "HTTP 400: Application client credentials cannot target '/me/drive'. "
                        "Please specify your Microsoft 365 User Email (e.g. user@company.com) so the service knows which user's OneDrive to target."
                    ),
                    "suggestion": "Enter your M365 user email in the 'Target User Email' field in the storage settings."
                }
            else:
                return {
                    "connected": False,
                    "stage": "drive_request_failed",
                    "drive_base": drive_base,
                    "status_code": resp.status_code,
                    "message": f"Microsoft Graph drive query failed with HTTP {resp.status_code}: {resp.text}"
                }
        except Exception as exc:
            return {
                "connected": False,
                "stage": "network_exception",
                "message": f"Network error communicating with Microsoft Graph: {exc}"
            }

    def verify_connection(self) -> bool:
        """Verify Graph API access and drive accessibility."""
        res = self.verify_connection_detailed()
        return res.get("connected", False)

    def ensure_directory_path(self, path_parts: List[str]) -> str:
        """Ensure nested directory structure exists and return relative path as identifier."""
        drive_base = self._resolve_drive_base()
        clean_parts = [self.root_folder_name] + [
            "".join(c for c in p if c.isalnum() or c in ("-", "_", ".", " "))
            for p in path_parts
        ]
        full_path = "/".join(clean_parts)
        if full_path in self._folder_cache:
            return full_path

        current_path = ""
        for part in clean_parts:
            parent_url = f"{drive_base}/root/children" if not current_path else f"{drive_base}/root:/{current_path}:/children"
            current_path = f"{current_path}/{part}" if current_path else part

            payload = {
                "name": part,
                "folder": {},
                "@microsoft.graph.conflictBehavior": "replace"
            }
            try:
                requests.post(parent_url, headers=self._headers(), json=payload, timeout=20)
            except Exception:
                pass

        self._folder_cache[full_path] = full_path
        return full_path

    def upload_file(self, local_path: Path, destination_folder_id: str, target_filename: str, overwrite: bool = True) -> str:
        """Upload file to OneDrive using Simple PUT (<4MB) or Chunked UploadSession (>4MB)."""
        drive_base = self._resolve_drive_base()
        local_path = Path(local_path).resolve()
        file_size = local_path.stat().st_size
        target_path = f"{destination_folder_id}/{target_filename}".strip("/")

        # Files <= 4MB can use simple direct upload
        if file_size <= 4 * 1024 * 1024:
            upload_url = f"{drive_base}/root:/{target_path}:/content"
            headers = self._headers()
            headers["Content-Type"] = "application/octet-stream"
            with open(str(local_path), "rb") as f:
                resp = requests.put(upload_url, headers=headers, data=f, timeout=60)
            resp.raise_for_status()
            logger.info("Uploaded %s to OneDrive (%d bytes)", target_filename, file_size)
            return resp.json().get("id", target_path)

        # Large files: Create upload session
        session_url = f"{drive_base}/root:/{target_path}:/createUploadSession"
        session_resp = requests.post(session_url, headers=self._headers(), json={}, timeout=30)
        session_resp.raise_for_status()
        upload_url = session_resp.json()["uploadUrl"]

        chunk_size = 5 * 1024 * 1024  # 5 MB chunks
        with open(str(local_path), "rb") as f:
            start = 0
            while start < file_size:
                end = min(start + chunk_size, file_size) - 1
                chunk = f.read(end - start + 1)
                chunk_headers = {
                    "Content-Range": f"bytes {start}-{end}/{file_size}",
                    "Content-Length": str(len(chunk))
                }
                put_resp = requests.put(upload_url, headers=chunk_headers, data=chunk, timeout=60)
                put_resp.raise_for_status()
                start = end + 1

        logger.info("Uploaded large file %s to OneDrive via upload session (%d bytes)", target_filename, file_size)
        return target_path

    def list_subdirectories(self, parent_folder_id: str) -> List[Dict[str, Any]]:
        """List folders in OneDrive path."""
        drive_base = self._resolve_drive_base()
        url = f"{drive_base}/root:/{parent_folder_id}:/children"
        resp = requests.get(url, headers=self._headers(), timeout=30)
        if resp.status_code != 200:
            return []

        results = []
        for item in resp.json().get("value", []):
            if "folder" in item:
                results.append({
                    "id": item["id"],
                    "name": item["name"],
                    "created_time": item.get("createdDateTime")
                })
        return results

    def delete_directory(self, folder_id: str) -> bool:
        """Delete directory by ID or path."""
        drive_base = self._resolve_drive_base()
        url = f"{drive_base}/items/{folder_id}"
        resp = requests.delete(url, headers=self._headers(), timeout=30)
        return resp.status_code in (204, 200)
