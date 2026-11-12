"""Microsoft OneDrive & SharePoint Storage Provider via Microsoft Graph API."""

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

    def __init__(self, tenant_id: str, client_id: str, client_secret: str, root_folder_name: str = "Enterprise_Backups"):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.root_folder_name = root_folder_name
        self._access_token = None
        self._token_expires_at = 0
        self._folder_cache = {}

    def _get_token(self) -> str:
        """Obtain or refresh OAuth2 token using client credentials flow."""
        now = time.time()
        if self._access_token and now < self._token_expires_at - 60:
            return self._access_token

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials"
        }

        resp = requests.post(token_url, data=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expires_at = now + data.get("expires_in", 3600)
        return self._access_token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json"
        }

    def verify_connection(self) -> bool:
        """Verify Graph API access and drive accessibility."""
        try:
            url = f"{GRAPH_BASE}/me/drive"
            resp = requests.get(url, headers=self._headers(), timeout=15)
            if resp.status_code == 200:
                logger.info("Microsoft OneDrive connection verified.")
                return True
            # Try app-only default drive if /me/drive is not available
            url = f"{GRAPH_BASE}/drives"
            resp = requests.get(url, headers=self._headers(), timeout=15)
            return resp.status_code == 200
        except Exception as exc:
            logger.error("OneDrive connection test failed: %s", exc)
            return False

    def ensure_directory_path(self, path_parts: List[str]) -> str:
        """Ensure nested directory structure exists and return relative path as identifier."""
        clean_parts = [self.root_folder_name] + [
            "".join(c for c in p if c.isalnum() or c in ("-", "_", ".", " "))
            for p in path_parts
        ]
        full_path = "/".join(clean_parts)
        if full_path in self._folder_cache:
            return full_path

        # Create path sequentially
        current_path = ""
        for part in clean_parts:
            parent_url = f"{GRAPH_BASE}/me/drive/root/children" if not current_path else f"{GRAPH_BASE}/me/drive/root:/{current_path}:/children"
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
        local_path = Path(local_path).resolve()
        file_size = local_path.stat().st_size
        target_path = f"{destination_folder_id}/{target_filename}".strip("/")

        # Files <= 4MB can use simple direct upload
        if file_size <= 4 * 1024 * 1024:
            upload_url = f"{GRAPH_BASE}/me/drive/root:/{target_path}:/content"
            headers = self._headers()
            headers["Content-Type"] = "application/octet-stream"
            with open(str(local_path), "rb") as f:
                resp = requests.put(upload_url, headers=headers, data=f, timeout=60)
            resp.raise_for_status()
            logger.info("Uploaded %s to OneDrive (%d bytes)", target_filename, file_size)
            return resp.json().get("id", target_path)

        # Large files: Create upload session
        session_url = f"{GRAPH_BASE}/me/drive/root:/{target_path}:/createUploadSession"
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
                start = end + 1

        logger.info("Uploaded large file %s to OneDrive via upload session (%d bytes)", target_filename, file_size)
        return target_path

    def list_subdirectories(self, parent_folder_id: str) -> List[Dict[str, Any]]:
        """List folders in OneDrive path."""
        url = f"{GRAPH_BASE}/me/drive/root:/{parent_folder_id}:/children"
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
        url = f"{GRAPH_BASE}/me/drive/items/{folder_id}"
        resp = requests.delete(url, headers=self._headers(), timeout=30)
        return resp.status_code in (204, 200)
