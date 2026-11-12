"""Google Drive API v3 Storage Provider.

Enterprise-grade implementation featuring:
- Service Account and OAuth2 User credential flows
- Path segment resolution and folder ID in-memory caching
- Chunked resumable uploads with exponential backoff
- Full Google Shared Drive (Team Drive) support
- Automated date-based directory purging for retention enforcement
"""

import os
import time
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from backup_service.storage.base import StorageProvider
from backup_service.config.settings import GoogleDriveConfig

logger = logging.getLogger("backup_service.gdrive")

# Google Drive API Scope required for full backup management
SCOPES = ["https://www.googleapis.com/auth/drive"]
FOLDER_MIME = "application/vnd.google-apps.folder"
CHUNK_SIZE = 5 * 1024 * 1024  # 5 MB resumable chunks


def _resolve_file_path(path_str: Optional[str]) -> Optional[Path]:
    """Resolve file path checking direct path, keys/ subfolder, and project root."""
    if not path_str:
        return None
    p = Path(path_str)
    if p.is_file():
        return p.resolve()
    # Check in keys/ folder
    in_keys = Path("keys") / p.name
    if in_keys.is_file():
        return in_keys.resolve()
    # Check in root folder
    in_cur = Path(".") / p.name
    if in_cur.is_file():
        return in_cur.resolve()
    return p.resolve()


class GoogleDriveProvider(StorageProvider):
    """Google Drive API v3 Storage Backend."""

    def __init__(self, config: GoogleDriveConfig):
        self.config = config
        self._service = None
        self._folder_cache: Dict[str, str] = {}  # key: f"{parent_id}:{folder_name}" -> folder_id
        self._root_id: Optional[str] = config.root_folder_id

    def _get_service(self):
        """Lazy-initialize and cache Google Drive API client with auto-detection."""
        if self._service is not None:
            return self._service

        from googleapiclient.discovery import build
        import json

        # Auto-detect JSON key file type if the file is present
        target_path = None
        if self.config.auth_mode == "service_account" and self.config.service_account_file:
            target_path = _resolve_file_path(self.config.service_account_file)
        elif self.config.auth_mode == "oauth_user" and self.config.oauth_client_file:
            target_path = _resolve_file_path(self.config.oauth_client_file)

        if target_path and target_path.is_file():
            try:
                with open(target_path, "r", encoding="utf-8") as jf:
                    data = json.load(jf)
                if data.get("type") == "service_account":
                    self.config.auth_mode = "service_account"
                    self.config.service_account_file = str(target_path)
                elif "installed" in data or "web" in data:
                    self.config.auth_mode = "oauth_user"
                    self.config.oauth_client_file = str(target_path)
            except Exception:
                pass

        if self.config.auth_mode == "service_account":
            from google.oauth2 import service_account

            if not self.config.service_account_file:
                raise ValueError("service_account_file must be specified when auth_mode is service_account")

            sa_path = _resolve_file_path(self.config.service_account_file)
            if not sa_path or not sa_path.is_file():
                raise FileNotFoundError(
                    f"Google Service Account key file not found at: {sa_path or self.config.service_account_file}. "
                    "Please upload your JSON key file in the Web Console or save it to 'keys/service_account.json'."
                )

            creds = service_account.Credentials.from_service_account_file(
                str(sa_path), scopes=SCOPES
            )
            self._service = build("drive", "v3", credentials=creds, cache_discovery=False)
            logger.info("Authenticated successfully via Google Service Account: %s", sa_path.name)

        elif self.config.auth_mode == "oauth_user":
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from google.auth.transport.requests import Request

            creds = None
            token_path = _resolve_file_path(self.config.oauth_token_file or "token.json")
            client_path = _resolve_file_path(self.config.oauth_client_file or "client_secret.json")

            if token_path and token_path.is_file():
                creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)

            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    if not client_path or not client_path.is_file():
                        raise FileNotFoundError(
                            f"OAuth client_secret.json file not found at: {client_path or self.config.oauth_client_file}. "
                            "Please upload your OAuth Client ID JSON file or save it to 'keys/client_secret.json'."
                        )
                    # Do not block the web server with run_local_server. Require web OAuth callback or token file.
                    raise PermissionError(
                        "Google OAuth2 User authorization has not been completed yet. "
                        "Please click 'Authorize with Google' in the Storage console to complete web authorization, "
                        "or switch to Google Service Account mode (Recommended for automated backups)."
                    )

            self._service = build("drive", "v3", credentials=creds, cache_discovery=False)
            logger.info("Authenticated successfully via Google OAuth2 User credentials")
        else:
            raise ValueError(f"Unsupported auth_mode: {self.config.auth_mode}")

        return self._service

    def verify_connection_detailed(self) -> Dict[str, Any]:
        """Perform comprehensive diagnostics of Google Drive API connection."""
        # 1. Check file existence
        if self.config.auth_mode == "service_account":
            sa_path = _resolve_file_path(self.config.service_account_file)
            if not sa_path or not sa_path.is_file():
                return {
                    "connected": False,
                    "stage": "key_file_missing",
                    "message": (
                        f"Google Service Account key file was not found at: '{sa_path or self.config.service_account_file}'. "
                        "Please place your Google Cloud JSON key in 'keys/service_account.json' or upload it directly in the form."
                    ),
                    "suggestion": "Go to Google Cloud Console > IAM & Admin > Service Accounts > Keys > Download JSON, and place it in the keys/ directory."
                }
        elif self.config.auth_mode == "oauth_user":
            client_path = _resolve_file_path(self.config.oauth_client_file or "client_secret.json")
            token_path = _resolve_file_path(self.config.oauth_token_file or "token.json")
            if not client_path or not client_path.is_file():
                return {
                    "connected": False,
                    "stage": "client_secret_missing",
                    "message": (
                        f"OAuth client secret JSON was not found at: '{client_path or self.config.oauth_client_file}'. "
                        "Please place your client_secret.json in 'keys/client_secret.json' or upload it directly in the form."
                    ),
                    "suggestion": "Download OAuth Client ID JSON from Google Cloud Console > APIs & Services > Credentials, and save as keys/client_secret.json."
                }
            if not token_path or not token_path.is_file():
                try:
                    from google_auth_oauthlib.flow import InstalledAppFlow
                    flow = InstalledAppFlow.from_client_secrets_file(
                        str(client_path), SCOPES, redirect_uri="http://localhost:8080/storage/gdrive/callback"
                    )
                    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")
                    return {
                        "connected": False,
                        "stage": "oauth_action_required",
                        "auth_url": auth_url,
                        "message": "OAuth Client ID JSON is valid, but your Google Account has not been authorized yet.",
                        "suggestion": "Click the 'Authorize with Google' button below to sign in and grant access."
                    }
                except Exception as exc:
                    return {
                        "connected": False,
                        "stage": "flow_error",
                        "message": f"OAuth flow initialization error: {exc}"
                    }

        # 2. Try initializing service
        try:
            service = self._get_service()
        except Exception as exc:
            return {
                "connected": False,
                "stage": "auth_initialization_failed",
                "message": f"Google Authentication Error: {str(exc)}",
                "suggestion": "Verify that your JSON file contains valid Google Cloud credentials."
            }

        # 3. Test API connectivity and get identity
        try:
            about = service.about().get(fields="user,storageQuota").execute()
            user_info = about.get("user", {}).get("emailAddress", "Authenticated Identity")
        except Exception as exc:
            err_str = str(exc)
            if "accessNotConfigured" in err_str or "Google Drive API has not been used" in err_str:
                return {
                    "connected": False,
                    "stage": "api_disabled",
                    "message": "Google Drive API v3 is NOT enabled in your Google Cloud Project.",
                    "suggestion": "Go to Google Cloud Console > APIs & Services > Library > search 'Google Drive API' > click 'Enable'."
                }
            return {
                "connected": False,
                "stage": "api_call_failed",
                "message": f"Google Drive API call failed: {err_str}",
                "suggestion": "Check Google Cloud Console credentials and permissions."
            }

        # 4. Check Root Folder access
        try:
            root_id = self._get_or_create_root_folder()
            return {
                "connected": True,
                "stage": "success",
                "identity": user_info,
                "root_folder_name": self.config.root_folder_name,
                "root_folder_id": root_id,
                "message": f"Successfully connected to Google Drive API as '{user_info}'! Root folder '{self.config.root_folder_name}' is accessible (ID: {root_id})."
            }
        except Exception as exc:
            err_str = str(exc)
            return {
                "connected": True,
                "stage": "folder_sharing_needed",
                "identity": user_info,
                "message": (
                    f"Authentication succeeded as '{user_info}', but folder '{self.config.root_folder_name}' could not be accessed. "
                    f"Make sure you have created the folder '{self.config.root_folder_name}' in Google Drive and Shared it with '{user_info}' as Editor!"
                ),
                "suggestion": f"Open Google Drive in browser, right-click '{self.config.root_folder_name}', click Share, and invite '{user_info}' as Editor."
            }

    def verify_connection(self) -> bool:
        """Verify API connectivity and root folder access."""
        res = self.verify_connection_detailed()
        return res.get("connected", False)

    def _get_or_create_root_folder(self) -> str:
        """Resolve or create the top-level root backup directory in Google Drive."""
        if self._root_id:
            return self._root_id

        service = self._get_service()
        folder_name = self.config.root_folder_name

        query = f"mimeType = '{FOLDER_MIME}' and name = '{folder_name}' and trashed = false"
        if not self.config.shared_drive_id:
            query += " and 'root' in parents"

        kwargs: Dict[str, Any] = {
            "q": query,
            "fields": "files(id, name)",
            "supportsAllDrives": True,
            "includeItemsFromAllDrives": True
        }
        if self.config.shared_drive_id:
            kwargs["corpora"] = "drive"
            kwargs["driveId"] = self.config.shared_drive_id

        res = service.files().list(**kwargs).execute()
        files = res.get("files", [])

        if files:
            self._root_id = files[0]["id"]
            logger.debug("Found existing root folder '%s' with ID: %s", folder_name, self._root_id)
            return self._root_id

        # Create root folder
        file_metadata = {
            "name": folder_name,
            "mimeType": FOLDER_MIME,
        }
        if self.config.shared_drive_id:
            file_metadata["parents"] = [self.config.shared_drive_id]

        created = service.files().create(
            body=file_metadata,
            fields="id",
            supportsAllDrives=True
        ).execute()

        self._root_id = created.get("id")
        logger.info("Created new root folder '%s' with ID: %s", folder_name, self._root_id)
        return self._root_id

    def ensure_directory_path(self, path_parts: List[str]) -> str:
        """Ensure nested directory structure exists in Google Drive.
        
        Example: ['client_star', 'incremental', '2026-11-12', 'files']
        Returns the folder ID of the deepest child.
        """
        service = self._get_service()
        current_parent_id = self._get_or_create_root_folder()

        for part in path_parts:
            cache_key = f"{current_parent_id}:{part}"
            if cache_key in self._folder_cache:
                current_parent_id = self._folder_cache[cache_key]
                continue

            query = (
                f"mimeType = '{FOLDER_MIME}' and name = '{part}' and "
                f"'{current_parent_id}' in parents and trashed = false"
            )
            kwargs = {
                "q": query,
                "fields": "files(id, name)",
                "supportsAllDrives": True,
                "includeItemsFromAllDrives": True
            }

            res = service.files().list(**kwargs).execute()
            files = res.get("files", [])

            if files:
                folder_id = files[0]["id"]
            else:
                meta = {
                    "name": part,
                    "mimeType": FOLDER_MIME,
                    "parents": [current_parent_id]
                }
                created = service.files().create(
                    body=meta,
                    fields="id",
                    supportsAllDrives=True
                ).execute()
                folder_id = created.get("id")
                logger.debug("Created remote folder '%s' under parent ID '%s'", part, current_parent_id)

            self._folder_cache[cache_key] = folder_id
            current_parent_id = folder_id

        return current_parent_id

    def upload_file(
        self,
        local_path: Path,
        destination_folder_id: str,
        target_filename: str,
        overwrite: bool = True
    ) -> str:
        """Upload a local file using chunked resumable upload with retry logic."""
        from googleapiclient.http import MediaFileUpload
        from googleapiclient.errors import HttpError

        service = self._get_service()
        local_path = Path(local_path).resolve()
        file_size = local_path.stat().st_size

        # Check if file exists in destination folder
        existing_file_id = None
        if overwrite:
            query = f"name = '{target_filename}' and '{destination_folder_id}' in parents and trashed = false"
            res = service.files().list(
                q=query,
                fields="files(id, name)",
                supportsAllDrives=True,
                includeItemsFromAllDrives=True
            ).execute()
            files = res.get("files", [])
            if files:
                existing_file_id = files[0]["id"]

        media = MediaFileUpload(
            str(local_path),
            chunksize=CHUNK_SIZE,
            resumable=True
        )

        max_retries = 5
        backoff_seconds = 2

        for attempt in range(1, max_retries + 1):
            try:
                if existing_file_id:
                    # Update existing file content
                    request = service.files().update(
                        fileId=existing_file_id,
                        media_body=media,
                        fields="id, name, size",
                        supportsAllDrives=True
                    )
                else:
                    # Create new file
                    file_metadata = {
                        "name": target_filename,
                        "parents": [destination_folder_id]
                    }
                    request = service.files().create(
                        body=file_metadata,
                        media_body=media,
                        fields="id, name, size",
                        supportsAllDrives=True
                    )

                response = None
                while response is None:
                    status, response = request.next_chunk()
                    if status:
                        progress = int(status.progress() * 100)
                        logger.debug("Uploading %s: %d%% complete", target_filename, progress)

                uploaded_id = response.get("id")
                logger.info(
                    "Uploaded file '%s' (%d bytes) to Google Drive (ID: %s)",
                    target_filename, file_size, uploaded_id
                )
                return uploaded_id

            except HttpError as err:
                if err.resp.status in (429, 500, 502, 503, 504) and attempt < max_retries:
                    logger.warning(
                        "Google Drive transient error HTTP %d. Retrying in %ds (Attempt %d/%d)...",
                        err.resp.status, backoff_seconds, attempt, max_retries
                    )
                    time.sleep(backoff_seconds)
                    backoff_seconds *= 2
                else:
                    logger.error("Fatal Google Drive upload error for '%s': %s", target_filename, err)
                    raise

    def list_subdirectories(self, parent_folder_id: str) -> List[Dict[str, Any]]:
        """List subdirectories inside parent folder."""
        service = self._get_service()
        query = (
            f"mimeType = '{FOLDER_MIME}' and "
            f"'{parent_folder_id}' in parents and trashed = false"
        )
        kwargs = {
            "q": query,
            "fields": "files(id, name, createdTime)",
            "pageSize": 1000,
            "supportsAllDrives": True,
            "includeItemsFromAllDrives": True
        }

        results = []
        page_token = None
        while True:
            if page_token:
                kwargs["pageToken"] = page_token
            res = service.files().list(**kwargs).execute()
            for f in res.get("files", []):
                results.append({
                    "id": f["id"],
                    "name": f["name"],
                    "created_time": f.get("createdTime")
                })
            page_token = res.get("nextPageToken")
            if not page_token:
                break

        return results

    def delete_directory(self, folder_id: str) -> bool:
        """Permanently delete a folder and all its contents."""
        service = self._get_service()
        try:
            service.files().delete(
                fileId=folder_id,
                supportsAllDrives=True
            ).execute()
            logger.info("Successfully deleted remote folder ID: %s", folder_id)
            return True
        except Exception as exc:
            logger.error("Failed to delete remote folder ID %s: %s", folder_id, exc)
            return False
