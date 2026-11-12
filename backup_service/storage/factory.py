"""Storage Provider Factory following Factory & Dependency Inversion Principles."""

from typing import Dict, Any
from backup_service.storage.base import StorageProvider
from backup_service.storage.gdrive import GoogleDriveProvider
from backup_service.storage.onedrive import OneDriveProvider
from backup_service.storage.s3_terabox import S3TeraBoxProvider
from backup_service.storage.local_storage import LocalStorageProvider
from backup_service.config.settings import GoogleDriveConfig


class StorageProviderFactory:
    """Factory responsible for instantiating concrete StorageProvider strategies."""

    @staticmethod
    def create_provider(provider_type: str, credentials: Dict[str, Any]) -> StorageProvider:
        """Create a storage provider instance based on provider type and credentials."""
        p_type = provider_type.lower().strip()

        if p_type == "gdrive":
            gdrive_cfg = GoogleDriveConfig(
                auth_mode=credentials.get("auth_mode", "service_account"),
                service_account_file=credentials.get("service_account_file"),
                oauth_client_file=credentials.get("oauth_client_file"),
                oauth_token_file=credentials.get("oauth_token_file", "token.json"),
                root_folder_name=credentials.get("root_folder_name", "Enterprise_Backups"),
                root_folder_id=credentials.get("root_folder_id"),
                shared_drive_id=credentials.get("shared_drive_id"),
            )
            return GoogleDriveProvider(gdrive_cfg)

        elif p_type == "onedrive":
            return OneDriveProvider(
                tenant_id=credentials.get("tenant_id", ""),
                client_id=credentials.get("client_id", ""),
                client_secret=credentials.get("client_secret", ""),
                root_folder_name=credentials.get("root_folder_name", "STAR_Enterprise_Backups"),
                user_email=credentials.get("user_email"),
                drive_id=credentials.get("drive_id")
            )

        elif p_type in ("s3", "terabox", "s3_terabox"):
            return S3TeraBoxProvider(
                endpoint_url=credentials.get("endpoint_url", ""),
                access_key=credentials.get("access_key", ""),
                secret_key=credentials.get("secret_key", ""),
                bucket_name=credentials.get("bucket_name", ""),
                region_name=credentials.get("region_name", "us-east-1"),
                root_prefix=credentials.get("root_prefix", "Enterprise_Backups"),
            )

        elif p_type == "local":
            return LocalStorageProvider(
                root_dir=credentials.get("root_dir", "./local_cloud_backup")
            )

        else:
            raise ValueError(f"Unsupported storage provider type: '{provider_type}'")
