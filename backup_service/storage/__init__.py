"""Storage Subsystem Package."""

from typing import Union
from backup_service.config.settings import AppConfig
from backup_service.storage.base import StorageProvider
from backup_service.storage.gdrive import GoogleDriveProvider
from backup_service.storage.onedrive import OneDriveProvider
from backup_service.storage.s3_terabox import S3TeraBoxProvider
from backup_service.storage.local_storage import LocalStorageProvider
from backup_service.storage.factory import StorageProviderFactory


def get_storage_provider(config: AppConfig) -> StorageProvider:
    """Instantiate the configured storage provider from AppConfig."""
    if config.storage_provider == "gdrive":
        return GoogleDriveProvider(config.gdrive)
    elif config.storage_provider == "local":
        return LocalStorageProvider(config.local_storage_root)
    else:
        return StorageProviderFactory.create_provider(config.storage_provider, {})


__all__ = [
    "StorageProvider",
    "GoogleDriveProvider",
    "OneDriveProvider",
    "S3TeraBoxProvider",
    "LocalStorageProvider",
    "StorageProviderFactory",
    "get_storage_provider",
]
