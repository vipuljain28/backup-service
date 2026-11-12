"""Unit tests for StorageProviderFactory and Multi-Cloud Abstractions."""

import tempfile
from pathlib import Path
from backup_service.storage.factory import StorageProviderFactory
from backup_service.storage.local_storage import LocalStorageProvider


def test_storage_factory_local():
    with tempfile.TemporaryDirectory() as tmp_dir:
        provider = StorageProviderFactory.create_provider("local", {"root_dir": tmp_dir})
        assert isinstance(provider, LocalStorageProvider)
        assert provider.verify_connection() is True

        # Test ensure directory path
        folder_path = provider.ensure_directory_path(["client_a", "incremental", "2026-11-12"])
        assert Path(folder_path).exists()


def test_storage_factory_invalid_provider():
    try:
        StorageProviderFactory.create_provider("unsupported_cloud", {})
        assert False, "Should have raised ValueError"
    except ValueError:
        pass
