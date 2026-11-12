"""Abstract base class for cloud/remote storage providers."""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
from pathlib import Path


class StorageProvider(ABC):
    """Abstract interface defining required storage operations for backup service."""

    @abstractmethod
    def verify_connection(self) -> bool:
        """Verify authentication and write access to storage backend."""
        pass

    @abstractmethod
    def ensure_directory_path(self, path_parts: List[str]) -> str:
        """Ensure nested directory structure exists and return its unique identifier (or path).
        
        Example: ['client_a', 'incremental', '2026-11-12', 'files']
        """
        pass

    @abstractmethod
    def upload_file(
        self,
        local_path: Path,
        destination_folder_id: str,
        target_filename: str,
        overwrite: bool = True
    ) -> str:
        """Upload a local file to the designated remote folder.
        
        Returns remote file identifier or path.
        """
        pass

    @abstractmethod
    def list_subdirectories(self, parent_folder_id: str) -> List[Dict[str, Any]]:
        """List subdirectories inside parent folder.
        
        Returns list of dicts with 'id', 'name', 'created_time'
        """
        pass

    @abstractmethod
    def delete_directory(self, folder_id: str) -> bool:
        """Permanently delete/purge a directory and all its contents (used for retention)."""
        pass
