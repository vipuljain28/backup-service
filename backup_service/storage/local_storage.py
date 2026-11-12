"""Local filesystem implementation of StorageProvider.

Useful for offline testing, local NAS targets, and dry-run verifications.
"""

import shutil
from pathlib import Path
from typing import List, Dict, Any
from backup_service.storage.base import StorageProvider


class LocalStorageProvider(StorageProvider):
    """Storage provider targeting a local or mounted network directory."""

    def __init__(self, root_dir: str):
        self.root_path = Path(root_dir).resolve()
        self.root_path.mkdir(parents=True, exist_ok=True)

    def verify_connection(self) -> bool:
        """Verify write access to local directory."""
        test_file = self.root_path / ".test_access"
        try:
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink()
            return True
        except Exception:
            return False

    def ensure_directory_path(self, path_parts: List[str]) -> str:
        """Create nested directory structure and return its absolute path string."""
        target_dir = self.root_path
        for part in path_parts:
            # Sanitize path parts
            safe_part = "".join(c for c in part if c.isalnum() or c in ("-", "_", ".", " "))
            target_dir = target_dir / safe_part

        target_dir.mkdir(parents=True, exist_ok=True)
        return str(target_dir)

    def upload_file(
        self,
        local_path: Path,
        destination_folder_id: str,
        target_filename: str,
        overwrite: bool = True
    ) -> str:
        """Copy local file to destination directory."""
        dest_dir = Path(destination_folder_id)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / target_filename

        if dest_file.exists() and not overwrite:
            return str(dest_file)

        shutil.copy2(str(local_path), str(dest_file))
        return str(dest_file)

    def list_subdirectories(self, parent_folder_id: str) -> List[Dict[str, Any]]:
        """List subdirectories in the specified folder."""
        p = Path(parent_folder_id)
        if not p.is_dir():
            return []

        results = []
        for child in p.iterdir():
            if child.is_dir():
                stat = child.stat()
                results.append({
                    "id": str(child),
                    "name": child.name,
                    "created_time": stat.st_ctime
                })
        return results

    def delete_directory(self, folder_id: str) -> bool:
        """Recursively delete a directory."""
        p = Path(folder_id)
        if p.exists() and p.is_dir():
            shutil.rmtree(str(p), ignore_errors=True)
            return True
        return False
