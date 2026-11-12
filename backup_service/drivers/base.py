"""Abstract base driver for interacting with source filesystems and databases."""

from abc import ABC, abstractmethod
from typing import Generator, List, Optional
from pathlib import Path
from dataclasses import dataclass
from backup_service.config.settings import DatabaseConfig


@dataclass
class SourceFileInfo:
    source_id: str
    rel_path: str
    abs_path_or_remote: str
    size: int
    mtime: float


class SourceDriver(ABC):
    """Abstract interface for local or remote host data extraction."""

    @abstractmethod
    def test_connection(self) -> bool:
        """Verify host connectivity and necessary permissions."""
        pass

    @abstractmethod
    def scan_source_files(
        self,
        source_id: str,
        base_path: str,
        exclude_patterns: List[str]
    ) -> Generator[SourceFileInfo, None, None]:
        """Scan directory and yield FileInfo for each eligible file."""
        pass

    @abstractmethod
    def fetch_file(self, file_info: SourceFileInfo, local_dest: Path) -> Path:
        """Fetch or copy the source file into local staging."""
        pass

    def fetch_files_batch(
        self,
        tasks: List[tuple],
        max_workers: int = 8,
        progress_callback: Optional[object] = None
    ) -> List[tuple]:
        """Fetch multiple files in batch. Defaults to sequential fetch_file if not overridden."""
        results = []
        for file_info, local_dest in tasks:
            try:
                self.fetch_file(file_info, local_dest)
                results.append((file_info, local_dest, None))
            except Exception as exc:
                results.append((file_info, local_dest, exc))
        return results

    @abstractmethod
    def dump_database(
        self,
        db_config: DatabaseConfig,
        local_output_path: Path
    ) -> int:
        """Perform database dump, compress with gzip, and write to local_output_path.
        
        Returns total bytes written.
        """
        pass

    def verify_database_access(self, db_config: DatabaseConfig) -> None:
        """Verify database connectivity and credentials without dumping data."""
        pass

    def close(self):
        """Clean up open connections or sessions."""
        pass
