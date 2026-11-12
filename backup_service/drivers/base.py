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

    def close(self):
        """Clean up open connections or sessions."""
        pass
