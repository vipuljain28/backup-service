"""Unit tests for Directory Explorer and OWASP Path Traversal Guards."""

import os
from pathlib import Path
from backup_service.drivers.explorer import DirectoryExplorer, sanitize_path


def test_path_sanitization_traversal_prevention():
    # Relative path escape attempts must be normalized
    assert sanitize_path("/var/www/../../etc/passwd") == "/etc/passwd"
    assert sanitize_path("uploads/../../../secret.txt") == "/secret.txt"
    assert sanitize_path("") in ("/", "C:\\")


def test_local_directory_exploration():
    # Explore current workspace directory
    res = DirectoryExplorer.explore_local(".")
    assert res["error"] is None
    assert "items" in res
    assert len(res["items"]) > 0

    # Test non-existent path
    bad_res = DirectoryExplorer.explore_local("/non_existent_folder_xyz123_456")
    assert bad_res["error"] is not None
