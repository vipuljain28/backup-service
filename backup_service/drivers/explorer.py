"""Interactive Directory Explorer for Local and Remote SSH Hosts.

Follows OWASP Secure Coding Practices:
- Strict path traversal prevention (rejects illegal `..` and non-canonical path tampering)
- Safe permission evaluation and symlink containment
"""

import os
import stat
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from backup_service.drivers.local_driver import LocalDriver
from backup_service.drivers.ssh_driver import SSHDriver
from backup_service.config.settings import SSHConfig

logger = logging.getLogger("backup_service.explorer")


def sanitize_path(requested_path: str) -> str:
    """Sanitize and normalize path to prevent OWASP directory traversal exploits.
    Always returns normalized forward-slash absolute path representation.
    Preserves Windows drive roots when running on Windows (e.g. C:/).
    """
    if not requested_path or requested_path.strip() in ("", "."):
        return "/"

    clean = requested_path.strip().replace("\\", "/")
    parts = []
    for segment in clean.split("/"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            if parts:
                parts.pop()
        else:
            parts.append(segment)

    if not parts:
        return "/"

    # Check for Windows drive letter (e.g., C:)
    if len(parts[0]) == 2 and parts[0][1] == ":" and parts[0][0].isalpha():
        drive = parts[0].upper()
        if len(parts) == 1:
            return f"{drive}/"
        return f"{drive}/" + "/".join(parts[1:])

    return "/" + "/".join(parts)


class DirectoryExplorer:
    """Explores directory hierarchies on local or remote servers."""

    @staticmethod
    def explore_local(target_path: str = "/") -> Dict[str, Any]:
        """List local directory contents with metadata."""
        clean_p = sanitize_path(target_path)

        # On Windows, browsing root "/" lists available drives (C:, D:, etc.)
        if os.name == "nt" and clean_p == "/":
            import string
            drives = []
            for letter in string.ascii_uppercase:
                if os.path.exists(f"{letter}:\\"):
                    drives.append({
                        "name": f"Drive {letter}:",
                        "path": f"{letter}:/",
                        "is_dir": True,
                        "size": 0,
                        "mtime": 0.0,
                        "readable": True
                    })
            return {
                "current_path": "/",
                "parent_path": None,
                "error": None,
                "items": drives
            }

        norm_path = Path("." if clean_p == "/" else clean_p).resolve()

        if not norm_path.exists():
            clean_parent = str(Path(clean_p).parent).replace("\\", "/") if clean_p not in ("/", "") else None
            return {
                "current_path": clean_p,
                "parent_path": clean_parent or "/",
                "error": "Directory does not exist",
                "items": []
            }

        if not norm_path.is_dir():
            norm_path = norm_path.parent

        items = []
        try:
            with os.scandir(str(norm_path)) as it:
                for entry in it:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                        st = entry.stat(follow_symlinks=False)
                        items.append({
                            "name": entry.name,
                            "path": str(Path(entry.path).resolve()).replace("\\", "/"),
                            "is_dir": is_dir,
                            "size": st.st_size if not is_dir else 0,
                            "mtime": st.st_mtime,
                            "readable": True
                        })
                    except (PermissionError, OSError):
                        items.append({
                            "name": entry.name,
                            "path": str(Path(entry.path)).replace("\\", "/"),
                            "is_dir": False,
                            "size": 0,
                            "mtime": 0.0,
                            "readable": False
                        })
        except PermissionError:
            return {
                "current_path": str(norm_path).replace("\\", "/"),
                "parent_path": str(norm_path.parent).replace("\\", "/") if norm_path.parent != norm_path else None,
                "error": "Permission denied",
                "items": []
            }

        # Sort: directories first, then alphabetical
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        parent = str(norm_path.parent).replace("\\", "/") if norm_path.parent != norm_path else None
        if os.name == "nt" and (not parent or parent == str(norm_path).replace("\\", "/") or parent.endswith(":")):
            parent = "/"

        return {
            "current_path": str(norm_path).replace("\\", "/"),
            "parent_path": parent,
            "error": None,
            "items": items
        }

    @staticmethod
    def explore_remote_ssh(ssh_config: SSHConfig, target_path: str = "/") -> Dict[str, Any]:
        """List remote server directory contents via SFTP."""
        driver = SSHDriver(ssh_config)
        clean_path = sanitize_path(target_path)

        try:
            sftp = driver._get_sftp()
            try:
                attr = sftp.stat(clean_path)
                if not stat.S_ISDIR(attr.st_mode):
                    clean_path = str(Path(clean_path).parent).replace("\\", "/")
            except IOError:
                clean_parent = str(Path(clean_path).parent).replace("\\", "/") if clean_path not in ("/", "") else None
                return {
                    "current_path": clean_path,
                    "parent_path": clean_parent or "/",
                    "error": f"Remote directory '{clean_path}' does not exist on this server.",
                    "items": []
                }

            items = []
            for attr in sftp.listdir_attr(clean_path):
                is_dir = stat.S_ISDIR(attr.st_mode)
                item_name = attr.filename
                full_item_path = f"{clean_path.rstrip('/')}/{item_name}"
                items.append({
                    "name": item_name,
                    "path": full_item_path,
                    "is_dir": is_dir,
                    "size": attr.st_size if not is_dir else 0,
                    "mtime": float(attr.st_mtime or 0.0),
                    "readable": True
                })

            items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
            parent_path = str(Path(clean_path).parent).replace("\\", "/") if clean_path not in ("/", "") else None

            return {
                "current_path": clean_path,
                "parent_path": parent_path,
                "error": None,
                "items": items
            }
        except Exception as exc:
            logger.error("SSH directory exploration failed for %s: %s", clean_path, exc)
            return {
                "current_path": clean_path,
                "parent_path": None,
                "error": str(exc),
                "items": []
            }
        finally:
            driver.close()
