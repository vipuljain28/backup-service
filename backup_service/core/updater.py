"""GitHub Self-Update and Version Diagnostics Subsystem."""

import subprocess
import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger("backup_service.updater")


class GitHubUpdater:
    """Manages version verification and automated GitHub updates."""

    def __init__(self, repo_owner: str = "vipuljain28", repo_name: str = "backup-service"):
        self.repo_owner = repo_owner
        self.repo_name = repo_name

    def get_local_version(self) -> Dict[str, Any]:
        """Query local git repository for active branch and commit hash."""
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
            branch = subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()
            return {"branch": branch, "commit": commit, "is_git": True}
        except Exception:
            return {"branch": "release", "commit": "v1.0.0", "is_git": False}

    def check_for_updates(self) -> Dict[str, Any]:
        """Compare local version with remote GitHub release/repository status."""
        local = self.get_local_version()
        info = {
            "local_commit": local["commit"],
            "local_branch": local["branch"],
            "update_available": False,
            "latest_release": "v1.0.0",
            "release_notes": "Up to date with current enterprise standards.",
            "status": "UP_TO_DATE"
        }

        try:
            url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/releases/latest"
            resp = requests.get(url, timeout=5, headers={"Accept": "application/vnd.github.v3+json"})
            if resp.status_code == 200:
                data = resp.json()
                tag = data.get("tag_name", "v1.0.0")
                info["latest_release"] = tag
                info["release_notes"] = data.get("body", "")
                if tag != local["commit"]:
                    info["update_available"] = True
                    info["status"] = "UPDATE_AVAILABLE"
            else:
                info["status"] = "OFFLINE_CHECK_COMPLETE"
        except Exception as exc:
            logger.debug("Remote GitHub update check returned: %s", exc)
            info["status"] = "CHECK_SKIPPED_NETWORK"

        return info

    def perform_git_pull(self) -> Dict[str, Any]:
        """Perform non-destructive git fast-forward update."""
        local = self.get_local_version()
        if not local["is_git"]:
            return {"success": False, "message": "Instance was not deployed via git clone."}

        try:
            out = subprocess.check_output(
                ["git", "pull", "--ff-only"],
                stderr=subprocess.STDOUT,
                text=True
            )
            logger.info("Executed git pull update: %s", out.strip())
            return {"success": True, "output": out.strip()}
        except subprocess.CalledProcessError as err:
            logger.error("Git pull failed: %s", err.output)
            return {"success": False, "error": err.output}
