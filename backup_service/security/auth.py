"""Authentication and Role-Based Access Control (RBAC) Module."""

import os
import hmac
import json
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

TOKEN_EXPIRATION_HOURS = 12
HASH_ITERATIONS = 100_000


class Role:
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"

    ALL_ROLES = [ADMIN, OPERATOR, AUDITOR]


def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with random salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, HASH_ITERATIONS)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"pbkdf2_sha256${HASH_ITERATIONS}${salt_b64}${key_b64}"


def verify_password(password: str, hashed_value: str) -> bool:
    """Verify password against stored PBKDF2 hash using constant-time comparison."""
    try:
        parts = hashed_value.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected_key = base64.b64decode(parts[3])

        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(key, expected_key)
    except Exception:
        return False


def generate_auth_token(user_id: int, username: str, role: str, secret_key: bytes) -> str:
    """Generate tamper-proof signed session token."""
    payload = {
        "uid": user_id,
        "sub": username,
        "role": role,
        "exp": (datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRATION_HOURS)).timestamp(),
        "iat": datetime.now(timezone.utc).timestamp(),
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii")

    signature = hmac.new(secret_key, payload_b64.encode("ascii"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii")

    return f"{payload_b64}.{sig_b64}"


def verify_auth_token(token: str, secret_key: bytes) -> Optional[Dict[str, Any]]:
    """Validate token signature and expiration, returning user payload or None."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None

        payload_b64, sig_b64 = parts
        expected_sig = hmac.new(secret_key, payload_b64.encode("ascii"), hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64.encode("ascii"))

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_json = base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8")
        payload = json.loads(payload_json)

        # Check expiration
        exp = payload.get("exp", 0)
        if datetime.now(timezone.utc).timestamp() > exp:
            return None

        return payload
    except Exception:
        return None


def has_permission(user_role: str, action: str) -> bool:
    """RBAC Permission Matrix Evaluator."""
    if user_role == Role.ADMIN:
        return True  # Full superuser access

    if user_role == Role.OPERATOR:
        # Operator can run operations, test connections, view data, but cannot edit users or system secrets
        forbidden_for_operators = {"manage_users", "edit_system_settings", "wipe_database"}
        return action not in forbidden_for_operators

    if user_role == Role.AUDITOR:
        # Auditor is strictly read-only
        allowed_for_auditors = {"view_dashboard", "view_clients", "view_jobs", "view_logs", "view_manifests"}
        return action in allowed_for_auditors

    return False
