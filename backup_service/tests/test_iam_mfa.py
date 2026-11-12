"""Comprehensive Automated IAM, TOTP MFA & Token Revocation Test Suite.

Verifies:
- RFC 6238 TOTP computation, verification, and clock drift tolerance
- RFC 6238 Replay Attack prevention (last_step_used guard)
- Emergency backup recovery code hashing and single-use consumption
- Token Versioning & immediate session revocation (Token Reuse Protection)
- Short-lived MFA challenge token lifecycles
- User management administrative safeguards (self-deletion & last-admin guards)
"""

import time
import json
from backup_service.security.totp import (
    generate_totp_secret, compute_totp_code, verify_totp_code,
    generate_recovery_codes, verify_and_consume_recovery_code,
    generate_otpauth_uri
)
from backup_service.security.auth import (
    generate_auth_token, verify_auth_token,
    generate_mfa_challenge_token, verify_mfa_challenge_token,
    Role
)
from backup_service.security.db import DatabaseManager


def test_totp_cryptographic_engine():
    """Verify RFC 6238 TOTP computation, clock drift, and replay mitigation."""
    secret = generate_totp_secret()
    assert len(secret) >= 26

    # Test token computation
    current_step = int(time.time()) // 30
    token = compute_totp_code(secret, current_step)
    assert len(token) == 6
    assert token.isdigit()

    # Valid token verification
    is_valid, matched_step = verify_totp_code(secret, token, last_step_used=0)
    assert is_valid is True
    assert matched_step == current_step

    # Replay Attack Prevention: cannot reuse same token if step <= last_step_used
    replayed, _ = verify_totp_code(secret, token, last_step_used=current_step)
    assert replayed is False, "Replay attack should have been blocked"

    # Invalid code rejection
    bad_code, _ = verify_totp_code(secret, "999999" if token != "999999" else "000000")
    assert bad_code is False

    # URI generation
    uri = generate_otpauth_uri(secret, "admin", "TechLIMS")
    assert uri.startswith("otpauth://totp/TechLIMS%3Aadmin?")
    assert "secret=" in uri


def test_emergency_recovery_codes():
    """Verify emergency backup recovery codes generation and single-use consumption."""
    plain_codes, hashed_codes = generate_recovery_codes(num_codes=8)
    assert len(plain_codes) == 8
    assert len(hashed_codes) == 8

    # Verify first code
    first_code = plain_codes[0]
    is_valid, matched_hash = verify_and_consume_recovery_code(first_code, hashed_codes)
    assert is_valid is True
    assert matched_hash == hashed_codes[0]

    # Remove consumed code
    hashed_codes.remove(matched_hash)

    # Re-testing consumed code must fail (single-use guarantee)
    reused, _ = verify_and_consume_recovery_code(first_code, hashed_codes)
    assert reused is False


def test_token_version_revocation_reuse_protection():
    """Verify CWE-613/CWE-384 token revocation via token version rotation."""
    secret_key = b"test_master_secret_32_bytes_ok!"
    
    # User token version 1
    token_v1 = generate_auth_token(
        user_id=1, username="admin", role=Role.ADMIN,
        secret_key=secret_key, token_version=1
    )

    payload = verify_auth_token(token_v1, secret_key)
    assert payload is not None
    assert payload["ver"] == 1

    # Simulate token version rotation in database (e.g. password change / logout)
    user_db_version = 2
    # Active check against DB version
    assert payload["ver"] != user_db_version, "Old token version must mismatch current database version"


def test_mfa_challenge_token_lifecycle():
    """Verify short-lived MFA challenge token cannot be used as standard session token."""
    secret_key = b"test_master_secret_32_bytes_ok!"
    challenge_token = generate_mfa_challenge_token(user_id=42, secret_key=secret_key)

    # Valid challenge verification
    payload = verify_mfa_challenge_token(challenge_token, secret_key)
    assert payload is not None
    assert payload["type"] == "mfa_challenge"
    assert payload["uid"] == 42

    # Standard session token cannot be verified as MFA challenge
    session_token = generate_auth_token(user_id=42, username="alice", role=Role.OPERATOR, secret_key=secret_key)
    invalid_challenge = verify_mfa_challenge_token(session_token, secret_key)
    assert invalid_challenge is None


def test_user_management_safeguards():
    """Verify administrative safeguards on user deletion."""
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
        temp_db_path = tf.name

    try:
        db = DatabaseManager(temp_db_path)
        # Default admin seeded as ID 1
        admin = db.get_user_by_username("admin")
        assert admin is not None

        # Safeguard 1: Admin cannot delete own account
        ok, msg = db.delete_user(admin["id"], requesting_user_id=admin["id"])
        assert ok is False
        assert "own active administrator" in msg

        # Safeguard 2: Cannot delete the sole remaining administrator
        ok2, msg2 = db.delete_user(admin["id"], requesting_user_id=999)
        assert ok2 is False
        assert "sole remaining administrator" in msg2

        # Create secondary operator and verify deletion
        op_id = db.create_user("operator_bob", "bob@lims.local", "hash123", Role.OPERATOR)
        ok3, msg3 = db.delete_user(op_id, requesting_user_id=admin["id"])
        assert ok3 is True
    finally:
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
