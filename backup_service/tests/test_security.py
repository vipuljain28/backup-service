"""Unit tests for Security: AES-256-GCM Vault, Password Hashing & RBAC."""

import os
from backup_service.security.vault import CredentialVault
from backup_service.security.auth import (
    hash_password, verify_password, generate_auth_token, verify_auth_token,
    Role, has_permission
)


def test_vault_encryption_and_tamper_detection():
    secret = b"test_master_secret_32_bytes_long!!"
    vault = CredentialVault(secret)

    plaintext = "SuperSecretDatabasePassword_2026!"
    ciphertext = vault.encrypt(plaintext)

    assert ciphertext.startswith("v1:")
    assert plaintext not in ciphertext

    # Decrypt
    decrypted = vault.decrypt(ciphertext)
    assert decrypted == plaintext

    # Tamper detection: modifying ciphertext must raise exception
    tampered = ciphertext[:-4] + "AAAA"
    try:
        vault.decrypt(tampered)
        assert False, "Tampered ciphertext should have raised decryption error"
    except Exception:
        pass


def test_password_hashing():
    pwd = "AdminSecurePassword_123!"
    hashed = hash_password(pwd)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_auth_token_lifecycle():
    secret = b"token_signing_key_secret_32bytes!"
    token = generate_auth_token(user_id=1, username="admin", role=Role.ADMIN, secret_key=secret)

    payload = verify_auth_token(token, secret)
    assert payload is not None
    assert payload["uid"] == 1
    assert payload["sub"] == "admin"
    assert payload["role"] == Role.ADMIN

    # Test invalid signature
    bad_secret = b"wrong_signing_key_32bytes_long!!"
    assert verify_auth_token(token, bad_secret) is None


def test_rbac_permission_matrix():
    assert has_permission(Role.ADMIN, "manage_users") is True
    assert has_permission(Role.ADMIN, "trigger_backup") is True

    # Operator cannot manage users, but can trigger backups
    assert has_permission(Role.OPERATOR, "manage_users") is False
    assert has_permission(Role.OPERATOR, "trigger_backup") is True

    # Auditor is strictly read-only
    assert has_permission(Role.AUDITOR, "trigger_backup") is False
    assert has_permission(Role.AUDITOR, "view_dashboard") is True
