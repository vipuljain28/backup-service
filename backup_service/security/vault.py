"""Enterprise Cryptographic Vault using AES-256-GCM.

Provides authenticated encryption with associated data (AEAD) for sensitive
credentials: database passwords, SSH private keys, and cloud OAuth secrets.
"""

import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

KEY_FILE_NAME = ".vault_key"
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 100_000


def get_or_create_master_secret(app_root: Path = Path(".")) -> bytes:
    """Retrieve master secret from environment or load/create local key file."""
    env_secret = os.environ.get("BACKUP_MASTER_KEY")
    if env_secret:
        return env_secret.encode("utf-8")

    key_path = app_root / KEY_FILE_NAME
    if key_path.exists():
        return key_path.read_bytes().strip()

    # Generate cryptographically secure random 32-byte secret
    new_secret = base64.urlsafe_b64encode(os.urandom(32))
    key_path.write_bytes(new_secret)
    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass
    return new_secret


class CredentialVault:
    """AES-256-GCM Authenticated Encryption Vault."""

    def __init__(self, master_secret: bytes = None):
        self._secret = master_secret or get_or_create_master_secret()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(self._secret)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string using AES-256-GCM.
        
        Returns formatted string: v1:<salt_b64>:<nonce_b64>:<ciphertext_with_tag_b64>
        """
        if not plaintext:
            return ""

        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        data = plaintext.encode("utf-8")
        ciphertext_and_tag = aesgcm.encrypt(nonce, data, associated_data=b"vault_v1")

        salt_b64 = base64.b64encode(salt).decode("ascii")
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        ct_b64 = base64.b64encode(ciphertext_and_tag).decode("ascii")

        return f"v1:{salt_b64}:{nonce_b64}:{ct_b64}"

    def decrypt(self, encrypted_block: str) -> str:
        """Decrypt AES-256-GCM ciphertext block."""
        if not encrypted_block:
            return ""

        parts = encrypted_block.split(":")
        if len(parts) != 4 or parts[0] != "v1":
            raise ValueError("Malformed ciphertext format: expected v1:<salt>:<nonce>:<ciphertext>")

        salt = base64.b64decode(parts[1])
        nonce = base64.b64decode(parts[2])
        ct_and_tag = base64.b64decode(parts[3])

        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        decrypted_bytes = aesgcm.decrypt(nonce, ct_and_tag, associated_data=b"vault_v1")
        return decrypted_bytes.decode("utf-8")
