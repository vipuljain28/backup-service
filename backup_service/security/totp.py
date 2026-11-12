"""RFC 6238 Time-Based One-Time Password (TOTP) Cryptographic Engine.

Pure Python standard library implementation adhering to:
- RFC 4226: HMAC-Based One-Time Password Algorithm (HOTP)
- RFC 6238: Time-Based One-Time Password Algorithm (TOTP)
- Compatible with Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden, Authy
"""

import os
import time
import hmac
import struct
import base64
import hashlib
import secrets
import urllib.parse
from typing import Tuple, List, Optional, Dict, Any


def generate_totp_secret(num_bytes: int = 20) -> str:
    """Generate 160-bit cryptographically secure random secret (Base32 encoded)."""
    return base64.b32encode(os.urandom(num_bytes)).decode("ascii").rstrip("=")


def format_secret_for_display(secret_b32: str) -> str:
    """Format Base32 secret with spaces in 4-character chunks for human readability."""
    clean = secret_b32.upper().replace(" ", "")
    return " ".join([clean[i:i+4] for i in range(0, len(clean), 4)])


def generate_otpauth_uri(secret_b32: str, account_name: str, issuer: str = "TechLIMS") -> str:
    """Construct RFC standard otpauth:// URI for authenticator QR scanning."""
    label = f"{issuer}:{account_name}"
    params = {
        "secret": secret_b32.upper().replace(" ", ""),
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    }
    return f"otpauth://totp/{urllib.parse.quote(label)}?{urllib.parse.urlencode(params)}"


def compute_totp_code(secret_b32: str, time_step: Optional[int] = None) -> str:
    """Compute 6-digit TOTP token for given 30-second time-step interval."""
    if time_step is None:
        time_step = int(time.time()) // 30

    clean_secret = secret_b32.upper().replace(" ", "")
    missing_padding = len(clean_secret) % 8
    if missing_padding:
        clean_secret += "=" * (8 - missing_padding)

    key = base64.b32decode(clean_secret, casefold=True)
    msg = struct.pack(">Q", time_step)

    # HMAC-SHA1 signature
    digest = hmac.new(key, msg, hashlib.sha1).digest()

    # Dynamic 4-byte truncation (RFC 4226 §5.4)
    offset = digest[19] & 0x0F
    code_int = (
        (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    )
    return f"{code_int:06d}"


def verify_totp_code(
    secret_b32: str,
    submitted_code: str,
    last_step_used: int = 0,
    window: int = 1
) -> Tuple[bool, int]:
    """Verify submitted code with clock drift tolerance and replay attack mitigation.
    
    Args:
        secret_b32: Base32 shared secret
        submitted_code: 6-digit user string
        last_step_used: Replay prevention counter from database
        window: Number of steps to check before and after current step (1 = +/- 30s)
        
    Returns:
        (is_valid: bool, matched_time_step: int)
    """
    clean_code = submitted_code.strip().replace(" ", "").replace("-", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False, 0

    current_step = int(time.time()) // 30

    # Test intervals: [current - window, ..., current + window]
    for step in range(current_step - window, current_step + window + 1):
        # RFC 6238 Replay Attack Protection: cannot reuse code from the same or earlier step
        if step <= last_step_used:
            continue

        expected = compute_totp_code(secret_b32, step)
        if hmac.compare_digest(expected, clean_code):
            return True, step

    return False, 0


def generate_recovery_codes(num_codes: int = 8) -> Tuple[List[str], List[str]]:
    """Generate cryptographically secure one-time recovery codes.
    
    Returns:
        (plain_codes: List[str], hashed_codes: List[str])
    """
    plain_codes = []
    hashed_codes = []
    for _ in range(num_codes):
        # 8-char hex code formatted as XXXX-XXXX
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        code = f"{part1}-{part2}"
        plain_codes.append(code)

        # Hash code with SHA-256 for secure database storage
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        hashed_codes.append(code_hash)

    return plain_codes, hashed_codes


def verify_and_consume_recovery_code(
    submitted_code: str,
    stored_hashes: List[str]
) -> Tuple[bool, Optional[str]]:
    """Verify an emergency recovery code against stored hashes.
    
    Returns:
        (is_valid: bool, matched_hash_to_remove: Optional[str])
    """
    clean_code = submitted_code.strip().upper().replace(" ", "")
    # Support both XXXX-XXXX and XXXXXXXX formats
    if len(clean_code) == 8 and "-" not in clean_code:
        clean_code = f"{clean_code[:4]}-{clean_code[4:]}"

    submitted_hash = hashlib.sha256(clean_code.encode("utf-8")).hexdigest()

    for stored_hash in stored_hashes:
        if hmac.compare_digest(stored_hash, submitted_hash):
            return True, stored_hash

    return False, None
