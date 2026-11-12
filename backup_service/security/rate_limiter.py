"""Thread-safe Sliding Window Rate Limiter & Brute-Force Defense Engine.

Adheres to OWASP Authentication Guidelines:
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- Sliding-window tracking of failed login attempts per IP and username
- Exponential lockout threshold (default: 5 failures / 5 min triggers 15 min lock)
"""

import time
import threading
from typing import Dict, List, Tuple


class RateLimiter:
    """In-memory thread-safe rate limiter with automatic lockout window."""

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures: Dict[str, List[float]] = {}
        self._lockouts: Dict[str, float] = {}
        self._lock = threading.Lock()

    def is_locked(self, key: str) -> Tuple[bool, int]:
        """Check if key (IP or username) is currently locked out.
        Returns: (is_locked: bool, retry_after_seconds: int)
        """
        now = time.time()
        with self._lock:
            lockout_until = self._lockouts.get(key)
            if lockout_until:
                if now < lockout_until:
                    return True, max(1, int(lockout_until - now))
                else:
                    # Lockout expired
                    del self._lockouts[key]
                    self._failures.pop(key, None)
            return False, 0

    def record_failure(self, key: str) -> Tuple[bool, int]:
        """Record a failed authentication attempt.
        Returns: (is_now_locked: bool, retry_after_seconds: int)
        """
        now = time.time()
        with self._lock:
            # Check if already locked
            lockout_until = self._lockouts.get(key)
            if lockout_until and now < lockout_until:
                return True, max(1, int(lockout_until - now))

            # Maintain sliding window
            attempts = self._failures.setdefault(key, [])
            # Evict attempts outside window
            cutoff = now - self.window_seconds
            attempts = [t for t in attempts if t > cutoff]
            attempts.append(now)
            self._failures[key] = attempts

            if len(attempts) >= self.max_attempts:
                lockout_until = now + self.lockout_seconds
                self._lockouts[key] = lockout_until
                return True, self.lockout_seconds

            return False, 0

    def reset(self, key: str) -> None:
        """Clear failed attempts upon successful authentication."""
        with self._lock:
            self._failures.pop(key, None)
            self._lockouts.pop(key, None)

    def cleanup_expired(self) -> None:
        """Periodic garbage collection for stale memory entries."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            # Cleanup failures
            for k in list(self._failures.keys()):
                self._failures[k] = [t for t in self._failures[k] if t > cutoff]
                if not self._failures[k]:
                    del self._failures[k]
            # Cleanup expired lockouts
            for k in list(self._lockouts.keys()):
                if now >= self._lockouts[k]:
                    del self._lockouts[k]


# Global singleton rate limiter for auth endpoints
auth_rate_limiter = RateLimiter(
    max_attempts=5,
    window_seconds=300,       # 5 minutes window
    lockout_seconds=900       # 15 minutes lockout
)
