"""
Token-bucket style rate limiter for outbound HTTP/DNS work.

Modules share one limiter so a full multi-module scan does not flood targets.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Simple thread-safe token bucket (requests per second)."""

    def __init__(self, rate_per_second: float = 5.0) -> None:
        self._rate = max(0.1, float(rate_per_second))
        self._tokens = self._rate
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def configure(self, rate_per_second: float) -> None:
        """Update the rate at runtime (Settings page)."""
        with self._lock:
            self._rate = max(0.1, float(rate_per_second))
            self._tokens = min(self._tokens, self._rate)

    def wait(self) -> None:
        """Block until a token is available, then consume one."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self._rate, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Seconds until next token
                need = (1.0 - self._tokens) / self._rate
            time.sleep(max(need, 0.01))


# Process-wide default limiter (scan orchestrator may replace/configure it)
default_limiter = RateLimiter()
