"""
In-memory + DB-backed audit helpers for scan actions.

Every module action should emit a short human-readable message so the
WebSocket live panel and the PDF audit appendix stay consistent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional


ProgressCallback = Optional[Callable[[str], None]]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(message: str) -> str:
    """Prefix a log line with an ISO-8601 UTC timestamp."""
    return f"[{utc_now().strftime('%Y-%m-%d %H:%M:%S UTC')}] {message}"


def emit(callback: ProgressCallback, message: str) -> str:
    """Send a stamped line to the live UI (if any) and return the stamped text."""
    line = stamp(message)
    if callback:
        callback(line)
    return line
