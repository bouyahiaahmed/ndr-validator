"""Time utilities for freshness computation and formatting."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def seconds_ago(ts: Optional[datetime]) -> Optional[float]:
    """Return seconds since the given timestamp, or None if ts is None."""
    if ts is None:
        return None
    now = utcnow()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds()


def format_duration(seconds: Optional[float]) -> str:
    """Human-readable duration string."""
    if seconds is None:
        return "N/A"
    if seconds < 0:
        return "in the future"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def parse_iso_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse an ISO timestamp string, returning None on failure."""
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def parse_epoch_ms(epoch_ms: float) -> datetime:
    """Convert epoch milliseconds to datetime."""
    return datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
