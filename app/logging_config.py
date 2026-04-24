"""
Structured logging configuration.
Uses standard library logging with JSON-structured output in production.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone

from app.config import settings


class StructuredFormatter(logging.Formatter):
    """JSON-style structured log formatter for production."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        msg = record.getMessage()
        base = (
            f'{{"ts":"{ts}","level":"{record.levelname}",'
            f'"logger":"{record.name}","msg":"{msg}"'
        )
        if record.exc_info and record.exc_info[1]:
            exc = self.formatException(record.exc_info).replace('"', '\\"').replace("\n", "\\n")
            base += f',"exception":"{exc}"'
        base += "}"
        return base


class HumanFormatter(logging.Formatter):
    """Human-readable formatter for dev environments."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        return f"[{ts}] {record.levelname:<7} {record.name}: {record.getMessage()}"


def setup_logging() -> None:
    """Configure root logger based on APP_ENV and LOG_LEVEL."""
    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Remove default handlers
    for h in root.handlers[:]:
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if settings.APP_ENV == "prod":
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(HumanFormatter())

    root.addHandler(handler)

    # Suppress noisy libraries
    for name in ("httpx", "httpcore", "asyncio", "paramiko", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger."""
    return logging.getLogger(name)
