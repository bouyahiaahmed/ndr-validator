"""
SQLite persistence layer for history, metric snapshots, and state.
Uses aiosqlite for async operations.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

import aiosqlite

from app.config import settings
from app.models import HistoryRecord, MetricSnapshot

logger = logging.getLogger(__name__)

_db_path: str = settings.SQLITE_DB_PATH
_conn: Optional[aiosqlite.Connection] = None


async def init_db() -> None:
    """Initialize database and create tables."""
    global _conn
    _conn = await aiosqlite.connect(_db_path)
    _conn.row_factory = aiosqlite.Row
    await _conn.execute("PRAGMA journal_mode=WAL")
    await _conn.execute("PRAGMA synchronous=NORMAL")

    await _conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            overall_status TEXT NOT NULL,
            component_statuses TEXT NOT NULL DEFAULT '{}',
            check_count INTEGER NOT NULL DEFAULT 0,
            red_count INTEGER NOT NULL DEFAULT 0,
            yellow_count INTEGER NOT NULL DEFAULT 0,
            green_count INTEGER NOT NULL DEFAULT 0,
            summary_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_history_ts ON history(timestamp DESC);

        CREATE TABLE IF NOT EXISTS metric_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            metrics_json TEXT NOT NULL DEFAULT '{}',
            labels_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS idx_snapshot_source_ts
            ON metric_snapshots(source, timestamp DESC);

        CREATE TABLE IF NOT EXISTS scrape_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    await _conn.commit()
    logger.info("Database initialized at %s", _db_path)


async def close_db() -> None:
    global _conn
    if _conn:
        await _conn.close()
        _conn = None


def _get_conn() -> aiosqlite.Connection:
    if _conn is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _conn


# ── History ────────────────────────────────────────────────────────────

async def save_history(record: HistoryRecord) -> int:
    conn = _get_conn()
    cursor = await conn.execute(
        """
        INSERT INTO history (timestamp, overall_status, component_statuses,
                             check_count, red_count, yellow_count, green_count, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.timestamp.isoformat(),
            record.overall_status.value,
            json.dumps(record.component_statuses),
            record.check_count,
            record.red_count,
            record.yellow_count,
            record.green_count,
            record.summary_json,
        ),
    )
    await conn.commit()
    return cursor.lastrowid  # type: ignore[return-value]


async def get_history(limit: int = 100, offset: int = 0) -> List[HistoryRecord]:
    conn = _get_conn()
    rows = await conn.execute_fetchall(
        "SELECT * FROM history ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    results = []
    for row in rows:
        results.append(
            HistoryRecord(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                overall_status=row["overall_status"],
                component_statuses=json.loads(row["component_statuses"]),
                check_count=row["check_count"],
                red_count=row["red_count"],
                yellow_count=row["yellow_count"],
                green_count=row["green_count"],
                summary_json=row["summary_json"],
            )
        )
    return results


# ── Metric Snapshots ──────────────────────────────────────────────────

async def save_snapshot(snap: MetricSnapshot) -> None:
    conn = _get_conn()
    await conn.execute(
        """
        INSERT INTO metric_snapshots (source, timestamp, metrics_json, labels_json)
        VALUES (?, ?, ?, ?)
        """,
        (
            snap.source,
            snap.timestamp.isoformat(),
            json.dumps(snap.metrics),
            json.dumps(snap.labels),
        ),
    )
    await conn.commit()


async def get_latest_snapshot(source: str) -> Optional[MetricSnapshot]:
    conn = _get_conn()
    rows = await conn.execute_fetchall(
        "SELECT * FROM metric_snapshots WHERE source = ? ORDER BY timestamp DESC LIMIT 1",
        (source,),
    )
    if not rows:
        return None
    row = rows[0]
    return MetricSnapshot(
        source=row["source"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        metrics=json.loads(row["metrics_json"]),
        labels=json.loads(row["labels_json"]),
    )


async def get_previous_snapshot(source: str) -> Optional[MetricSnapshot]:
    """Get the second-most-recent snapshot for delta computation."""
    conn = _get_conn()
    rows = await conn.execute_fetchall(
        "SELECT * FROM metric_snapshots WHERE source = ? ORDER BY timestamp DESC LIMIT 2",
        (source,),
    )
    if len(rows) < 2:
        return None
    row = rows[1]
    return MetricSnapshot(
        source=row["source"],
        timestamp=datetime.fromisoformat(row["timestamp"]),
        metrics=json.loads(row["metrics_json"]),
        labels=json.loads(row["labels_json"]),
    )


async def cleanup_old_snapshots(max_age_hours: int = 48) -> int:  # noqa: ARG001
    """Remove snapshots beyond the per-source rolling window (500 most recent)."""
    conn = _get_conn()
    cursor = await conn.execute(
        """
        DELETE FROM metric_snapshots WHERE id NOT IN (
            SELECT id FROM (
                SELECT id, ROW_NUMBER() OVER (PARTITION BY source ORDER BY timestamp DESC) as rn
                FROM metric_snapshots
            ) WHERE rn <= 500
        )
        """
    )
    await conn.commit()
    return cursor.rowcount


async def cleanup_old_history(max_records: int = 10000) -> int:
    conn = _get_conn()
    cursor = await conn.execute(
        """
        DELETE FROM history WHERE id NOT IN (
            SELECT id FROM history ORDER BY timestamp DESC LIMIT ?
        )
        """,
        (max_records,),
    )
    await conn.commit()
    return cursor.rowcount


# ── Scrape State ──────────────────────────────────────────────────────

async def set_state(key: str, value: str) -> None:
    conn = _get_conn()
    now = datetime.now(timezone.utc).isoformat()
    await conn.execute(
        """
        INSERT INTO scrape_state (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """,
        (key, value, now),
    )
    await conn.commit()


async def get_state(key: str) -> Optional[str]:
    conn = _get_conn()
    rows = await conn.execute_fetchall(
        "SELECT value FROM scrape_state WHERE key = ?", (key,)
    )
    if rows:
        return rows[0]["value"]
    return None


async def is_db_ready() -> bool:
    """Quick readiness check."""
    try:
        conn = _get_conn()
        await conn.execute_fetchall("SELECT 1")
        return True
    except Exception:
        return False
