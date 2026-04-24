"""
History service – convenience wrappers around db.get_history.
Thin layer kept for future extension (e.g., trend computation).
"""
from __future__ import annotations
from typing import List
from app import db
from app.models import HistoryRecord


async def get_recent_history(limit: int = 100, offset: int = 0) -> List[HistoryRecord]:
    return await db.get_history(limit=limit, offset=offset)


async def get_history_summary(limit: int = 100) -> dict:
    records = await db.get_history(limit=limit)
    if not records:
        return {"count": 0, "red_pct": 0.0, "yellow_pct": 0.0, "green_pct": 0.0}
    n = len(records)
    red = sum(1 for r in records if r.overall_status.value == "red")
    yellow = sum(1 for r in records if r.overall_status.value == "yellow")
    green = sum(1 for r in records if r.overall_status.value == "green")
    return {
        "count": n,
        "red_pct": round(red / n * 100, 1),
        "yellow_pct": round(yellow / n * 100, 1),
        "green_pct": round(green / n * 100, 1),
    }
