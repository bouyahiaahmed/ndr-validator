"""API routes: /checks, /checks/actionable"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from app.services.evaluator import get_latest_summary
from app.models import Status

router = APIRouter(tags=["Checks"])


@router.get("/checks")
async def get_checks():
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    return [c.model_dump() for c in s.checks]


@router.get("/checks/actionable")
async def get_actionable_checks():
    """
    Returns all red/yellow checks with their diagnosis field populated.
    Sorted by severity (critical first) then status (red first).
    This is the primary endpoint for 'what is broken and how to fix it'.
    """
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    status_order = {Status.RED: 0, Status.YELLOW: 1, Status.UNKNOWN: 2}

    actionable = [
        c for c in s.checks
        if c.status in (Status.RED, Status.YELLOW, Status.UNKNOWN)
    ]
    actionable.sort(key=lambda c: (
        status_order.get(c.status, 9),
        severity_order.get(c.severity, 9),
    ))
    return [c.model_dump() for c in actionable]
