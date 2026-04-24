"""API routes: /checks, /checks/{id}"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from app.services.evaluator import get_latest_summary

router = APIRouter(tags=["Checks"])


@router.get("/checks")
async def get_checks(component: Optional[str] = None, status: Optional[str] = None):
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    results = s.checks
    if component:
        results = [c for c in results if c.component.value == component]
    if status:
        results = [c for c in results if c.status.value == status]
    return [c.model_dump() for c in results]


@router.get("/checks/{check_id:path}")
async def get_check(check_id: str):
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    for c in s.checks:
        if c.id == check_id:
            return c.model_dump()
    raise HTTPException(status_code=404, detail=f"Check '{check_id}' not found")
