"""API routes: /history"""
from __future__ import annotations
from fastapi import APIRouter, Query
from app import db

router = APIRouter(tags=["History"])


@router.get("/history")
async def get_history(limit: int = Query(100, le=1000), offset: int = 0):
    records = await db.get_history(limit=limit, offset=offset)
    return [r.model_dump() for r in records]
