"""API routes: /metrics (Prometheus exposition)"""
from __future__ import annotations
from fastapi import APIRouter
from fastapi.responses import Response
from app.metrics import generate_metrics, get_content_type

router = APIRouter(tags=["Metrics"])


@router.get("/metrics")
async def get_metrics():
    data = generate_metrics()
    return Response(content=data, media_type=get_content_type())
