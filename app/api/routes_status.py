"""API routes: /status, /components, /sensors"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from app.services.evaluator import get_latest_summary
from app.models import StatusSummary

router = APIRouter(tags=["Status"])


@router.get("/status", response_model=StatusSummary)
async def get_status():
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    return s


@router.get("/components")
async def get_components():
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    return [c.model_dump() for c in s.components]


@router.get("/components/{name}")
async def get_component(name: str):
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    for c in s.components:
        if c.name.value == name:
            return c.model_dump()
    raise HTTPException(status_code=404, detail=f"Component '{name}' not found")


@router.get("/sensors")
async def get_sensors():
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    return [sen.model_dump() for sen in s.sensors]


@router.get("/sensors/{sensor_id}")
async def get_sensor(sensor_id: str):
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    for sen in s.sensors:
        if sen.sensor_ip == sensor_id or sen.display_name == sensor_id:
            return sen.model_dump()
    raise HTTPException(status_code=404, detail=f"Sensor '{sensor_id}' not found")
