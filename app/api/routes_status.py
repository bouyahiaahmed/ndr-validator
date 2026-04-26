"""API routes: /status, /components, /sensors, /readiness, /validation/synthetic-check"""
from __future__ import annotations
import textwrap
from fastapi import APIRouter, HTTPException
from app.services.evaluator import get_latest_summary
from app.models import StatusSummary, ProductionReadiness
from app.config import settings

router = APIRouter(tags=["Status"])


@router.get("/status", response_model=StatusSummary)
async def get_status():
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    return s


@router.get("/readiness", response_model=ProductionReadiness)
async def get_readiness():
    """Production readiness score and classification (0-100, blocking issues, warnings)."""
    s = get_latest_summary()
    if s is None:
        raise HTTPException(status_code=503, detail="No scrape data yet")
    return s.readiness


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


@router.post("/validation/synthetic-check")
async def synthetic_check_workflow():
    """
    Returns a documented production validation workflow.

    This endpoint does NOT generate traffic itself — you must run the commands
    from each sensor (or a test host on the same segment). After generating
    traffic, wait one SCRAPE_INTERVAL_SECONDS cycle and call GET /status to
    confirm freshness improved.
    """
    interval = settings.SCRAPE_INTERVAL_SECONDS
    sensors = settings.sensor_ips or ["<sensor-ip>"]
    log_types = ["conn", "dns", "http", "ssl"]
    pattern = settings.sensor_liveness_pattern

    sensor_commands = []
    for s in sensors:
        name = settings.sensor_display_name(s)
        sensor_commands.append({
            "sensor": name,
            "ip": s,
            "commands": [
                f"# Generate DNS traffic",
                f"dig +short google.com @8.8.8.8",
                f"# Generate HTTP traffic",
                f"curl -s http://example.com -o /dev/null",
                f"# Generate TLS traffic",
                f"curl -s https://example.com -o /dev/null",
                f"# Generate additional conn traffic",
                f"nc -z -w2 8.8.8.8 443 || true",
            ],
        })

    return {
        "workflow": "NDR Stack Synthetic Validation",
        "description": textwrap.dedent("""
            Run the commands below from each sensor (or a host on the same network segment).
            After running, wait one scrape interval for the pipeline to ingest the data,
            then call GET /status or GET /readiness to confirm coverage improved.
        """).strip(),
        "steps": [
            {
                "step": 1,
                "action": "Generate test traffic on each sensor",
                "sensors": sensor_commands,
            },
            {
                "step": 2,
                "action": f"Wait {interval} seconds (one scrape interval)",
                "command": f"sleep {interval}",
            },
            {
                "step": 3,
                "action": "Check freshness per sensor and log type",
                "endpoint": "GET /status",
                "check_ids": [
                    f"freshness.sensor_liveness.<sensor_ip>",
                    f"freshness.detection_coverage.{lt}"
                    for lt in log_types
                ],
            },
            {
                "step": 4,
                "action": "Check overall readiness",
                "endpoint": "GET /readiness",
                "success_criteria": "readiness_level = production_ready or production_candidate",
            },
            {
                "step": 5,
                "action": "Review actionable failures",
                "endpoint": "GET /checks/actionable",
                "description": "Lists all red/yellow checks with diagnosis, fix_location, and next_steps",
            },
        ],
        "index_pattern_used_for_liveness": pattern,
        "required_log_types": log_types,
        "scrape_interval_seconds": interval,
        "tips": [
            f"Set SENSOR_LIVENESS_INDEX_PATTERN=zeek-* (broad) to avoid false 'sensor dead' alerts from quiet conn/http logs.",
            f"Set CONTINUOUS_REQUIRED_LOG_TYPES=conn,dns if these must always be present (makes stale RED, not YELLOW).",
            "Use DP_TO_OS_CORRELATION_INDEX_PATTERN=zeek-* to enable the DP→OS drop-rate check with correct scope.",
        ],
    }
