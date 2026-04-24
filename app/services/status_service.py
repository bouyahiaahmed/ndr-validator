"""
Status service – convenience layer for querying and formatting status data.
Wraps the evaluator's in-memory summary for richer API/UI consumption.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Any
from app.services.evaluator import get_latest_summary
from app.models import Component, Status, StatusSummary


def get_overall_status() -> Status:
    s = get_latest_summary()
    return s.overall_status if s else Status.UNKNOWN


def get_component_summary(name: str) -> Optional[Dict[str, Any]]:
    s = get_latest_summary()
    if not s:
        return None
    for c in s.components:
        if c.name.value == name:
            return c.model_dump()
    return None


def get_sensor_summary(sensor_id: str) -> Optional[Dict[str, Any]]:
    s = get_latest_summary()
    if not s:
        return None
    for sen in s.sensors:
        if sen.sensor_ip == sensor_id or sen.display_name == sensor_id:
            return sen.model_dump()
    return None


def get_checks_by_status(status: str) -> List[Dict[str, Any]]:
    s = get_latest_summary()
    if not s:
        return []
    return [c.model_dump() for c in s.checks if c.status.value == status]


def get_checks_by_component(comp: str) -> List[Dict[str, Any]]:
    s = get_latest_summary()
    if not s:
        return []
    return [c.model_dump() for c in s.checks if c.component.value == comp]


def get_red_checks() -> List[Dict[str, Any]]:
    return get_checks_by_status("red")


def get_concise_status() -> Dict[str, Any]:
    """Return a minimal status payload suitable for monitoring integrations."""
    s = get_latest_summary()
    if not s:
        return {"status": "unknown", "message": "No scrape data yet"}
    return {
        "status": s.overall_status.value,
        "timestamp": s.timestamp.isoformat(),
        "config_fingerprint": s.config_fingerprint,
        "version": s.version,
        "components": {c.name.value: c.status.value for c in s.components},
        "check_count": len(s.checks),
        "red_count": sum(1 for c in s.checks if c.status == Status.RED),
        "yellow_count": sum(1 for c in s.checks if c.status == Status.YELLOW),
        "urgent_count": len(s.urgent_findings),
        "rates": {
            "vector_to_dp_drop_percent": s.rates.vector_to_dp_drop_percent,
            "dp_to_os_drop_percent": s.rates.dp_to_os_drop_percent,
            "overall_freshness_seconds": s.rates.overall_freshness_seconds,
        },
    }
