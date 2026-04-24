"""
Vector metrics collector – scrapes Prometheus metrics from each sensor's Vector instance.
Supports both current and legacy metric name families via alias mapping.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.config import settings
from app.utils.http import fetch_url
from app.utils.prometheus_parser import (
    MetricFamily,
    find_metric_value,
    parse_prometheus_text,
    sum_metric_values,
    get_samples_by_label,
)

logger = logging.getLogger(__name__)

# ── Metric alias mapping ────────────────────────────────────────────────
# Maps legacy metric names → canonical (current) names.
VECTOR_METRIC_ALIASES: Dict[str, str] = {
    "events_in_total": "component_received_events_total",
    "events_out_total": "component_sent_events_total",
    "processing_errors_total": "component_errors_total",
}

CANONICAL_METRICS = [
    "component_received_events_total",
    "component_sent_events_total",
    "component_errors_total",
    "component_received_bytes_total",
    "component_sent_bytes_total",
]

LEGACY_METRICS = [
    "events_in_total",
    "events_out_total",
    "processing_errors_total",
]


class VectorScrapeResult:
    """Result of scraping a single Vector instance."""

    __slots__ = (
        "sensor_ip",
        "reachable",
        "error",
        "latency_ms",
        "families",
        "raw_text",
        "metric_version",
        "received_events",
        "sent_events",
        "errors_total",
        "received_bytes",
        "sent_bytes",
        "components",
    )

    def __init__(self, sensor_ip: str):
        self.sensor_ip = sensor_ip
        self.reachable: bool = False
        self.error: Optional[str] = None
        self.latency_ms: float = 0.0
        self.families: Dict[str, MetricFamily] = {}
        self.raw_text: str = ""
        self.metric_version: str = "unknown"  # "current", "legacy", "unknown"
        self.received_events: float = 0.0
        self.sent_events: float = 0.0
        self.errors_total: float = 0.0
        self.received_bytes: float = 0.0
        self.sent_bytes: float = 0.0
        self.components: Dict[str, Dict[str, Any]] = {}


async def scrape_vector(sensor_ip: str) -> VectorScrapeResult:
    """Scrape Vector metrics from a single sensor."""
    result = VectorScrapeResult(sensor_ip)
    url = settings.vector_metrics_url(sensor_ip)

    status_code, body, latency, error = await fetch_url(url)
    result.latency_ms = latency

    if error or status_code != 200:
        result.error = error or f"HTTP {status_code}"
        return result

    result.reachable = True
    result.raw_text = body

    try:
        result.families = parse_prometheus_text(body)
    except Exception as e:
        result.error = f"parse_error: {e}"
        return result

    # Detect metric version
    result.metric_version = _detect_metric_version(result.families)

    # Extract canonical values with alias fallback
    result.received_events = sum_metric_values(
        result.families,
        "component_received_events_total",
        aliases=["events_in_total"],
    )
    result.sent_events = sum_metric_values(
        result.families,
        "component_sent_events_total",
        aliases=["events_out_total"],
    )
    result.errors_total = sum_metric_values(
        result.families,
        "component_errors_total",
        aliases=["processing_errors_total"],
    )
    result.received_bytes = sum_metric_values(
        result.families, "component_received_bytes_total"
    )
    result.sent_bytes = sum_metric_values(
        result.families, "component_sent_bytes_total"
    )

    # Discover per-component metrics
    result.components = _extract_components(result.families, result.metric_version)

    return result


def _detect_metric_version(families: Dict[str, MetricFamily]) -> str:
    """Detect whether metrics are current or legacy."""
    family_names = set(families.keys())
    has_current = any(m in family_names or f"{m}" in family_names for m in CANONICAL_METRICS)
    has_legacy = any(m in family_names for m in LEGACY_METRICS)

    # Also check sample names
    for fam in families.values():
        for s in fam.samples:
            if s.name in CANONICAL_METRICS or s.name.replace("_total", "") + "_total" in CANONICAL_METRICS:
                has_current = True
            if s.name in LEGACY_METRICS:
                has_legacy = True

    if has_current and not has_legacy:
        return "current"
    if has_legacy and not has_current:
        return "legacy"
    if has_current and has_legacy:
        return "current"  # Prefer current when both present
    return "unknown"


def _extract_components(
    families: Dict[str, MetricFamily], version: str
) -> Dict[str, Dict[str, Any]]:
    """Extract per-component metrics from Vector families."""
    components: Dict[str, Dict[str, Any]] = {}
    label_key = "component_id" if version == "current" else "component_id"

    for fam in families.values():
        for sample in fam.samples:
            comp_id = sample.labels.get("component_id") or sample.labels.get("component_name", "")
            if not comp_id:
                continue
            if comp_id not in components:
                components[comp_id] = {
                    "component_kind": sample.labels.get("component_kind", ""),
                    "component_type": sample.labels.get("component_type", ""),
                    "metrics": {},
                }
            components[comp_id]["metrics"][sample.name] = sample.value

    return components


async def scrape_all_sensors() -> List[VectorScrapeResult]:
    """Scrape Vector metrics from all configured sensors."""
    import asyncio

    tasks = [scrape_vector(ip) for ip in settings.sensor_ips]
    if not tasks:
        return []
    return await asyncio.gather(*tasks)


def get_flat_metrics(result: VectorScrapeResult) -> Dict[str, float]:
    """Return a flat dict of canonical metric values for snapshot storage."""
    return {
        "received_events": result.received_events,
        "sent_events": result.sent_events,
        "errors_total": result.errors_total,
        "received_bytes": result.received_bytes,
        "sent_bytes": result.sent_bytes,
    }
