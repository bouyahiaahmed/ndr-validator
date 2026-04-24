"""
Vector metrics collector – scrapes Prometheus metrics from each sensor's Vector instance.
Supports current (component_*), vector_-prefixed current, and legacy metric name families.
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

# ── Metric name sets ────────────────────────────────────────────────────────
# Current canonical names (without vector_ prefix)
_CANONICAL = [
    "component_received_events_total",
    "component_sent_events_total",
    "component_errors_total",
    "component_received_bytes_total",
    "component_sent_bytes_total",
]
# vector_-prefixed variant (Vector ≥ 0.37 ships these)
_VECTOR_PREFIXED = [f"vector_{m}" for m in _CANONICAL]

# Legacy names (Vector < 0.21)
_LEGACY = [
    "events_in_total",
    "events_out_total",
    "processing_errors_total",
]

# Alias map: any name on the left is treated as the canonical name on the right
VECTOR_METRIC_ALIASES: Dict[str, str] = {
    # vector_-prefixed → canonical
    "vector_component_received_events_total": "component_received_events_total",
    "vector_component_sent_events_total": "component_sent_events_total",
    "vector_component_errors_total": "component_errors_total",
    "vector_component_received_bytes_total": "component_received_bytes_total",
    "vector_component_sent_bytes_total": "component_sent_bytes_total",
    # legacy → canonical
    "events_in_total": "component_received_events_total",
    "events_out_total": "component_sent_events_total",
    "processing_errors_total": "component_errors_total",
}


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
        self.metric_version: str = "unknown"  # "current", "vector_prefixed", "legacy", "unknown"
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

    result.metric_version = _detect_metric_version(result.families)

    # Extract source received events (component_kind=source) with all alias variants.
    # Summing only source-kind samples avoids double-counting events that pass
    # through transform and sink components.
    source_filter = {"component_kind": "source"}
    sink_filter = {"component_kind": "sink"}

    result.received_events = (
        _sum_with_aliases(result.families, "component_received_events_total",
                          ["vector_component_received_events_total", "events_in_total"],
                          source_filter)
        # If no component_kind labels present (older Vector), fall back to summing all
        or _sum_with_aliases(result.families, "component_received_events_total",
                             ["vector_component_received_events_total", "events_in_total"])
    )
    result.sent_events = (
        _sum_with_aliases(result.families, "component_sent_events_total",
                          ["vector_component_sent_events_total", "events_out_total"],
                          sink_filter)
        or _sum_with_aliases(result.families, "component_sent_events_total",
                             ["vector_component_sent_events_total", "events_out_total"])
    )
    result.errors_total = (
        _sum_with_aliases(result.families, "component_errors_total",
                          ["vector_component_errors_total", "processing_errors_total"],
                          sink_filter)
        or _sum_with_aliases(result.families, "component_errors_total",
                             ["vector_component_errors_total", "processing_errors_total"])
    )
    result.received_bytes = _sum_with_aliases(
        result.families, "component_received_bytes_total",
        ["vector_component_received_bytes_total"], source_filter,
    ) or _sum_with_aliases(
        result.families, "component_received_bytes_total",
        ["vector_component_received_bytes_total"],
    )
    result.sent_bytes = _sum_with_aliases(
        result.families, "component_sent_bytes_total",
        ["vector_component_sent_bytes_total"], sink_filter,
    ) or _sum_with_aliases(
        result.families, "component_sent_bytes_total",
        ["vector_component_sent_bytes_total"],
    )

    result.components = _extract_components(result.families, result.metric_version)
    return result


def _sum_with_aliases(
    families: Dict[str, MetricFamily],
    primary: str,
    aliases: List[str],
    label_filters: Optional[Dict[str, str]] = None,
) -> float:
    """Sum metric values trying primary name first, then aliases."""
    return sum_metric_values(families, primary, label_filters=label_filters, aliases=aliases)


def _detect_metric_version(families: Dict[str, MetricFamily]) -> str:
    """Classify metrics as current, vector_prefixed, legacy, or unknown."""
    names: set = set()
    for fam in families.values():
        names.add(fam.name)
        for s in fam.samples:
            names.add(s.name)

    has_vector_prefix = any(n in names for n in _VECTOR_PREFIXED)
    has_canonical = any(n in names for n in _CANONICAL)
    has_legacy = any(n in names for n in _LEGACY)

    if has_vector_prefix:
        return "vector_prefixed"   # Vector ≥ 0.37 default
    if has_canonical and not has_legacy:
        return "current"
    if has_legacy and not has_canonical:
        return "legacy"
    if has_canonical and has_legacy:
        return "current"
    return "unknown"


def _extract_components(
    families: Dict[str, MetricFamily],
    version: str,
) -> Dict[str, Dict[str, Any]]:
    """Extract per-component metrics keyed by component_id."""
    components: Dict[str, Dict[str, Any]] = {}
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
