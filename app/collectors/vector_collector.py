"""
Vector metrics collector – scrapes Prometheus metrics from each sensor's Vector instance.
Supports current (component_*), vector_-prefixed current, and legacy metric name families.

Key design:
- dp_sink_sent_events: events sent by the *specific* sink(s) to Data Prepper only.
- discarded_events: intentional filter discards (not delivery loss).
- source_received_events: total events entering the pipeline.
Used by correlation_checks to build an accurate Vector→DataPrepper drop rate.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.config import settings
from app.utils.http import fetch_url
from app.utils.prometheus_parser import (
    MetricFamily,
    MetricSample,
    parse_prometheus_text,
    sum_metric_values,
)

logger = logging.getLogger(__name__)

# ── Metric name sets ────────────────────────────────────────────────────────
_CANONICAL = [
    "component_received_events_total",
    "component_sent_events_total",
    "component_errors_total",
    "component_received_bytes_total",
    "component_sent_bytes_total",
]
_VECTOR_PREFIXED = [f"vector_{m}" for m in _CANONICAL]
_LEGACY = ["events_in_total", "events_out_total", "processing_errors_total"]

# Alias map: left → canonical right
VECTOR_METRIC_ALIASES: Dict[str, str] = {
    "vector_component_received_events_total": "component_received_events_total",
    "vector_component_sent_events_total": "component_sent_events_total",
    "vector_component_errors_total": "component_errors_total",
    "vector_component_received_bytes_total": "component_received_bytes_total",
    "vector_component_sent_bytes_total": "component_sent_bytes_total",
    "events_in_total": "component_received_events_total",
    "events_out_total": "component_sent_events_total",
    "processing_errors_total": "component_errors_total",
}

# Component types that are never the DP delivery sink
_PROM_SINK_TYPES = frozenset({
    "prometheus_exporter", "prometheus_remote_write",
    "prom_metrics", "prometheus",
})
_NON_SINK_KINDS = frozenset({"source", "transform"})

# All metric names that carry per-component sent_events
_SENT_METRIC_NAMES = frozenset({
    "vector_component_sent_events_total",
    "component_sent_events_total",
})
_RECEIVED_METRIC_NAMES = frozenset({
    "vector_component_received_events_total",
    "component_received_events_total",
})
_DISCARDED_METRIC_NAMES = frozenset({
    "vector_component_discarded_events_total",
    "component_discarded_events_total",
})


class VectorScrapeResult:
    """Result of scraping a single Vector instance."""

    __slots__ = (
        "sensor_ip", "reachable", "error", "latency_ms",
        "families", "raw_text", "metric_version",
        "received_events", "sent_events", "errors_total",
        "received_bytes", "sent_bytes",
        # DP-sink specific
        "dp_sink_sent_events",
        "dp_sink_ambiguous",
        "detected_dp_sink_ids",
        "excluded_sink_ids",
        "sink_sent_by_id",
        # Filtering observability
        "discarded_events",
        "source_received_events",
        # Component breakdown
        "components",
    )

    def __init__(self, sensor_ip: str):
        self.sensor_ip = sensor_ip
        self.reachable: bool = False
        self.error: Optional[str] = None
        self.latency_ms: float = 0.0
        self.families: Dict[str, MetricFamily] = {}
        self.raw_text: str = ""
        self.metric_version: str = "unknown"
        self.received_events: float = 0.0
        self.sent_events: float = 0.0
        self.errors_total: float = 0.0
        self.received_bytes: float = 0.0
        self.sent_bytes: float = 0.0
        # DP sink resolution
        self.dp_sink_sent_events: float = 0.0
        self.dp_sink_ambiguous: bool = False
        self.detected_dp_sink_ids: List[str] = []
        self.excluded_sink_ids: List[str] = []
        self.sink_sent_by_id: Dict[str, Dict[str, Any]] = {}
        # Filtering
        self.discarded_events: float = 0.0
        self.source_received_events: float = 0.0
        # Per-component breakdown
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

    # Build per-component sink map (all sinks, keyed by component_id)
    result.sink_sent_by_id = _build_sink_sent_map(result.families)

    # Resolve the DP delivery sink
    configured_ids = settings.vector_dp_sink_ids
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(
        result.sink_sent_by_id, configured_ids,
    )
    result.dp_sink_sent_events = dp_sent
    result.dp_sink_ambiguous = ambiguous
    result.detected_dp_sink_ids = detected
    result.excluded_sink_ids = excluded

    # Overall sent/received (for general Vector health checks)
    source_filter = {"component_kind": "source"}
    sink_filter = {"component_kind": "sink"}

    result.received_events = _sum_with_aliases(
        result.families, "component_received_events_total",
        ["vector_component_received_events_total", "events_in_total"],
        source_filter,
    ) or _sum_with_aliases(
        result.families, "component_received_events_total",
        ["vector_component_received_events_total", "events_in_total"],
    )
    result.sent_events = _sum_with_aliases(
        result.families, "component_sent_events_total",
        ["vector_component_sent_events_total", "events_out_total"],
        sink_filter,
    ) or _sum_with_aliases(
        result.families, "component_sent_events_total",
        ["vector_component_sent_events_total", "events_out_total"],
    )
    result.errors_total = _sum_with_aliases(
        result.families, "component_errors_total",
        ["vector_component_errors_total", "processing_errors_total"],
        sink_filter,
    ) or _sum_with_aliases(
        result.families, "component_errors_total",
        ["vector_component_errors_total", "processing_errors_total"],
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

    # Filtering observability
    result.discarded_events = _extract_intentional_discards(result.families)
    result.source_received_events = _extract_source_received(result.families)

    result.components = _extract_components(result.families)
    return result


# ── Sink resolution ─────────────────────────────────────────────────────────

def _build_sink_sent_map(families: Dict[str, MetricFamily]) -> Dict[str, Dict[str, Any]]:
    """Collect per-component sent_events for all labelled components."""
    sink_map: Dict[str, Dict[str, Any]] = {}
    for fam in families.values():
        for sample in fam.samples:
            if sample.name not in _SENT_METRIC_NAMES:
                continue
            cid = sample.labels.get("component_id", "")
            if not cid:
                continue
            if cid not in sink_map:
                sink_map[cid] = {
                    "sent": 0.0,
                    "kind": sample.labels.get("component_kind", ""),
                    "type": sample.labels.get("component_type", ""),
                    "metric": sample.name,
                }
            sink_map[cid]["sent"] += sample.value
            if sample.labels.get("component_kind"):
                sink_map[cid]["kind"] = sample.labels["component_kind"]
            if sample.labels.get("component_type"):
                sink_map[cid]["type"] = sample.labels["component_type"]
    return sink_map


def _resolve_dp_sink(
    sink_map: Dict[str, Dict[str, Any]],
    configured_ids: List[str],
) -> Tuple[float, bool, List[str], List[str]]:
    """Return (dp_sent_total, ambiguous, detected_ids, excluded_ids).

    configured_ids: parsed from VECTOR_DATAPREPPER_SINK_COMPONENTS.
    When empty, auto-inference is attempted.
    """
    if not sink_map:
        return 0.0, True, [], []

    if configured_ids:
        # Explicit configuration: use exactly those IDs, verify they are sinks
        detected: List[str] = []
        excluded: List[str] = []
        total = 0.0
        for cid, info in sink_map.items():
            if cid in configured_ids:
                kind = info.get("kind", "sink")
                if kind in _NON_SINK_KINDS:
                    logger.warning(
                        "VECTOR_DATAPREPPER_SINK_COMPONENTS contains %s which has "
                        "component_kind=%s (not a sink) – skipping.",
                        cid, kind,
                    )
                    excluded.append(cid)
                    continue
                total += info["sent"]
                detected.append(cid)
            else:
                excluded.append(cid)

        if not detected:
            logger.warning(
                "None of the configured VECTOR_DATAPREPPER_SINK_COMPONENTS (%s) "
                "were found in Vector metrics. Check component IDs.",
                configured_ids,
            )
            return 0.0, True, [], list(configured_ids)
        return total, False, sorted(detected), sorted(excluded)

    # Auto-inference: find HTTP-like sinks, exclude prometheus exporters/transforms
    candidates: Dict[str, Dict[str, Any]] = {}
    excluded: List[str] = []
    for cid, info in sink_map.items():
        kind = info.get("kind", "")
        ctype = info.get("type", "").lower()

        if kind in _NON_SINK_KINDS:
            excluded.append(cid)
            continue
        if kind != "sink":
            # No kind label – treat conservatively as potential sink
            pass
        if ctype in _PROM_SINK_TYPES or "prom" in ctype:
            excluded.append(cid)
            continue
        candidates[cid] = info

    if len(candidates) == 1:
        cid, info = next(iter(candidates.items()))
        return info["sent"], False, [cid], sorted(excluded + [
            c for c in sink_map if c != cid and c not in excluded
        ])

    # 0 or multiple candidates – ambiguous
    all_cids = sorted(candidates.keys())
    logger.info(
        "Vector DP sink auto-detection ambiguous: found %d HTTP sink candidates %s. "
        "Set VECTOR_DATAPREPPER_SINK_COMPONENTS to resolve.",
        len(candidates), all_cids,
    )
    return 0.0, True, [], sorted(sink_map.keys())


def _extract_intentional_discards(families: Dict[str, MetricFamily]) -> float:
    """Sum events intentionally discarded by filter transforms."""
    total = 0.0
    for fam in families.values():
        for sample in fam.samples:
            if sample.name in _DISCARDED_METRIC_NAMES:
                if sample.labels.get("intentional", "").lower() == "true":
                    total += sample.value
    return total


def _extract_source_received(families: Dict[str, MetricFamily]) -> float:
    """Sum received events from all source components."""
    total = 0.0
    for fam in families.values():
        for sample in fam.samples:
            if sample.name in _RECEIVED_METRIC_NAMES:
                if sample.labels.get("component_kind", "") == "source":
                    total += sample.value
    return total


# ── Helpers ──────────────────────────────────────────────────────────────────

def _sum_with_aliases(
    families: Dict[str, MetricFamily],
    primary: str,
    aliases: List[str],
    label_filters: Optional[Dict[str, str]] = None,
) -> float:
    return sum_metric_values(families, primary, label_filters=label_filters, aliases=aliases)


def _detect_metric_version(families: Dict[str, MetricFamily]) -> str:
    names: set = set()
    for fam in families.values():
        names.add(fam.name)
        for s in fam.samples:
            names.add(s.name)

    if any(n in names for n in _VECTOR_PREFIXED):
        return "vector_prefixed"
    if any(n in names for n in _CANONICAL) and not any(n in names for n in _LEGACY):
        return "current"
    if any(n in names for n in _LEGACY) and not any(n in names for n in _CANONICAL):
        return "legacy"
    if any(n in names for n in _CANONICAL):
        return "current"
    return "unknown"


def _extract_components(families: Dict[str, MetricFamily]) -> Dict[str, Dict[str, Any]]:
    components: Dict[str, Dict[str, Any]] = {}
    for fam in families.values():
        for sample in fam.samples:
            cid = (sample.labels.get("component_id")
                   or sample.labels.get("component_name", ""))
            if not cid:
                continue
            if cid not in components:
                components[cid] = {
                    "component_kind": sample.labels.get("component_kind", ""),
                    "component_type": sample.labels.get("component_type", ""),
                    "metrics": {},
                }
            components[cid]["metrics"][sample.name] = sample.value
    return components


async def scrape_all_sensors() -> List[VectorScrapeResult]:
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
        "dp_sink_sent_events": result.dp_sink_sent_events,
        "discarded_events": result.discarded_events,
        "source_received_events": result.source_received_events,
    }
