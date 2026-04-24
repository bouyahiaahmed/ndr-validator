"""
Prometheus metrics exposed by the validator itself.
Uses prometheus_client to expose scrape stats, check counts, etc.
"""
from __future__ import annotations

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Info,
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# Use a custom registry so we don't get default process/platform collectors
# that don't make sense inside a container
REGISTRY = CollectorRegistry()

# ── Validator info ────────────────────────────────────────────────────
validator_info = Info(
    "ndr_validator",
    "NDR Pipeline Validator build info",
    registry=REGISTRY,
)

# ── Scrape metrics ────────────────────────────────────────────────────
scrape_total = Counter(
    "ndr_validator_scrape_total",
    "Total number of scrape cycles completed",
    registry=REGISTRY,
)

scrape_errors_total = Counter(
    "ndr_validator_scrape_errors_total",
    "Total number of scrape cycles that encountered errors",
    registry=REGISTRY,
)

scrape_duration_seconds = Histogram(
    "ndr_validator_scrape_duration_seconds",
    "Duration of each scrape cycle",
    buckets=[0.5, 1, 2, 5, 10, 30, 60],
    registry=REGISTRY,
)

# ── Check result metrics ─────────────────────────────────────────────
check_status_gauge = Gauge(
    "ndr_validator_check_status",
    "Current status of each check (0=unknown, 1=green, 2=yellow, 3=red)",
    ["check_id", "component"],
    registry=REGISTRY,
)

component_status_gauge = Gauge(
    "ndr_validator_component_status",
    "Current status of each component (0=unknown, 1=green, 2=yellow, 3=red)",
    ["component"],
    registry=REGISTRY,
)

overall_status_gauge = Gauge(
    "ndr_validator_overall_status",
    "Current overall pipeline status (0=unknown, 1=green, 2=yellow, 3=red)",
    registry=REGISTRY,
)

checks_total_gauge = Gauge(
    "ndr_validator_checks_total",
    "Total number of checks evaluated",
    registry=REGISTRY,
)

checks_red_gauge = Gauge(
    "ndr_validator_checks_red",
    "Number of checks currently red",
    registry=REGISTRY,
)

checks_yellow_gauge = Gauge(
    "ndr_validator_checks_yellow",
    "Number of checks currently yellow",
    registry=REGISTRY,
)

checks_green_gauge = Gauge(
    "ndr_validator_checks_green",
    "Number of checks currently green",
    registry=REGISTRY,
)

# ── Pipeline rate metrics ─────────────────────────────────────────────
pipeline_freshness_seconds = Gauge(
    "ndr_validator_pipeline_freshness_seconds",
    "Overall pipeline freshness in seconds",
    registry=REGISTRY,
)

vector_to_dp_drop_percent = Gauge(
    "ndr_validator_vector_to_dp_drop_percent",
    "Estimated drop rate Vector to Data Prepper",
    registry=REGISTRY,
)

dp_to_os_drop_percent = Gauge(
    "ndr_validator_dp_to_os_drop_percent",
    "Estimated drop rate Data Prepper to OpenSearch",
    registry=REGISTRY,
)


def status_to_int(status_str: str) -> int:
    return {"unknown": 0, "green": 1, "yellow": 2, "red": 3}.get(status_str, 0)


def generate_metrics() -> bytes:
    """Generate the Prometheus exposition text."""
    return generate_latest(REGISTRY)


def get_content_type() -> str:
    return CONTENT_TYPE_LATEST
