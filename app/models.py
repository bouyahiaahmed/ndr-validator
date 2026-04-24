"""
Core domain models: check results, component status, status summary.
All typed with Pydantic for serialization and validation.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Status(str, enum.Enum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"
    UNKNOWN = "unknown"

    @staticmethod
    def worst(a: "Status", b: "Status") -> "Status":
        # Priority: RED > YELLOW > GREEN > UNKNOWN
        # UNKNOWN means "no data yet" and must NEVER mask a real RED or YELLOW.
        order = {Status.UNKNOWN: 0, Status.GREEN: 1, Status.YELLOW: 2, Status.RED: 3}
        return a if order.get(a, 0) >= order.get(b, 0) else b


class Component(str, enum.Enum):
    ZEEK = "zeek"
    VECTOR = "vector"
    DATAPREPPER = "dataprepper"
    OPENSEARCH = "opensearch"
    DASHBOARDS = "dashboards"
    CORRELATION = "correlation"
    DATA_QUALITY = "data_quality"


class CheckResult(BaseModel):
    """Outcome of a single validation check."""

    id: str
    title: str
    component: Component
    severity: str = "warning"  # default severity: info, warning, critical
    status: Status = Status.UNKNOWN
    details: str = ""
    current_value: Any = None
    threshold: Any = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    remediation: str = ""
    sensor: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ComponentStatus(BaseModel):
    """Aggregate status for one component."""

    name: Component
    status: Status = Status.UNKNOWN
    checks: List[CheckResult] = Field(default_factory=list)
    summary: str = ""
    last_scrape: Optional[datetime] = None
    scrape_duration_ms: Optional[float] = None


class SensorStatus(BaseModel):
    """Per-sensor aggregate."""

    sensor_ip: str
    display_name: str
    status: Status = Status.UNKNOWN
    checks: List[CheckResult] = Field(default_factory=list)
    summary: str = ""


class UrgentFinding(BaseModel):
    """A prioritized finding for the top-N list."""

    rank: int
    check_id: str
    title: str
    component: Component
    status: Status
    details: str
    remediation: str
    sensor: Optional[str] = None


class PipelineRates(BaseModel):
    """Computed rates/percentages across the pipeline."""

    vector_total_sent_delta: float = 0.0
    dp_records_processed_delta: float = 0.0
    dp_records_in_opensearch_delta: float = 0.0
    os_doc_count_delta: float = 0.0
    vector_to_dp_drop_percent: Optional[float] = None
    dp_to_os_drop_percent: Optional[float] = None
    overall_freshness_seconds: Optional[float] = None
    worst_sensor_freshness_seconds: Optional[float] = None
    worst_sensor_name: Optional[str] = None
    worst_log_type_freshness_seconds: Optional[float] = None
    worst_log_type_name: Optional[str] = None
    dp_pipeline_latency_seconds: Optional[float] = None
    dp_buffer_usage_ratio: Optional[float] = None
    os_search_latency_ms: Optional[float] = None


class StatusSummary(BaseModel):
    """Top-level status payload returned by /status."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0.0"
    config_fingerprint: str = ""
    overall_status: Status = Status.UNKNOWN
    components: List[ComponentStatus] = Field(default_factory=list)
    sensors: List[SensorStatus] = Field(default_factory=list)
    checks: List[CheckResult] = Field(default_factory=list)
    urgent_findings: List[UrgentFinding] = Field(default_factory=list)
    rates: PipelineRates = Field(default_factory=PipelineRates)


class HistoryRecord(BaseModel):
    """A persisted point-in-time snapshot."""

    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_status: Status = Status.UNKNOWN
    component_statuses: Dict[str, str] = Field(default_factory=dict)
    check_count: int = 0
    red_count: int = 0
    yellow_count: int = 0
    green_count: int = 0
    summary_json: str = "{}"


class MetricSnapshot(BaseModel):
    """Raw metric snapshot for delta computation."""

    source: str  # e.g. "vector:10.0.0.11", "dataprepper", "opensearch"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metrics: Dict[str, float] = Field(default_factory=dict)
    labels: Dict[str, Dict[str, str]] = Field(default_factory=dict)
