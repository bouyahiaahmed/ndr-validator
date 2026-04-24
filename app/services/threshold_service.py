"""
Threshold service – central accessor for all configurable thresholds.
Provides typed helpers so check modules don't need to import settings directly for thresholds.
"""
from __future__ import annotations
from dataclasses import dataclass
from app.config import settings


@dataclass(frozen=True)
class FreshnessThresholds:
    warn_seconds: int
    critical_seconds: int


@dataclass(frozen=True)
class DropRateThresholds:
    vector_to_dp_max_percent: float
    dp_to_os_max_percent: float


@dataclass(frozen=True)
class LatencyThresholds:
    dp_pipeline_warn_seconds: float
    dp_pipeline_crit_seconds: float
    os_search_warn_ms: int
    os_search_crit_ms: int


@dataclass(frozen=True)
class BufferThresholds:
    usage_warn: float
    usage_crit: float
    write_failure_delta_max: int
    write_timeout_delta_max: int


@dataclass(frozen=True)
class ResourceThresholds:
    heap_percent_warn: float
    disk_free_percent_warn: float


@dataclass(frozen=True)
class DeltaThresholds:
    doc_error_delta_max: int
    bulk_failure_delta_max: int
    tls_handshake_failure_delta_max: int


def get_freshness() -> FreshnessThresholds:
    return FreshnessThresholds(
        warn_seconds=settings.STALE_DATA_THRESHOLD_SECONDS,
        critical_seconds=settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS,
    )


def get_drop_rates() -> DropRateThresholds:
    return DropRateThresholds(
        vector_to_dp_max_percent=settings.MAX_VECTOR_TO_DP_DROP_PERCENT,
        dp_to_os_max_percent=settings.MAX_DP_TO_OS_DROP_PERCENT,
    )


def get_latency() -> LatencyThresholds:
    return LatencyThresholds(
        dp_pipeline_warn_seconds=settings.MAX_DP_PIPELINE_LATENCY_SECONDS_WARN,
        dp_pipeline_crit_seconds=settings.MAX_DP_PIPELINE_LATENCY_SECONDS_CRIT,
        os_search_warn_ms=settings.MAX_OS_SEARCH_LATENCY_MS_WARN,
        os_search_crit_ms=settings.MAX_OS_SEARCH_LATENCY_MS_CRIT,
    )


def get_buffer() -> BufferThresholds:
    return BufferThresholds(
        usage_warn=settings.MAX_DP_BUFFER_USAGE_RATIO_WARN,
        usage_crit=settings.MAX_DP_BUFFER_USAGE_RATIO_CRIT,
        write_failure_delta_max=settings.MAX_DP_BUFFER_WRITE_FAILURE_DELTA,
        write_timeout_delta_max=0,
    )


def get_resources() -> ResourceThresholds:
    return ResourceThresholds(
        heap_percent_warn=settings.HIGH_HEAP_THRESHOLD_PERCENT,
        disk_free_percent_warn=settings.LOW_DISK_THRESHOLD_PERCENT,
    )


def get_deltas() -> DeltaThresholds:
    return DeltaThresholds(
        doc_error_delta_max=settings.MAX_DP_DOCUMENT_ERROR_DELTA,
        bulk_failure_delta_max=settings.MAX_DP_BULK_FAILURE_DELTA,
        tls_handshake_failure_delta_max=settings.MAX_DP_TLS_HANDSHAKE_FAILURE_DELTA,
    )
