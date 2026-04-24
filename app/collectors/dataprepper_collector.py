"""
Data Prepper collector – scrapes management metrics and probes ingest health.
"""
from __future__ import annotations
import glob
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from app.config import settings
from app.utils.http import fetch_json, fetch_url
from app.utils.prometheus_parser import (
    MetricFamily, discover_pipeline_names, find_metric_value,
    parse_prometheus_text, sum_metric_values,
)

logger = logging.getLogger(__name__)

class DataPrepperScrapeResult:
    def __init__(self):
        self.metrics_reachable = False
        self.metrics_tls_ok = False
        self.metrics_auth_ok = False
        self.metrics_error: Optional[str] = None
        self.metrics_latency_ms = 0.0
        self.families: Dict[str, MetricFamily] = {}
        self.ingest_reachable = False
        self.ingest_healthy = False
        self.ingest_error: Optional[str] = None
        self.ingest_latency_ms = 0.0
        self.pipeline_names: List[str] = []
        self.pipeline_metrics: Dict[str, Dict[str, float]] = {}
        self.records_processed = 0.0
        self.http_requests_received = 0.0
        self.http_success_requests = 0.0
        self.http_request_timeouts = 0.0
        self.http_requests_rejected = 0.0
        self.http_bad_requests = 0.0
        self.http_internal_server_errors = 0.0
        self.os_records_in = 0.0
        self.os_document_errors = 0.0
        self.os_bulk_request_failed = 0.0
        self.os_pipeline_latency = 0.0
        self.buffer_records_in_buffer = 0.0
        self.buffer_records_in_flight = 0.0
        self.buffer_usage = 0.0
        self.buffer_write_failed = 0.0
        self.buffer_write_timeouts = 0.0
        self.tls_handshake_success = 0.0
        self.tls_handshake_failure = 0.0
        self.jvm_heap_used = 0.0
        self.jvm_heap_max = 0.0
        self.jvm_gc_pause_seconds = 0.0
        self.process_cpu = 0.0
        self.thread_count = 0.0
        self.dlq_files: List[str] = []
        self.dlq_nonempty_files: List[str] = []

def _dp_auth() -> Tuple[str, str]:
    return (settings.DATAPREPPER_USERNAME, settings.DATAPREPPER_PASSWORD)

def _dp_ingest_auth() -> Optional[Tuple[str, str]]:
    if settings.DATAPREPPER_HEALTH_REQUIRES_AUTH:
        return (settings.DATAPREPPER_INGEST_USERNAME, settings.DATAPREPPER_INGEST_PASSWORD)
    return None

def _find(families, name, label_filters=None):
    val = find_metric_value(families, name, label_filters)
    return val if val is not None else 0.0

_PIPELINE_SUFFIXES = [
    "recordsProcessed_total", "http_requestsReceived_total",
    "http_successRequests_total", "http_requestTimeouts_total",
    "http_requestsRejected_total", "http_badRequests_total",
    "http_internalServerError_total", "opensearch_recordsIn_total",
    "opensearch_documentErrors_total", "opensearch_bulkRequestFailed_total",
    "opensearch_PipelineLatency_seconds", "opensearch_documentsSuccess_total",
    "BlockingBuffer_recordsInBuffer", "BlockingBuffer_recordsInFlight",
    "BlockingBuffer_bufferUsage", "BlockingBuffer_recordsWriteFailed_total",
    "BlockingBuffer_writeTimeouts_total",
]

def _extract_pipeline_metrics(families, pipeline_name):
    prefix = pipeline_name + "_"
    metrics = {}
    for suffix in _PIPELINE_SUFFIXES:
        val = find_metric_value(families, prefix + suffix)
        if val is not None:
            metrics[suffix] = val
    return metrics

def _aggregate_metrics(result):
    for pm in result.pipeline_metrics.values():
        result.records_processed += pm.get("recordsProcessed_total", 0)
        result.http_requests_received += pm.get("http_requestsReceived_total", 0)
        result.http_success_requests += pm.get("http_successRequests_total", 0)
        result.http_request_timeouts += pm.get("http_requestTimeouts_total", 0)
        result.http_requests_rejected += pm.get("http_requestsRejected_total", 0)
        result.http_bad_requests += pm.get("http_badRequests_total", 0)
        result.http_internal_server_errors += pm.get("http_internalServerError_total", 0)
        result.os_records_in += pm.get("opensearch_recordsIn_total", 0)
        result.os_document_errors += pm.get("opensearch_documentErrors_total", 0)
        result.os_bulk_request_failed += pm.get("opensearch_bulkRequestFailed_total", 0)
        result.buffer_records_in_buffer += pm.get("BlockingBuffer_recordsInBuffer", 0)
        result.buffer_records_in_flight += pm.get("BlockingBuffer_recordsInFlight", 0)
        result.buffer_usage = max(result.buffer_usage, pm.get("BlockingBuffer_bufferUsage", 0))
        result.buffer_write_failed += pm.get("BlockingBuffer_recordsWriteFailed_total", 0)
        result.buffer_write_timeouts += pm.get("BlockingBuffer_writeTimeouts_total", 0)
        lat = pm.get("opensearch_PipelineLatency_seconds", 0)
        if lat > result.os_pipeline_latency:
            result.os_pipeline_latency = lat

async def scrape_dataprepper() -> DataPrepperScrapeResult:
    result = DataPrepperScrapeResult()
    ca = settings.CA_CERT_PATH
    status_code, body, latency, error = await fetch_url(
        settings.dataprepper_metrics_url, ca_path=ca, auth=_dp_auth()
    )
    result.metrics_latency_ms = latency
    if error:
        result.metrics_error = error
        return result
    if status_code in (401, 403):
        result.metrics_reachable = True
        result.metrics_tls_ok = True
        result.metrics_auth_ok = False
        result.metrics_error = "auth_failure"
        return result
    if status_code != 200:
        result.metrics_reachable = True
        result.metrics_error = f"HTTP {status_code}"
        return result
    result.metrics_reachable = True
    result.metrics_tls_ok = True
    result.metrics_auth_ok = True
    try:
        result.families = parse_prometheus_text(body)
    except Exception as e:
        result.metrics_error = f"parse_error: {e}"
        return result
    result.pipeline_names = discover_pipeline_names(result.families)
    if settings.DATAPREPPER_PIPELINE_NAME and settings.DATAPREPPER_PIPELINE_NAME not in result.pipeline_names:
        result.pipeline_names.append(settings.DATAPREPPER_PIPELINE_NAME)
    for pn in result.pipeline_names:
        result.pipeline_metrics[pn] = _extract_pipeline_metrics(result.families, pn)
    _aggregate_metrics(result)
    result.jvm_heap_used = _find(result.families, "jvm_memory_bytes_used", {"area": "heap"})
    result.jvm_heap_max = _find(result.families, "jvm_memory_bytes_max", {"area": "heap"})
    result.jvm_gc_pause_seconds = _find(result.families, "jvm_gc_pause_seconds_sum")
    result.process_cpu = _find(result.families, "process_cpu_seconds_total")
    result.thread_count = _find(result.families, "jvm_threads_current")
    result.tls_handshake_success = _find(result.families, "armeria_server_tls_handshakes_total", {"result": "success"})
    result.tls_handshake_failure = _find(result.families, "armeria_server_tls_handshakes_total", {"result": "failure"})
    await _check_ingest_health(result)
    if settings.ENABLE_DP_DLQ_CHECK:
        _check_dlq(result)
    return result

async def _check_ingest_health(result):
    data, latency, error = await fetch_json(
        settings.dataprepper_health_url, settings.CA_CERT_PATH, _dp_ingest_auth()
    )
    result.ingest_latency_ms = latency
    if error:
        result.ingest_error = error
        return
    result.ingest_reachable = True
    if isinstance(data, dict):
        result.ingest_healthy = str(data.get("status", "")).lower() in ("up", "ok", "healthy", "true")
    else:
        result.ingest_healthy = True

def _check_dlq(result):
    try:
        files = glob.glob(settings.DP_DLQ_GLOB)
        result.dlq_files = files
        result.dlq_nonempty_files = [f for f in files if os.path.getsize(f) > 0]
    except Exception as e:
        logger.debug("DLQ check error: %s", e)

def get_flat_metrics(result: DataPrepperScrapeResult) -> Dict[str, float]:
    return {
        "records_processed": result.records_processed,
        "http_requests_received": result.http_requests_received,
        "http_success_requests": result.http_success_requests,
        "http_request_timeouts": result.http_request_timeouts,
        "os_records_in": result.os_records_in,
        "os_document_errors": result.os_document_errors,
        "os_bulk_request_failed": result.os_bulk_request_failed,
        "os_pipeline_latency": result.os_pipeline_latency,
        "buffer_usage": result.buffer_usage,
        "buffer_write_failed": result.buffer_write_failed,
        "buffer_write_timeouts": result.buffer_write_timeouts,
        "tls_handshake_success": result.tls_handshake_success,
        "tls_handshake_failure": result.tls_handshake_failure,
        "jvm_heap_used": result.jvm_heap_used,
        "jvm_heap_max": result.jvm_heap_max,
    }
