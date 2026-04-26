"""
Tests for Data Prepper checks.
Covers: auth failure, TLS failure, buffer failures, doc errors, TLS handshake failures.
"""
import pytest
from app.collectors.dataprepper_collector import DataPrepperScrapeResult
from app.checks.dataprepper_checks import run_dataprepper_checks
from app.models import Status


def _base_healthy() -> DataPrepperScrapeResult:
    r = DataPrepperScrapeResult()
    r.metrics_reachable = True
    r.metrics_tls_ok = True
    r.metrics_auth_ok = True
    r.ingest_reachable = True
    r.ingest_healthy = True
    r.pipeline_names = ["zeek_ingestion_pipeline"]
    # families must be non-empty so dp.metrics.parse is GREEN
    from app.utils.prometheus_parser import MetricFamily
    r.families = {"_dummy": MetricFamily(name="_dummy", type="counter")}
    r.records_processed = 1000.0
    r.http_requests_received = 500.0
    r.http_success_requests = 498.0
    r.os_records_in = 999.0
    r.os_document_errors = 0.0
    r.os_bulk_request_failed = 0.0
    # Use os_pipeline_latency_max (the field _compute_safe_latency reads first).
    # A non-negative value is returned directly as the latency reading.
    r.os_pipeline_latency_max = 0.5
    r.os_pipeline_latency = 0.5
    r.buffer_usage = 0.1
    r.buffer_write_failed = 0.0
    r.buffer_write_timeouts = 0.0
    r.tls_handshake_failure = 0.0
    r.tls_handshake_success = 100.0
    r.jvm_heap_used = 512 * 1024 * 1024
    r.jvm_heap_max = 2 * 1024 * 1024 * 1024
    return r


def test_healthy_dp_all_green():
    r = _base_healthy()
    prev = {
        "records_processed": 900.0, "http_requests_received": 450.0,
        "os_records_in": 899.0, "os_document_errors": 0.0,
        "os_bulk_request_failed": 0.0, "buffer_write_failed": 0.0,
        "tls_handshake_failure": 0.0,
    }
    checks = run_dataprepper_checks(r, prev)
    red = [c for c in checks if c.status == Status.RED]
    assert red == [], f"Expected no red checks, got: {[c.id for c in red]}"


def test_auth_failure_returns_red():
    r = DataPrepperScrapeResult()
    r.metrics_reachable = True
    r.metrics_tls_ok = True
    r.metrics_auth_ok = False
    r.metrics_error = "auth_failure"
    checks = run_dataprepper_checks(r, {})
    auth_check = next(c for c in checks if c.id == "dp.metrics.auth")
    assert auth_check.status == Status.RED


def test_tls_failure_returns_red():
    r = DataPrepperScrapeResult()
    r.metrics_reachable = True
    r.metrics_tls_ok = False
    r.metrics_auth_ok = False
    r.metrics_error = "certificate_trust_failure"
    checks = run_dataprepper_checks(r, {})
    tls_check = next(c for c in checks if c.id == "dp.metrics.tls")
    assert tls_check.status == Status.RED


def test_buffer_write_failure_delta_red():
    r = _base_healthy()
    r.buffer_write_failed = 5.0
    prev = {"buffer_write_failed": 0.0}
    checks = run_dataprepper_checks(r, prev)
    bwf = next(c for c in checks if c.id == "dp.buffer.write_failed")
    assert bwf.status == Status.RED
    assert bwf.current_value == 5.0


def test_document_errors_delta_red():
    r = _base_healthy()
    r.os_document_errors = 10.0
    prev = {"os_document_errors": 0.0}
    checks = run_dataprepper_checks(r, prev)
    de = next(c for c in checks if c.id == "dp.os.doc_errors")
    assert de.status == Status.RED


def test_tls_handshake_failures_red():
    r = _base_healthy()
    r.tls_handshake_failure = 3.0
    prev = {"tls_handshake_failure": 0.0}
    checks = run_dataprepper_checks(r, prev)
    tf = next(c for c in checks if "tls.handshake" in c.id)
    assert tf.status == Status.RED


def test_high_buffer_usage_yellow():
    r = _base_healthy()
    r.buffer_usage = 0.75
    checks = run_dataprepper_checks(r, {})
    bu = next(c for c in checks if c.id == "dp.buffer.usage")
    assert bu.status == Status.YELLOW


def test_pipeline_latency_high_red():
    """
    _compute_safe_latency reads os_pipeline_latency_max first (rolling window).
    Setting it to 35.0 s (above the CRIT threshold of 30 s) must produce RED.
    """
    r = _base_healthy()
    r.os_pipeline_latency_max = 35.0  # _compute_safe_latency returns this directly
    r.os_pipeline_latency = 35.0
    checks = run_dataprepper_checks(r, {})
    lat = next(c for c in checks if c.id == "dp.pipeline.latency")
    assert lat.status == Status.RED, (
        f"Latency 35s must be RED, got {lat.status}: {lat.details}"
    )


def test_ingest_unhealthy_red():
    """
    Status is YELLOW when ingest_reachable=True but unhealthy (pipeline error).
    Status is RED only when ingest_reachable=False (port unreachable).
    This tests the RED path: port completely unreachable.
    """
    r = _base_healthy()
    r.ingest_reachable = False   # port unreachable → RED
    r.ingest_healthy = False
    r.ingest_error = "connection_refused"
    checks = run_dataprepper_checks(r, {})
    ih = next(c for c in checks if c.id == "dp.ingest.reachable")
    assert ih.status == Status.RED, (
        f"Port-unreachable ingest must be RED, got {ih.status}: {ih.details}"
    )


def test_ingest_reachable_but_unhealthy_is_yellow():
    """Reachable port but unhealthy response → YELLOW (pipeline error, not full outage)."""
    r = _base_healthy()
    r.ingest_reachable = True    # port open
    r.ingest_healthy = False
    r.ingest_error = "pipeline_error"
    checks = run_dataprepper_checks(r, {})
    ih = next(c for c in checks if c.id == "dp.ingest.reachable")
    assert ih.status == Status.YELLOW, (
        f"Reachable-but-unhealthy ingest must be YELLOW, got {ih.status}: {ih.details}"
    )


def test_missing_dp_endpoint_first_check_red():
    r = DataPrepperScrapeResult()
    r.metrics_error = "endpoint_unreachable"
    checks = run_dataprepper_checks(r, {})
    reach = next(c for c in checks if c.id == "dp.metrics.reachable")
    assert reach.status == Status.RED
