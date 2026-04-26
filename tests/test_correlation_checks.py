"""
Tests for correlation checks.
Covers: Zeek→Vector, Vector→DP drop, DP→OS drop, TLS mismatch, bottleneck, E2E freshness.
"""
import pytest
from datetime import datetime, timezone, timedelta
from app.collectors.vector_collector import VectorScrapeResult
from app.collectors.dataprepper_collector import DataPrepperScrapeResult
from app.collectors.opensearch_collector import OpenSearchScrapeResult
from app.collectors.zeek_collector import ZeekSensorResult
from app.checks.correlation_checks import run_correlation_checks
from app.models import Status


def _vec(ip, sent=10000.0, recv=10000.0, errors=0.0, reachable=True):
    v = VectorScrapeResult(ip)
    v.reachable = reachable
    v.sent_events = sent
    v.received_events = recv
    v.errors_total = errors
    return v


def _dp(records=10000.0, os_in=9980.0, tls_fail=0.0, buf_usage=0.1,
        buf_write_fail=0.0, success=9990.0, http_recv=200.0, lat=0.5):
    d = DataPrepperScrapeResult()
    d.metrics_reachable = True
    d.metrics_tls_ok = True
    d.metrics_auth_ok = True
    d.records_processed = records
    d.os_records_in = os_in
    d.tls_handshake_failure = tls_fail
    d.buffer_usage = buf_usage
    d.buffer_write_failed = buf_write_fail
    d.http_success_requests = success
    d.http_requests_received = http_recv
    d.os_pipeline_latency = lat
    d.os_bulk_request_failed = 0.0
    d.os_document_errors = 0.0
    d.buffer_write_timeouts = 0.0
    return d


def _os(total=50000, latest_ts=None, cluster_status="green"):
    o = OpenSearchScrapeResult()
    o.reachable = True
    o.auth_ok = True
    o.total_count = total
    o.cluster = {"status": cluster_status}
    o.overall_latest_ts = latest_ts or datetime.now(timezone.utc).isoformat()
    o.sensor_freshness = {}
    o.log_type_freshness = {}
    return o


def test_all_healthy_no_red():
    sensors = ["10.0.0.11", "10.0.0.12"]
    vecs = [_vec(ip) for ip in sensors]
    dp = _dp()
    os = _os()
    prev_v = {ip: {"sent_events": 9000.0} for ip in sensors}
    prev_dp = {"records_processed": 9000.0, "os_records_in": 8980.0,
               "tls_handshake_failure": 0.0, "buffer_write_failed": 0.0,
               "os_bulk_request_failed": 0.0, "http_success_requests": 8990.0}
    prev_os = {"total_count": 49000}
    checks = run_correlation_checks(vecs, dp, os, [], prev_v, prev_dp, prev_os)
    red = [c for c in checks if c.status == Status.RED]
    assert red == [], f"Unexpected red: {[(c.id, c.details) for c in red]}"


def test_vector_dp_drop_rate_red():
    """
    Vector sends 9000 events to DP sink (10000 - 1000 prev), but DP only processed 2700 → ~70% drop.
    The check must be YELLOW or RED (not UNKNOWN).
    """
    vr = _vec("10.0.0.11", sent=10000.0)
    vr.dp_sink_sent_events = 10000.0
    vr.dp_sink_ambiguous = False
    vr.detected_dp_sink_ids = ["dp_ingest"]
    vr.excluded_sink_ids = []
    vr.discarded_events = 0.0
    vr.source_received_events = 10000.0

    dp = _dp(records=2700.0)
    os = _os()
    prev_v = {"10.0.0.11": {"dp_sink_sent_events": 1000.0}}
    prev_dp = {"records_processed": 0.0, "os_records_in": 0.0,
               "tls_handshake_failure": 0.0, "buffer_write_failed": 0.0,
               "os_bulk_request_failed": 0.0, "http_success_requests": 0.0}
    prev_os = {"total_count": 0}
    checks = run_correlation_checks([vr], dp, os, [], prev_v, prev_dp, prev_os)
    drop = next((c for c in checks if c.id == "corr.vector_dp.drop_rate"), None)
    assert drop is not None
    assert drop.status in (Status.YELLOW, Status.RED)


def test_tls_mismatch_classified_red():
    vecs = [_vec("10.0.0.11")]
    dp = _dp(tls_fail=10.0, success=0.0)
    os = _os()
    prev_dp = {"tls_handshake_failure": 0.0, "records_processed": 0.0,
               "os_records_in": 0.0, "buffer_write_failed": 0.0,
               "os_bulk_request_failed": 0.0, "http_success_requests": 0.0}
    checks = run_correlation_checks(vecs, dp, os, [], {}, prev_dp, {})
    mismatch = next((c for c in checks if "tls" in c.id and "mismatch" in c.id), None)
    assert mismatch is not None
    assert mismatch.status == Status.RED
    assert "plaintext" in mismatch.details.lower() or "tls" in mismatch.details.lower()


def test_e2e_freshness_stale_red():
    vecs = [_vec("10.0.0.11")]
    dp = _dp()
    stale = (datetime.now(timezone.utc) - timedelta(seconds=400)).isoformat()
    os = _os(latest_ts=stale)
    checks = run_correlation_checks(vecs, dp, os, [], {}, {}, {})
    fresh = next((c for c in checks if c.id == "corr.e2e.freshness"), None)
    assert fresh is not None
    assert fresh.status == Status.RED


def test_indexing_stall_detected():
    vecs = [_vec("10.0.0.11", sent=10000.0)]
    dp = _dp(os_in=5000.0)
    os = _os(total=1000)
    prev_v = {"10.0.0.11": {"sent_events": 0.0}}
    prev_dp = {"records_processed": 0.0, "os_records_in": 0.0,
               "tls_handshake_failure": 0.0, "buffer_write_failed": 0.0,
               "os_bulk_request_failed": 0.0, "http_success_requests": 0.0}
    prev_os = {"total_count": 1000}  # no growth
    checks = run_correlation_checks(vecs, dp, os, [], prev_v, prev_dp, prev_os)
    stall = next((c for c in checks if "stall" in c.id), None)
    assert stall is not None
    assert stall.status == Status.RED


def test_buffer_bottleneck_detected():
    vecs = [_vec("10.0.0.11")]
    dp = _dp(buf_usage=0.95, buf_write_fail=5.0)
    os = _os(cluster_status="red")
    prev_dp = {"buffer_write_failed": 0.0, "tls_handshake_failure": 0.0,
               "records_processed": 0.0, "os_records_in": 0.0,
               "os_bulk_request_failed": 0.0, "http_success_requests": 0.0}
    checks = run_correlation_checks(vecs, dp, os, [], {}, prev_dp, {})
    bottleneck = next((c for c in checks if "bottleneck" in c.id and c.status == Status.RED), None)
    assert bottleneck is not None
