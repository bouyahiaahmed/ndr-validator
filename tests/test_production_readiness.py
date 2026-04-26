"""
Production readiness validator – 9-scenario test suite.

Tests are fully self-contained using unittest.mock – no live services required.
"""
from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock
from typing import Dict, Optional

from app.models import CheckResult, Component, Diagnosis, Status, ProductionReadiness, ReadinessLevel
from app.services.readiness import compute_readiness


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _chk(
    id: str,
    status: Status,
    severity: str = "warning",
    title: str = "",
    details: str = "",
    diagnosis: Optional[Diagnosis] = None,
) -> CheckResult:
    return CheckResult(
        id=id,
        title=title or id,
        component=Component.OPENSEARCH,
        severity=severity,
        status=status,
        details=details,
        diagnosis=diagnosis,
    )


def _green_baseline() -> list:
    """A minimal all-green check set covering all critical paths."""
    return [
        _chk("vector.10.0.0.1.reachable", Status.GREEN, "critical"),
        _chk("dp.metrics.reachable", Status.GREEN, "critical"),
        _chk("dp.os.doc_errors", Status.GREEN, "critical"),
        _chk("dp.os.bulk_failed", Status.GREEN, "critical"),
        _chk("os.cluster.health", Status.GREEN, "critical"),
        _chk("freshness.sensor_liveness.10.0.0.1", Status.GREEN, "critical"),
        _chk("freshness.detection_coverage.conn", Status.GREEN, "warning"),
        _chk("freshness.detection_coverage.dns", Status.GREEN, "warning"),
        _chk("corr.tls.mismatch", Status.GREEN, "critical"),
    ]


# ─── Scenario 1: Sensor alive (dhcp logs) but detection logs stale ───────────

def test_sensor_liveness_green_coverage_yellow_no_red(monkeypatch):
    """
    Sensor has fresh dhcp/analyzer logs → liveness GREEN.
    conn/dns detection log types are stale → coverage YELLOW.
    Overall readiness is NOT red / NOT blocking.
    """
    from app.checks.freshness_checks import run_sensor_liveness_checks, run_detection_coverage_checks

    monkeypatch.setattr("app.config.settings.STALE_DATA_THRESHOLD_SECONDS", 120)
    monkeypatch.setattr("app.config.settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS", 300)
    monkeypatch.setattr("app.config.settings.REQUIRED_LOG_TYPES", "conn,dns,http")
    monkeypatch.setattr("app.config.settings.CONTINUOUS_REQUIRED_LOG_TYPES", "")
    monkeypatch.setattr("app.config.settings.SENSOR_LIVENESS_INDEX_PATTERN", "zeek-*")
    monkeypatch.setattr("app.config.settings.SENSOR_LIST", "10.0.0.2")
    monkeypatch.setattr("app.config.settings.SENSOR_NAME_MAP_JSON", "{}")
    monkeypatch.setattr("app.config.settings.ZEEK_LOG_DIR", "/opt/zeek/logs/current")

    # Sensor has fresh data in liveness pattern (far future → always fresh)
    liveness_freshness = {"10.0.0.2": "2099-01-01T00:00:00Z"}
    liveness = run_sensor_liveness_checks(liveness_freshness)
    coverage = run_detection_coverage_checks({})  # no detection log data

    live_check = next((c for c in liveness if "10.0.0.2" in c.id), None)
    assert live_check is not None, "Missing liveness check for 10.0.0.2"
    assert live_check.status == Status.GREEN, f"Liveness should be GREEN, got {live_check.status}"

    for chk in coverage:
        assert chk.status in (Status.YELLOW, Status.GREEN), (
            f"Coverage check {chk.id} must be YELLOW/GREEN (not RED) when "
            f"CONTINUOUS_REQUIRED_LOG_TYPES is empty, got {chk.status}"
        )

    all_checks = liveness + coverage
    readiness = compute_readiness(all_checks, ssh_enabled=False)
    assert readiness.score > 0
    assert not any("liveness" in b for b in readiness.blocking_issues)


# ─── Scenario 2: Sensor no data anywhere → liveness RED ─────────────────────

def test_sensor_no_data_liveness_red(monkeypatch):
    """No data from a sensor in liveness pattern → sensor_liveness check is RED."""
    from app.checks.freshness_checks import run_sensor_liveness_checks

    monkeypatch.setattr("app.config.settings.SENSOR_LIST", "10.0.0.9")
    monkeypatch.setattr("app.config.settings.SENSOR_NAME_MAP_JSON", "{}")
    monkeypatch.setattr("app.config.settings.SENSOR_LIVENESS_INDEX_PATTERN", "zeek-*")
    monkeypatch.setattr("app.config.settings.STALE_DATA_THRESHOLD_SECONDS", 120)
    monkeypatch.setattr("app.config.settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS", 300)
    monkeypatch.setattr("app.config.settings.ZEEK_LOG_DIR", "/opt/zeek/logs/current")

    liveness = run_sensor_liveness_checks({})  # empty = no sensor data at all

    check = next((c for c in liveness if "10.0.0.9" in c.id), None)
    assert check is not None, "Missing liveness check for sensor 10.0.0.9"
    assert check.status == Status.RED, f"No data → liveness must be RED, got {check.status}"
    assert check.diagnosis is not None, "Diagnosis must be populated for RED liveness check"
    assert check.diagnosis.fix_location, "fix_location must be set"


# ─── Scenario 3: Vector dp_ingest Δ == DP processed Δ → GREEN ───────────────

def test_vector_dp_exact_match_is_green(monkeypatch):
    """
    When Vector dp_ingest sent delta equals Data Prepper records_processed delta,
    the corr.vector_dp.drop_rate check must be GREEN.
    """
    from app.checks.correlation_checks import run_correlation_checks
    from app.collectors.vector_collector import VectorScrapeResult
    from app.collectors.dataprepper_collector import DataPrepperScrapeResult

    monkeypatch.setattr("app.config.settings.VECTOR_DATAPREPPER_SINK_COMPONENTS", "dp_ingest")
    monkeypatch.setattr("app.config.settings.MAX_VECTOR_TO_DP_DROP_PERCENT", 5)

    vr = VectorScrapeResult("10.0.0.1")
    vr.reachable = True
    vr.dp_sink_sent_events = 1500.0
    vr.dp_sink_ambiguous = False
    vr.detected_dp_sink_ids = ["dp_ingest"]
    vr.excluded_sink_ids = []
    vr.discarded_events = 200.0
    vr.source_received_events = 1700.0

    dp = DataPrepperScrapeResult()
    dp.metrics_reachable = True
    dp.records_processed = 1500.0
    dp.http_requests_received = 10.0
    dp.os_records_in = 1500.0
    dp.os_document_errors = 0.0
    dp.buffer_usage = 0.1
    dp.buffer_write_failed = 0.0
    dp.buffer_write_timeouts = 0.0
    dp.os_bulk_request_failed = 0.0
    dp.os_pipeline_latency = 0.3
    dp.tls_handshake_failure = 0.0
    dp.http_success_requests = 10.0
    dp.metrics_tls_ok = True

    prev_vr = {"10.0.0.1": {"dp_sink_sent_events": 1000.0, "discarded_events": 0.0, "source_received_events": 1000.0}}
    prev_dp = {"records_processed": 1000.0}

    checks = run_correlation_checks([vr], dp, None, [], prev_vector=prev_vr, prev_dp=prev_dp, prev_os={})
    drop_check = next((c for c in checks if c.id == "corr.vector_dp.drop_rate"), None)
    assert drop_check is not None, "corr.vector_dp.drop_rate check must exist"
    assert drop_check.status == Status.GREEN, (
        f"Exact-match delivery must be GREEN, got {drop_check.status}: {drop_check.details}"
    )


# ─── Scenario 4: DP document errors → blocking ───────────────────────────────

def test_dp_document_errors_blocking():
    """Data Prepper document errors → appears in blocking_issues."""
    checks = [
        _chk("dp.os.doc_errors", Status.RED, "critical",
             title="Data Prepper document errors",
             details="Document error delta: 42"),
    ]
    r = compute_readiness(checks, ssh_enabled=False)
    assert r.score < 100, "Score must drop when doc_errors is RED"
    assert any("document error" in b.lower() or "dp.os.doc_errors" in b.lower()
               or "document" in b.lower() for b in r.blocking_issues), (
        f"dp.os.doc_errors RED must be blocking. blocking_issues={r.blocking_issues}"
    )


# ─── Scenario 5: OS single-node replicas → warning only, not blocking ────────

def test_opensearch_single_node_replicas_warning_only():
    """OpenSearch YELLOW (single-node replica) → warning, NOT blocking."""
    checks = [
        _chk("os.cluster.health", Status.YELLOW, "critical",
             title="OpenSearch cluster health",
             details="Cluster status: yellow"),
        _chk("os.cluster.active_shards", Status.YELLOW, "warning",
             title="OpenSearch active shards %",
             details="Active shards: 50% – single-node"),
    ]
    r = compute_readiness(checks, ssh_enabled=False)
    assert len(r.blocking_issues) == 0, (
        f"Single-node replica shards must NOT be blocking. blocking={r.blocking_issues}"
    )
    assert len(r.warnings) > 0, "Should have at least one warning for YELLOW cluster"
    assert r.score > 70, f"Score should stay above 70 for warning-only issues, got {r.score}"


# ─── Scenario 6: Zeek SSH disabled → UNKNOWN, not production_ready ───────────

def test_zeek_ssh_disabled_unknown_not_production_ready():
    """
    When ENABLE_SENSOR_SSH=False, Zeek checks are UNKNOWN.
    System is NOT production_ready (can be production_candidate at best).
    """
    checks = _green_baseline()
    # Add UNKNOWN zeek checks (as would happen when SSH is disabled)
    checks.append(_chk("zeek.10.0.0.1.running", Status.UNKNOWN, "critical"))
    checks.append(_chk("zeek.10.0.0.1.ssh", Status.UNKNOWN, "critical"))

    r = compute_readiness(checks, ssh_enabled=False)
    assert r.readiness_level != ReadinessLevel.PRODUCTION_READY, (
        f"With SSH disabled, must NOT be production_ready (got {r.readiness_level})"
    )
    assert r.readiness_level in (
        ReadinessLevel.PRODUCTION_CANDIDATE,
        ReadinessLevel.LAB_READY,
        ReadinessLevel.NOT_READY,
    )


# ─── Scenario 7: Zeek SSH enabled and Zeek down → blocking ───────────────────

def test_zeek_ssh_enabled_zeek_down_is_blocking():
    """When SSH enabled and Zeek is down → blocking_issues contains Zeek entry."""
    checks = _green_baseline()
    checks.append(_chk(
        "zeek.10.0.0.1.running", Status.RED, "critical",
        title="Zeek running on sensor1",
        details="Zeek not running",
    ))
    r = compute_readiness(checks, ssh_enabled=True)
    assert len(r.blocking_issues) > 0, "Zeek down with SSH enabled must be blocking"
    assert any("zeek" in b.lower() or "sensor" in b.lower() for b in r.blocking_issues), (
        f"Blocking issues should mention Zeek: {r.blocking_issues}"
    )
    assert r.score < 90, f"Score must drop below 90 with Zeek blocking, got {r.score}"


# ─── Scenario 8: DP health endpoint missing (404) but records healthy → YELLOW ──

def test_dp_health_404_records_healthy_yellow_not_blocking():
    """
    DP health endpoint returns 404 (YELLOW) but records_processed increasing (GREEN).
    Must not be a blocking issue.
    """
    checks = [
        _chk("dp.ingest.reachable", Status.YELLOW, "warning",
             title="Data Prepper ingest health",
             details="Health endpoint returned 404"),
        _chk("dp.records.processed", Status.GREEN, "warning"),
        _chk("dp.metrics.reachable", Status.GREEN, "critical"),
    ]
    r = compute_readiness(checks, ssh_enabled=False)
    assert len(r.blocking_issues) == 0, (
        f"Health endpoint 404 must NOT be blocking. blocking={r.blocking_issues}"
    )
    assert any("ingest" in w.lower() or "404" in w or "health" in w.lower() for w in r.warnings), (
        f"Health 404 should appear as a warning. warnings={r.warnings}"
    )


# ─── Scenario 9: Readiness score changes correctly ───────────────────────────

def test_readiness_score_transitions():
    """Score decreases predictably as blocking issues are added."""
    # All green
    all_green = _green_baseline()
    r0 = compute_readiness(all_green, ssh_enabled=True)
    assert r0.score >= 90, f"All-green must score ≥90, got {r0.score}"
    assert not r0.blocking_issues

    # One blocking issue (-15)
    one_blocking = _green_baseline() + [
        _chk("vector.10.0.0.2.reachable", Status.RED, "critical",
             title="Vector reachable on sensor2"),
    ]
    r1 = compute_readiness(one_blocking, ssh_enabled=True)
    assert r1.score < r0.score, "One blocking issue must lower score"
    assert r1.score <= 85, f"One blocking (-15) should give ≤85, got {r1.score}"

    # Multiple blocking issues
    multi_blocking = _green_baseline() + [
        _chk("vector.10.0.0.2.reachable", Status.RED, "critical"),
        _chk("dp.os.doc_errors", Status.RED, "critical"),
        _chk("freshness.sensor_liveness.10.0.0.3", Status.RED, "critical"),
    ]
    r2 = compute_readiness(multi_blocking, ssh_enabled=True)
    assert r2.score < r1.score, "More blocking issues must lower score further"
    assert r2.score <= 55, f"Three blocking issues should give ≤55, got {r2.score}"
    assert r2.readiness_level in (ReadinessLevel.LAB_READY, ReadinessLevel.NOT_READY)

    # Full failure
    all_bad = [
        _chk("vector.10.0.0.1.reachable", Status.RED, "critical"),
        _chk("dp.metrics.reachable", Status.RED, "critical"),
        _chk("dp.os.doc_errors", Status.RED, "critical"),
        _chk("dp.os.bulk_failed", Status.RED, "critical"),
        _chk("os.cluster.health", Status.RED, "critical"),
        _chk("freshness.sensor_liveness.10.0.0.1", Status.RED, "critical"),
        _chk("corr.tls.mismatch", Status.RED, "critical"),
    ]
    r3 = compute_readiness(all_bad, ssh_enabled=True)
    assert r3.score <= 0, f"All blocking must give score=0, got {r3.score}"
    assert r3.readiness_level == ReadinessLevel.NOT_READY
