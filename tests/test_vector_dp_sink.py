"""
Tests for VECTOR_DATAPREPPER_SINK_COMPONENTS and intentional filtering.
Covers all 8 test scenarios from the specification.
"""
from __future__ import annotations
import pytest
from typing import Dict, Any
from unittest.mock import MagicMock

from app.collectors.vector_collector import (
    VectorScrapeResult,
    _build_sink_sent_map,
    _resolve_dp_sink,
    _extract_intentional_discards,
    _extract_source_received,
    get_flat_metrics,
    _PROM_SINK_TYPES,
)
from app.utils.prometheus_parser import MetricFamily, MetricSample


# ─── Helpers ────────────────────────────────────────────────────────────────

def _make_sample(
    metric_name: str,
    component_id: str,
    component_kind: str = "",
    component_type: str = "",
    intentional: str = "",
    value: float = 1000.0,
) -> MetricSample:
    labels: Dict[str, str] = {"component_id": component_id}
    if component_kind:
        labels["component_kind"] = component_kind
    if component_type:
        labels["component_type"] = component_type
    if intentional:
        labels["intentional"] = intentional
    return MetricSample(name=metric_name, labels=labels, value=value)


def _make_families(*samples: MetricSample) -> Dict[str, MetricFamily]:
    """Group samples into families by metric name."""
    families: Dict[str, MetricFamily] = {}
    for s in samples:
        if s.name not in families:
            families[s.name] = MetricFamily(name=s.name, type="counter")
            families[s.name].samples = []
        families[s.name].samples.append(s)
    return families


def _make_vr(
    sensor_ip: str = "10.0.0.1",
    dp_sink_sent: float = 0.0,
    ambiguous: bool = False,
    detected: list = None,
    excluded: list = None,
    discarded: float = 0.0,
    source_received: float = 0.0,
) -> VectorScrapeResult:
    vr = VectorScrapeResult(sensor_ip)
    vr.reachable = True
    vr.dp_sink_sent_events = dp_sink_sent
    vr.dp_sink_ambiguous = ambiguous
    vr.detected_dp_sink_ids = detected or []
    vr.excluded_sink_ids = excluded or []
    vr.discarded_events = discarded
    vr.source_received_events = source_received
    return vr


# ─── Scenario 1: Only dp_ingest is counted ──────────────────────────────────

def test_only_dp_ingest_counted_not_prom_or_transforms():
    """Source, transforms, prom_metrics sink, and dp_ingest: only dp_ingest sent events counted."""
    families = _make_families(
        # source – should be excluded from sink map for DP delivery
        _make_sample("vector_component_sent_events_total",
                     "zeek_raw", component_kind="source", component_type="file", value=5000),
        # transforms – should never count for DP delivery
        _make_sample("vector_component_sent_events_total",
                     "zeek_filter", component_kind="transform", component_type="filter", value=4000),
        _make_sample("vector_component_sent_events_total",
                     "zeek_drop_ntp_noise", component_kind="transform", component_type="filter", value=3500),
        # prom sink – must never count
        _make_sample("vector_component_sent_events_total",
                     "prom_exporter", component_kind="sink", component_type="prometheus_exporter", value=999),
        # dp_ingest – the only one that should count
        _make_sample("vector_component_sent_events_total",
                     "dp_ingest", component_kind="sink", component_type="http", value=181),
    )
    sink_map = _build_sink_sent_map(families)
    # Resolve with explicit config
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, ["dp_ingest"])

    assert not ambiguous
    assert detected == ["dp_ingest"]
    assert dp_sent == pytest.approx(181.0)
    assert "prom_exporter" in excluded
    assert "zeek_filter" in excluded


def test_transforms_never_counted():
    """Transform component_sent_events must never appear in DP sink resolution."""
    families = _make_families(
        _make_sample("vector_component_sent_events_total",
                     "zeek_drop_pipeline", component_kind="transform", component_type="filter", value=999),
        _make_sample("vector_component_sent_events_total",
                     "dp_ingest", component_kind="sink", component_type="http", value=100),
    )
    sink_map = _build_sink_sent_map(families)
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, ["dp_ingest"])
    assert dp_sent == pytest.approx(100.0)
    assert "zeek_drop_pipeline" in excluded


# ─── Scenario 2: Intentional discards are not delivery loss ─────────────────

def test_intentional_discards_extracted():
    """vector_component_discarded_events_total{intentional=true} is summed."""
    families = _make_families(
        _make_sample("vector_component_discarded_events_total",
                     "zeek_filter", component_kind="transform",
                     component_type="filter", intentional="true", value=800),
        _make_sample("vector_component_discarded_events_total",
                     "zeek_drop_ntp_noise", component_kind="transform",
                     component_type="filter", intentional="true", value=200),
    )
    total = _extract_intentional_discards(families)
    assert total == pytest.approx(1000.0)


def test_non_intentional_discards_not_counted():
    """Discards without intentional=true are not summed."""
    families = _make_families(
        _make_sample("vector_component_discarded_events_total",
                     "zeek_filter", intentional="false", value=500),
        _make_sample("vector_component_discarded_events_total",
                     "zeek_drop_ntp_noise", intentional="true", value=100),
    )
    total = _extract_intentional_discards(families)
    assert total == pytest.approx(100.0)


def test_filtering_check_is_green_never_red(monkeypatch):
    """corr.vector_dp.filtering must be GREEN even with high discard rate."""
    from app.checks.correlation_checks import run_correlation_checks
    from app.collectors.dataprepper_collector import DataPrepperScrapeResult
    from app.models import Status

    monkeypatch.setattr("app.config.settings.VECTOR_DATAPREPPER_SINK_COMPONENTS", "dp_ingest")

    vr = _make_vr("10.0.0.1", dp_sink_sent=181.0, ambiguous=False,
                  detected=["dp_ingest"], excluded=["prom_exporter"],
                  discarded=800.0, source_received=1000.0)

    dp = DataPrepperScrapeResult()
    dp.metrics_reachable = True
    dp.records_processed = 181.0
    dp.http_requests_received = 10.0
    dp.os_records_in = 181.0
    dp.os_document_errors = 0.0
    dp.buffer_usage = 0.05
    dp.buffer_write_failed = 0.0
    dp.buffer_write_timeouts = 0.0
    dp.os_bulk_request_failed = 0.0
    dp.os_pipeline_latency = 0.5
    dp.tls_handshake_failure = 0.0
    dp.http_success_requests = 10.0
    dp.metrics_tls_ok = True

    prev_vr = {"10.0.0.1": {"dp_sink_sent_events": 0.0,
                             "discarded_events": 0.0,
                             "source_received_events": 0.0}}
    prev_dp = {}

    checks = run_correlation_checks(
        [vr], dp, None, [], prev_vector=prev_vr, prev_dp=prev_dp, prev_os={}
    )
    filtering_check = next((c for c in checks if c.id == "corr.vector_dp.filtering"), None)
    if filtering_check:
        assert filtering_check.status == Status.GREEN, (
            f"Filtering check must be GREEN, got {filtering_check.status}"
        )


# ─── Scenario 3: Multiple HTTP sinks → UNKNOWN not RED ──────────────────────

def test_multiple_http_sinks_no_config_gives_ambiguous():
    """When multiple HTTP sinks exist and no config: ambiguous=True."""
    sink_map = {
        "dp_ingest": {"sent": 181.0, "kind": "sink", "type": "http", "metric": "vector_component_sent_events_total"},
        "backup_sink": {"sent": 50.0, "kind": "sink", "type": "http", "metric": "vector_component_sent_events_total"},
    }
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, [])
    assert ambiguous is True
    assert dp_sent == 0.0


def test_multiple_http_sinks_emits_unknown_check(monkeypatch):
    """corr.vector_dp.drop_rate must be UNKNOWN (not RED) when sink is ambiguous."""
    from app.checks.correlation_checks import run_correlation_checks
    from app.collectors.dataprepper_collector import DataPrepperScrapeResult
    from app.models import Status

    monkeypatch.setattr("app.config.settings.VECTOR_DATAPREPPER_SINK_COMPONENTS", "")

    vr = _make_vr("10.0.0.1", dp_sink_sent=0.0, ambiguous=True,
                  detected=[], excluded=["dp_ingest", "backup_sink"])

    dp = DataPrepperScrapeResult()
    dp.metrics_reachable = True
    dp.records_processed = 181.0

    checks = run_correlation_checks([vr], dp, None, [], prev_vector={}, prev_dp={}, prev_os={})
    drop_check = next((c for c in checks if c.id == "corr.vector_dp.drop_rate"), None)
    assert drop_check is not None
    assert drop_check.status == Status.UNKNOWN, (
        f"Ambiguous sink must yield UNKNOWN, got {drop_check.status}"
    )
    assert "VECTOR_DATAPREPPER_SINK_COMPONENTS" in drop_check.details


# ─── Scenario 4: Configured dp_ingest → correct drop rate ───────────────────

def test_configured_sink_calculates_correct_drop_rate(monkeypatch):
    """VECTOR_DATAPREPPER_SINK_COMPONENTS=dp_ingest uses only dp_ingest metrics."""
    from app.checks.correlation_checks import run_correlation_checks
    from app.collectors.dataprepper_collector import DataPrepperScrapeResult
    from app.models import Status

    monkeypatch.setattr("app.config.settings.VECTOR_DATAPREPPER_SINK_COMPONENTS", "dp_ingest")

    # dp_ingest sent 181, DP processed 178 → drop = (181-178)/181 = 1.66% → GREEN
    vr = _make_vr("10.0.0.1", dp_sink_sent=1181.0, ambiguous=False,
                  detected=["dp_ingest"], excluded=["prom_exporter"])

    dp = DataPrepperScrapeResult()
    dp.metrics_reachable = True
    dp.records_processed = 1178.0

    prev_vr = {"10.0.0.1": {"dp_sink_sent_events": 1000.0}}
    prev_dp = {"records_processed": 1000.0}

    checks = run_correlation_checks(
        [vr], dp, None, [], prev_vector=prev_vr, prev_dp=prev_dp, prev_os={}
    )
    drop_check = next((c for c in checks if c.id == "corr.vector_dp.drop_rate"), None)
    assert drop_check is not None
    assert drop_check.status == Status.GREEN, (
        f"1.66% drop should be GREEN, got {drop_check.status}: {drop_check.details}"
    )
    # Verify diagnostics contain the sink ID
    assert "dp_ingest" in drop_check.details


def test_configured_sink_drop_rate_details_include_diagnostics(monkeypatch):
    """Drop rate check details must include sink IDs, per-sensor info, DP counter."""
    from app.checks.correlation_checks import run_correlation_checks
    from app.collectors.dataprepper_collector import DataPrepperScrapeResult

    monkeypatch.setattr("app.config.settings.VECTOR_DATAPREPPER_SINK_COMPONENTS", "dp_ingest")

    vr = _make_vr("10.0.0.1", dp_sink_sent=281.0, ambiguous=False,
                  detected=["dp_ingest"], excluded=["prom_exporter"])
    dp = DataPrepperScrapeResult()
    dp.metrics_reachable = True
    dp.records_processed = 275.0

    checks = run_correlation_checks(
        [vr], dp, None, [],
        prev_vector={"10.0.0.1": {"dp_sink_sent_events": 100.0}},
        prev_dp={"records_processed": 100.0},
        prev_os={},
    )
    drop_check = next(c for c in checks if c.id == "corr.vector_dp.drop_rate")
    # Must contain diagnostics
    assert "dp_ingest" in drop_check.details
    assert "records_processed" in drop_check.details
    assert "Δ" in drop_check.details


# ─── Scenario 5: prometheus_exporter never counted ──────────────────────────

def test_prometheus_exporter_never_counted():
    """prometheus_exporter sink is excluded from DP delivery count."""
    sink_map = {
        "prom_sink": {"sent": 9999.0, "kind": "sink",
                      "type": "prometheus_exporter", "metric": "vector_component_sent_events_total"},
        "dp_ingest": {"sent": 200.0, "kind": "sink",
                      "type": "http", "metric": "vector_component_sent_events_total"},
    }
    # Auto-detection with no config should pick dp_ingest
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, [])
    assert not ambiguous
    assert detected == ["dp_ingest"]
    assert dp_sent == pytest.approx(200.0)
    assert "prom_sink" in excluded


def test_all_prom_sink_types_excluded():
    """All known prometheus sink type strings are excluded from inference."""
    for prom_type in ("prometheus_exporter", "prometheus_remote_write", "prom_metrics", "prometheus"):
        sink_map = {
            "prom_s": {"sent": 999.0, "kind": "sink", "type": prom_type, "metric": "x"},
            "dp_ingest": {"sent": 100.0, "kind": "sink", "type": "http", "metric": "x"},
        }
        _, ambiguous, detected, _ = _resolve_dp_sink(sink_map, [])
        assert not ambiguous, f"Should resolve unambiguously excluding {prom_type}"
        assert "dp_ingest" in detected
        assert "prom_s" not in detected


# ─── Scenario 6: Transforms never counted for DP delivery ───────────────────

def test_transform_sent_events_not_in_sink_map():
    """_build_sink_sent_map only maps components present in sent_events metric.
    Transforms will appear but _resolve_dp_sink must exclude them when configured."""
    families = _make_families(
        _make_sample("vector_component_sent_events_total",
                     "zeek_filter", component_kind="transform", value=4500),
        _make_sample("vector_component_sent_events_total",
                     "dp_ingest", component_kind="sink", component_type="http", value=200),
    )
    sink_map = _build_sink_sent_map(families)
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, ["dp_ingest"])

    assert dp_sent == pytest.approx(200.0)
    assert not ambiguous
    # zeek_filter is in sink_map (it has sent_events) but must be excluded
    assert "zeek_filter" in excluded


def test_transform_auto_inference_excluded():
    """Without configuration, transforms are excluded from auto-inference."""
    sink_map = {
        "zeek_drop_ntp": {"sent": 1000.0, "kind": "transform", "type": "filter", "metric": "x"},
        "dp_ingest": {"sent": 100.0, "kind": "sink", "type": "http", "metric": "x"},
    }
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, [])
    assert not ambiguous
    assert detected == ["dp_ingest"]
    assert "zeek_drop_ntp" in excluded


# ─── Scenario 7: get_flat_metrics includes new fields ───────────────────────

def test_flat_metrics_includes_dp_sink_fields():
    """get_flat_metrics must persist dp_sink_sent_events for delta computation."""
    vr = _make_vr("10.0.0.1", dp_sink_sent=500.0, discarded=100.0, source_received=1000.0)
    flat = get_flat_metrics(vr)
    assert "dp_sink_sent_events" in flat
    assert flat["dp_sink_sent_events"] == pytest.approx(500.0)
    assert "discarded_events" in flat
    assert "source_received_events" in flat


# ─── Scenario 8: source_received extraction ─────────────────────────────────

def test_source_received_only_source_kind():
    """Only source-kind components are counted for source_received_events."""
    families = _make_families(
        _make_sample("vector_component_received_events_total",
                     "zeek_raw", component_kind="source", component_type="file", value=5000),
        _make_sample("vector_component_received_events_total",
                     "zeek_filter", component_kind="transform", component_type="filter", value=4500),
    )
    total = _extract_source_received(families)
    assert total == pytest.approx(5000.0)


# ─── Scenario 9: vector_-prefixed discarded metric names ────────────────────

def test_vector_prefixed_discarded_metric():
    """vector_component_discarded_events_total (with prefix) is recognized."""
    families = _make_families(
        _make_sample("vector_component_discarded_events_total",
                     "zeek_drop_pkg_http", component_kind="transform",
                     intentional="true", value=300),
    )
    total = _extract_intentional_discards(families)
    assert total == pytest.approx(300.0)


# ─── Scenario 10: Single HTTP sink auto-detected ────────────────────────────

def test_single_http_sink_auto_detected():
    """When exactly one non-prom HTTP sink exists, auto-detection succeeds."""
    sink_map = {
        "prom_s": {"sent": 9999.0, "kind": "sink", "type": "prometheus_exporter", "metric": "x"},
        "dp_ingest": {"sent": 181.0, "kind": "sink", "type": "http", "metric": "x"},
    }
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, [])
    assert not ambiguous
    assert dp_sent == pytest.approx(181.0)
    assert detected == ["dp_ingest"]


def test_zero_http_sinks_gives_ambiguous():
    """When there are no HTTP sinks, result is ambiguous (not an exception)."""
    sink_map = {
        "prom_s": {"sent": 999.0, "kind": "sink", "type": "prometheus_exporter", "metric": "x"},
    }
    dp_sent, ambiguous, detected, _ = _resolve_dp_sink(sink_map, [])
    assert ambiguous is True
    assert dp_sent == 0.0
    assert detected == []


def test_empty_sink_map_gives_ambiguous():
    """When no components have sent_events, result is ambiguous."""
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink({}, [])
    assert ambiguous is True
    assert dp_sent == 0.0


# ─── Scenario 11: Configured ID not found in metrics ────────────────────────

def test_configured_sink_not_found_in_metrics():
    """If the configured component_id is not in the metrics, emit ambiguous."""
    sink_map = {
        "other_sink": {"sent": 100.0, "kind": "sink", "type": "http", "metric": "x"},
    }
    dp_sent, ambiguous, detected, excluded = _resolve_dp_sink(sink_map, ["dp_ingest"])
    assert ambiguous is True
    assert dp_sent == 0.0
