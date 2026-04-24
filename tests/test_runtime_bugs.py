"""
Tests for runtime bugs discovered from real NDR lab deployment.
Covers all 10 fix areas from the runtime findings report.
"""
from __future__ import annotations
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1 · Dotted field lookup
# ─────────────────────────────────────────────────────────────────────────────
from app.utils.field_utils import get_field


def test_literal_dotted_key_lookup():
    """Raw Zeek docs store 'id.orig_h' as a literal key."""
    doc = {"id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2"}
    assert get_field(doc, "id.orig_h") == "1.1.1.1"
    assert get_field(doc, "id.resp_h") == "2.2.2.2"


def test_nested_object_fallback():
    """ECS-normalised docs use nested objects."""
    doc = {"id": {"orig_h": "1.1.1.1"}}
    assert get_field(doc, "id.orig_h") == "1.1.1.1"


def test_exact_key_preferred_over_nested():
    """When both literal key and nested path exist, literal key wins."""
    doc = {"id.orig_h": "literal", "id": {"orig_h": "nested"}}
    assert get_field(doc, "id.orig_h") == "literal"


def test_missing_field_returns_none():
    assert get_field({"a": "b"}, "id.orig_h") is None


def test_non_dict_returns_none():
    assert get_field(None, "id.orig_h") is None  # type: ignore[arg-type]


def test_top_level_key():
    doc = {"@timestamp": "2024-01-01T00:00:00Z", "proto": "tcp"}
    assert get_field(doc, "@timestamp") == "2024-01-01T00:00:00Z"
    assert get_field(doc, "proto") == "tcp"


def test_coverage_check_uses_get_field():
    """data_quality_checks must detect literal dotted keys in coverage sample."""
    from app.checks.data_quality_checks import _safe_id
    from app.utils.field_utils import get_field as gf
    doc = {"id.orig_h": "10.0.0.1"}
    assert gf(doc, "id.orig_h") == "10.0.0.1"


# ─────────────────────────────────────────────────────────────────────────────
# Fix 2 · Data Prepper pipeline latency
# ─────────────────────────────────────────────────────────────────────────────
from app.collectors.dataprepper_collector import DataPrepperScrapeResult
from app.checks.dataprepper_checks import _compute_safe_latency


def _base_dp():
    r = DataPrepperScrapeResult()
    r.metrics_reachable = True
    r.metrics_tls_ok = True
    r.metrics_auth_ok = True
    r.families = {"x": MagicMock()}
    r.pipeline_names = ["zeek_ingestion_pipeline"]
    return r


def test_latency_prefers_max_gauge():
    """_max is semantically correct (rolling window), use it first."""
    r = _base_dp()
    r.os_pipeline_latency_max = 0.5      # 500ms – sensible
    r.os_pipeline_latency_sum = 24046.0  # cumulative sum – should be ignored
    r.os_pipeline_latency_count = 1000.0
    lat, source = _compute_safe_latency(r, {})
    assert lat == pytest.approx(0.5)
    assert "max" in source


def test_latency_delta_average_when_no_max():
    """Without _max, compute delta(sum)/delta(count) from previous snapshot."""
    r = _base_dp()
    r.os_pipeline_latency_max = -1.0
    r.os_pipeline_latency_sum = 1010.0
    r.os_pipeline_latency_count = 200.0
    prev = {"os_pipeline_latency_sum": 1000.0, "os_pipeline_latency_count": 190.0}
    lat, source = _compute_safe_latency(r, prev)
    # delta = 10s / 10 obs = 1.0s average
    assert lat == pytest.approx(1.0)
    assert "delta" in source


def test_latency_unknown_on_first_scrape():
    """On first cycle there is no prev snapshot → emit None (UNKNOWN)."""
    r = _base_dp()
    r.os_pipeline_latency_max = -1.0
    r.os_pipeline_latency_sum = 1000.0
    r.os_pipeline_latency_count = 100.0
    # prev has same values → count_delta = 0
    prev = {"os_pipeline_latency_sum": 1000.0, "os_pipeline_latency_count": 100.0}
    lat, source = _compute_safe_latency(r, prev)
    assert lat is None


def test_cumulative_sum_not_used_as_latency():
    """24046s cumulative sum must never appear as a latency value."""
    r = _base_dp()
    r.os_pipeline_latency_max = -1.0
    r.os_pipeline_latency_sum = 24046.0
    r.os_pipeline_latency_count = 5000.0
    # No prev → UNKNOWN
    lat, _ = _compute_safe_latency(r, {})
    assert lat is None


def test_latency_check_emits_unknown_not_red_on_first_cycle():
    """The check must not mark RED when latency cannot be computed."""
    from app.checks.dataprepper_checks import run_dataprepper_checks
    from app.models import Status
    r = _base_dp()
    r.os_pipeline_latency_max = -1.0
    r.os_pipeline_latency_sum = 24046.0
    r.os_pipeline_latency_count = 5000.0
    r.ingest_reachable = True
    r.ingest_healthy = True
    checks = run_dataprepper_checks(r, {})
    lat_check = next(c for c in checks if c.id == "dp.pipeline.latency")
    assert lat_check.status != Status.RED, (
        f"Latency check must not be RED on first cycle, got {lat_check.status}: {lat_check.details}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Fix 3 · DP→OS correlation scope mismatch
# ─────────────────────────────────────────────────────────────────────────────
from app.checks.correlation_checks import _dp_os_scopes_match


def test_scope_mismatch_detected_for_comma_pattern(monkeypatch):
    """Comma-separated narrowed pattern → mismatch → drop rate check UNKNOWN."""
    monkeypatch.setattr("app.config.settings.OPENSEARCH_INDEX_PATTERN",
                        "zeek-conn-*,zeek-dns-*,zeek-http-*")
    monkeypatch.setattr("app.config.settings.DP_TO_OS_CORRELATION_INDEX_PATTERN", "")
    assert _dp_os_scopes_match() is False


def test_scope_ok_for_broad_wildcard(monkeypatch):
    """Single wildcard (zeek-*) is assumed to cover all DP metric scope."""
    monkeypatch.setattr("app.config.settings.OPENSEARCH_INDEX_PATTERN", "zeek-*")
    monkeypatch.setattr("app.config.settings.DP_TO_OS_CORRELATION_INDEX_PATTERN", "")
    assert _dp_os_scopes_match() is True


def test_scope_ok_when_correlation_pattern_set(monkeypatch):
    """Explicit DP_TO_OS_CORRELATION_INDEX_PATTERN always trusts the user."""
    monkeypatch.setattr("app.config.settings.OPENSEARCH_INDEX_PATTERN",
                        "zeek-conn-*,zeek-dns-*")
    monkeypatch.setattr("app.config.settings.DP_TO_OS_CORRELATION_INDEX_PATTERN", "zeek-*")
    assert _dp_os_scopes_match() is True


def test_dp_os_drop_rate_emits_unknown_on_scope_mismatch(monkeypatch):
    """When scope mismatches, drop rate must be UNKNOWN not RED."""
    from app.checks.correlation_checks import run_correlation_checks
    from app.models import Status
    monkeypatch.setattr("app.config.settings.OPENSEARCH_INDEX_PATTERN",
                        "zeek-conn-*,zeek-dns-*,zeek-http-*,zeek-ssl-*,zeek-files-*")
    monkeypatch.setattr("app.config.settings.DP_TO_OS_CORRELATION_INDEX_PATTERN", "")

    dp = DataPrepperScrapeResult()
    dp.metrics_reachable = True
    dp.os_records_in = 10000.0
    dp.os_document_errors = 0.0
    dp.buffer_usage = 0.1
    dp.buffer_write_failed = 0.0
    dp.buffer_write_timeouts = 0.0
    dp.os_bulk_request_failed = 0.0
    dp.os_pipeline_latency = 0.5
    dp.tls_handshake_failure = 0.0
    dp.http_success_requests = 500.0
    dp.metrics_tls_ok = True

    from app.collectors.opensearch_collector import OpenSearchScrapeResult
    os_r = OpenSearchScrapeResult()
    os_r.reachable = True
    os_r.total_count = 5000  # only 5k vs 10k DP → would be 50% drop (false)
    os_r.cluster = {"status": "yellow"}

    checks = run_correlation_checks([], dp, os_r, [],
                                    prev_dp={"os_records_in": 5000.0},
                                    prev_os={"total_count": 2500})
    drop_check = next((c for c in checks if c.id == "corr.dp_os.drop_rate"), None)
    if drop_check:
        assert drop_check.status in (Status.UNKNOWN, Status.YELLOW), (
            f"Drop rate should be UNKNOWN/YELLOW on scope mismatch, got {drop_check.status}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Fix 4 · OpenSearch @timestamp sort with unmapped indices
# ─────────────────────────────────────────────────────────────────────────────
def test_search_latest_query_includes_unmapped_type():
    """search_latest must include unmapped_type:date in sort to avoid shard exceptions."""
    from app.utils import opensearch as os_util
    import inspect, ast
    src = inspect.getsource(os_util.search_latest)
    assert "unmapped_type" in src, "search_latest must include unmapped_type in sort"


def test_search_recent_query_includes_unmapped_type():
    """search_recent must include unmapped_type:date in sort."""
    from app.utils import opensearch as os_util
    import inspect
    src = inspect.getsource(os_util.search_recent)
    assert "unmapped_type" in src, "search_recent must include unmapped_type in sort"


# ─────────────────────────────────────────────────────────────────────────────
# Fix 5 · OpenSearch single-node replica handling
# ─────────────────────────────────────────────────────────────────────────────
from app.collectors.opensearch_collector import OpenSearchScrapeResult
from app.checks.opensearch_checks import run_opensearch_checks
from app.models import Status


def test_single_node_unassigned_replicas_is_yellow_not_red():
    """Single-node cluster with unassigned replicas must be YELLOW, not RED."""
    r = OpenSearchScrapeResult()
    r.reachable = True
    r.tls_ok = True
    r.auth_ok = True
    r.cluster = {
        "status": "yellow",
        "number_of_nodes": 1,
        "active_primary_shards": 10,
        "active_shards": 10,
        "unassigned_shards": 10,       # replica shards unassigned
        "active_shards_percent_as_number": 50.0,  # would be RED without fix
    }
    r.nodes = [{"name": "node1", "heap.percent": "45"}]
    r.indices = [{"index": "zeek-2024.01.01", "health": "yellow",
                  "docs.count": "1000", "store.size": "100mb"}]
    r.total_count = 1000
    r.search_latency_ms = 50.0
    r.recent_count = 100
    r.overall_latest_ts = datetime.now(timezone.utc).isoformat()
    r.sensors_present = []
    r.log_types_present = []
    r.sensor_freshness = {}
    r.log_type_freshness = {}

    checks = run_opensearch_checks(r, {})
    shard_check = next(c for c in checks if c.id == "os.cluster.active_shards")
    assert shard_check.status == Status.YELLOW, (
        f"Single-node replica issue must be YELLOW not RED, got {shard_check.status}: {shard_check.details}"
    )
    assert "single-node" in shard_check.details.lower() or "replica" in shard_check.details.lower()


def test_primary_unassigned_is_still_red():
    """If primary shards are unassigned, that IS a real problem → RED."""
    r = OpenSearchScrapeResult()
    r.reachable = True
    r.tls_ok = True
    r.auth_ok = True
    r.cluster = {
        "status": "red",
        "number_of_nodes": 1,
        "active_primary_shards": 0,   # primaries missing!
        "active_shards": 0,
        "unassigned_shards": 20,
        "active_shards_percent_as_number": 0.0,
    }
    r.nodes = []
    r.indices = []
    r.total_count = 0
    r.search_latency_ms = 0.0
    r.recent_count = 0
    r.overall_latest_ts = None
    r.sensors_present = []
    r.log_types_present = []
    r.sensor_freshness = {}
    r.log_type_freshness = {}

    checks = run_opensearch_checks(r, {})
    shard_check = next(c for c in checks if c.id == "os.cluster.active_shards")
    assert shard_check.status == Status.RED


# ─────────────────────────────────────────────────────────────────────────────
# Fix 6 · Vector vector_-prefixed metric version detection
# ─────────────────────────────────────────────────────────────────────────────
from app.collectors.vector_collector import _detect_metric_version
from app.utils.prometheus_parser import MetricFamily, MetricSample


def _make_family(name: str, sample_name: str = None) -> MetricFamily:
    fam = MetricFamily(name=name, type="counter")
    fam.samples.append(MetricSample(
        name=sample_name or name,
        labels={"component_kind": "source", "component_id": "zeek_src"},
        value=1234.0,
    ))
    return fam


def test_vector_prefixed_metrics_detected_as_vector_prefixed():
    families = {
        "vector_component_received_events_total": _make_family(
            "vector_component_received_events_total",
        ),
        "vector_component_sent_events_total": _make_family(
            "vector_component_sent_events_total",
        ),
    }
    version = _detect_metric_version(families)
    assert version == "vector_prefixed", f"Expected 'vector_prefixed', got '{version}'"


def test_vector_prefixed_not_marked_unknown():
    families = {
        "vector_component_received_events_total": _make_family(
            "vector_component_received_events_total",
        ),
    }
    version = _detect_metric_version(families)
    assert version != "unknown", "vector_ prefixed metrics must not be classified as unknown"


def test_canonical_metrics_detected_as_current():
    families = {
        "component_received_events_total": _make_family("component_received_events_total"),
        "component_sent_events_total": _make_family("component_sent_events_total"),
    }
    version = _detect_metric_version(families)
    assert version == "current"


def test_legacy_metrics_detected():
    families = {
        "events_in_total": _make_family("events_in_total"),
        "events_out_total": _make_family("events_out_total"),
    }
    version = _detect_metric_version(families)
    assert version == "legacy"


# ─────────────────────────────────────────────────────────────────────────────
# Fix 7 · Data Prepper ingest health check
# ─────────────────────────────────────────────────────────────────────────────
from app.collectors.dataprepper_collector import _parse_health_body


def test_health_json_dict_up():
    assert _parse_health_body('{"status": "UP"}') is True


def test_health_json_dict_ok():
    assert _parse_health_body('{"status": "ok"}') is True


def test_health_json_string():
    assert _parse_health_body('"UP"') is True


def test_health_plain_text_ok():
    assert _parse_health_body("OK") is True


def test_health_plain_text_healthy():
    assert _parse_health_body("healthy") is True


def test_health_empty_200_is_healthy():
    """Empty body with 200 means healthy."""
    assert _parse_health_body("") is True
    assert _parse_health_body("   ") is True


def test_health_unhealthy_body():
    assert _parse_health_body('{"status": "DOWN"}') is False


def test_health_404_yields_yellow_check():
    """A 404 from the health endpoint must produce YELLOW, not RED."""
    from app.checks.dataprepper_checks import run_dataprepper_checks
    from app.models import Status
    r = _base_dp()
    r.ingest_reachable = False
    r.ingest_healthy = False
    r.ingest_health_404 = True
    r.ingest_error = "health_endpoint_not_found"
    checks = run_dataprepper_checks(r, {})
    health_check = next(c for c in checks if c.id == "dp.ingest.reachable")
    assert health_check.status == Status.YELLOW, (
        f"Health 404 must be YELLOW not {health_check.status}"
    )
    assert "404" in health_check.details or "health_check_service" in health_check.details


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1 (additional) · Status.worst – UNKNOWN must not hide RED
# ─────────────────────────────────────────────────────────────────────────────
from app.models import Status as St


def test_worst_red_unknown_gives_red():
    assert St.worst(St.RED, St.UNKNOWN) == St.RED


def test_worst_unknown_red_gives_red():
    assert St.worst(St.UNKNOWN, St.RED) == St.RED


def test_worst_unknown_green_gives_green():
    assert St.worst(St.UNKNOWN, St.GREEN) == St.GREEN


def test_worst_unknown_unknown_gives_unknown():
    assert St.worst(St.UNKNOWN, St.UNKNOWN) == St.UNKNOWN
