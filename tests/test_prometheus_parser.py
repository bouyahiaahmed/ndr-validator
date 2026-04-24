"""
Tests for Prometheus text format parser.
"""
import pytest
from app.utils.prometheus_parser import (
    parse_prometheus_text, find_metric_value, sum_metric_values,
    discover_pipeline_names, get_samples_by_label, extract_flat_metrics,
)

BASIC_PAYLOAD = """
# HELP component_received_events_total Total received events
# TYPE component_received_events_total counter
component_received_events_total{component_id="zeek_logs",component_kind="source",component_type="file"} 12345.0
component_received_events_total{component_id="dp_sink",component_kind="sink",component_type="http"} 0.0
# HELP component_sent_events_total Total sent events
# TYPE component_sent_events_total counter
component_sent_events_total{component_id="dp_sink",component_kind="sink",component_type="http"} 12000.0
# HELP component_errors_total Total errors
# TYPE component_errors_total counter
component_errors_total{component_id="dp_sink",component_kind="sink"} 5.0
"""

LEGACY_PAYLOAD = """
# HELP events_in_total Legacy events in
# TYPE events_in_total counter
events_in_total 9000.0
# HELP events_out_total Legacy events out
# TYPE events_out_total counter
events_out_total 8800.0
# HELP processing_errors_total Legacy errors
# TYPE processing_errors_total counter
processing_errors_total 2.0
"""

DP_PAYLOAD = """
# HELP zeek_ingestion_pipeline_recordsProcessed_total Records processed
# TYPE zeek_ingestion_pipeline_recordsProcessed_total counter
zeek_ingestion_pipeline_recordsProcessed_total 50000.0
# HELP zeek_ingestion_pipeline_opensearch_recordsIn_total Records in OS
# TYPE zeek_ingestion_pipeline_opensearch_recordsIn_total counter
zeek_ingestion_pipeline_opensearch_recordsIn_total 49800.0
# HELP zeek_ingestion_pipeline_opensearch_documentErrors_total Doc errors
# TYPE zeek_ingestion_pipeline_opensearch_documentErrors_total counter
zeek_ingestion_pipeline_opensearch_documentErrors_total 0.0
# HELP armeria_server_tls_handshakes_total TLS handshakes
# TYPE armeria_server_tls_handshakes_total counter
armeria_server_tls_handshakes_total{result="success"} 100.0
armeria_server_tls_handshakes_total{result="failure"} 0.0
"""


def test_parse_basic_current_metrics():
    families = parse_prometheus_text(BASIC_PAYLOAD)
    assert "component_received_events_total" in families or any(
        s.name == "component_received_events_total"
        for f in families.values() for s in f.samples
    )


def test_find_metric_value_with_label():
    families = parse_prometheus_text(BASIC_PAYLOAD)
    val = find_metric_value(families, "component_received_events_total",
                            label_filters={"component_id": "zeek_logs"})
    assert val == 12345.0


def test_sum_metric_values():
    families = parse_prometheus_text(BASIC_PAYLOAD)
    total = sum_metric_values(families, "component_received_events_total")
    assert total == 12345.0


def test_parse_legacy_metrics():
    families = parse_prometheus_text(LEGACY_PAYLOAD)
    val = find_metric_value(families, "events_in_total")
    assert val == 9000.0


def test_alias_mapping_in_extract_flat():
    families = parse_prometheus_text(LEGACY_PAYLOAD)
    alias_map = {
        "events_in_total": "component_received_events_total",
        "events_out_total": "component_sent_events_total",
    }
    flat = extract_flat_metrics(families, alias_map)
    assert "component_received_events_total" in flat
    assert flat["component_received_events_total"] == 9000.0


def test_discover_pipeline_names():
    families = parse_prometheus_text(DP_PAYLOAD)
    names = discover_pipeline_names(families)
    assert "zeek_ingestion_pipeline" in names


def test_tls_handshake_label_filter():
    families = parse_prometheus_text(DP_PAYLOAD)
    success = find_metric_value(families, "armeria_server_tls_handshakes_total",
                                 label_filters={"result": "success"})
    failure = find_metric_value(families, "armeria_server_tls_handshakes_total",
                                 label_filters={"result": "failure"})
    assert success == 100.0
    assert failure == 0.0


def test_malformed_lines_dont_crash():
    bad = "# HELP foo bar\nfoo{broken label 99.0\nfoo 1.0\n"
    families = parse_prometheus_text(bad)
    # Should not raise, may have partial results
    assert isinstance(families, dict)


def test_nan_and_inf_handled():
    payload = "foo NaN\nbar +Inf\nbaz -Inf\n"
    families = parse_prometheus_text(payload)
    import math
    flat = extract_flat_metrics(families)
    assert math.isnan(flat.get("foo", 0)) or "foo" in flat
