"""
Tests for Vector alias mapping and metric version detection.
"""
import pytest
from app.utils.prometheus_parser import parse_prometheus_text
from app.collectors.vector_collector import (
    _detect_metric_version, _extract_components,
    VectorScrapeResult, VECTOR_METRIC_ALIASES,
)

CURRENT_PAYLOAD = """
component_received_events_total{component_id="src_zeek",component_kind="source"} 10000.0
component_sent_events_total{component_id="dp_sink",component_kind="sink"} 9800.0
component_errors_total{component_id="dp_sink",component_kind="sink"} 0.0
component_received_bytes_total{component_id="src_zeek"} 5000000.0
component_sent_bytes_total{component_id="dp_sink"} 4900000.0
"""

LEGACY_PAYLOAD = """
events_in_total 8000.0
events_out_total 7900.0
processing_errors_total 1.0
"""


def test_detect_current_version():
    families = parse_prometheus_text(CURRENT_PAYLOAD)
    assert _detect_metric_version(families) == "current"


def test_detect_legacy_version():
    families = parse_prometheus_text(LEGACY_PAYLOAD)
    assert _detect_metric_version(families) == "legacy"


def test_alias_map_has_all_legacy_keys():
    assert "events_in_total" in VECTOR_METRIC_ALIASES
    assert "events_out_total" in VECTOR_METRIC_ALIASES
    assert "processing_errors_total" in VECTOR_METRIC_ALIASES


def test_extract_components_current():
    families = parse_prometheus_text(CURRENT_PAYLOAD)
    comps = _extract_components(families)
    assert "src_zeek" in comps or "dp_sink" in comps


def test_scrape_result_reachable_false_on_error():
    r = VectorScrapeResult("10.0.0.11")
    r.error = "connection_refused"
    assert r.reachable is False
    assert r.error == "connection_refused"


def test_legacy_metrics_sum_correctly():
    from app.utils.prometheus_parser import sum_metric_values
    families = parse_prometheus_text(LEGACY_PAYLOAD)
    recv = sum_metric_values(families, "component_received_events_total",
                              aliases=["events_in_total"])
    sent = sum_metric_values(families, "component_sent_events_total",
                              aliases=["events_out_total"])
    assert recv == 8000.0
    assert sent == 7900.0


def test_current_metrics_sum_correctly():
    from app.utils.prometheus_parser import sum_metric_values
    families = parse_prometheus_text(CURRENT_PAYLOAD)
    recv = sum_metric_values(families, "component_received_events_total")
    sent = sum_metric_values(families, "component_sent_events_total")
    assert recv == 10000.0
    assert sent == 9800.0
