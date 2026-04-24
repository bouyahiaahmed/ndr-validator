"""
Tests for OpenSearch checks.
Covers: cluster yellow, stale freshness, missing fields, missing sensors.
"""
import pytest
from datetime import datetime, timezone, timedelta
from app.collectors.opensearch_collector import OpenSearchScrapeResult
from app.checks.opensearch_checks import run_opensearch_checks
from app.models import Status


def _healthy_os() -> OpenSearchScrapeResult:
    r = OpenSearchScrapeResult()
    r.reachable = True
    r.tls_ok = True
    r.auth_ok = True
    r.cluster = {
        "status": "green",
        "number_of_nodes": 3,
        "active_shards_percent_as_number": 100.0,
        "unassigned_shards": 0,
    }
    r.nodes = [{"name": "node1", "heap.percent": "45"}]
    r.indices = [
        {"index": "zeek-2024.01.01", "health": "green", "docs.count": "50000", "store.size": "1gb"},
    ]
    r.total_count = 50000
    r.search_latency_ms = 120.0
    r.recent_count = 500
    now = datetime.now(timezone.utc)
    r.overall_latest_ts = now.isoformat()
    r.sensors_present = ["10.0.0.11", "10.0.0.12"]
    r.log_types_present = ["conn", "dns", "http", "ssl", "files"]
    r.sensor_freshness = {
        "10.0.0.11": now.isoformat(),
        "10.0.0.12": now.isoformat(),
    }
    r.log_type_freshness = {
        "conn": now.isoformat(),
        "dns": now.isoformat(),
    }
    r.field_caps_data = {
        "fields": {
            "@timestamp": {"date": {}},
            "source.ip": {"ip": {}},
            "destination.ip": {"ip": {}},
            "network.protocol": {"keyword": {}},
        }
    }
    return r


def test_healthy_os_all_green():
    r = _healthy_os()
    checks = run_opensearch_checks(r, {"total_count": 49000})
    red = [c for c in checks if c.status == Status.RED]
    assert red == [], f"Unexpected red: {[(c.id, c.details) for c in red]}"


def test_cluster_yellow_produces_yellow():
    r = _healthy_os()
    r.cluster["status"] = "yellow"
    checks = run_opensearch_checks(r, {})
    ch = next(c for c in checks if c.id == "os.cluster.health")
    assert ch.status == Status.YELLOW


def test_cluster_red_produces_red():
    r = _healthy_os()
    r.cluster["status"] = "red"
    checks = run_opensearch_checks(r, {})
    ch = next(c for c in checks if c.id == "os.cluster.health")
    assert ch.status == Status.RED


def test_stale_freshness_produces_red():
    r = _healthy_os()
    stale_ts = (datetime.now(timezone.utc) - timedelta(seconds=400)).isoformat()
    r.overall_latest_ts = stale_ts
    checks = run_opensearch_checks(r, {})
    fr = next(c for c in checks if c.id == "os.freshness.overall")
    assert fr.status == Status.RED


def test_stale_freshness_warn_threshold():
    r = _healthy_os()
    stale_ts = (datetime.now(timezone.utc) - timedelta(seconds=150)).isoformat()
    r.overall_latest_ts = stale_ts
    checks = run_opensearch_checks(r, {})
    fr = next(c for c in checks if c.id == "os.freshness.overall")
    assert fr.status == Status.YELLOW


def test_no_indices_produces_red():
    r = _healthy_os()
    r.indices = []
    checks = run_opensearch_checks(r, {})
    idx = next(c for c in checks if c.id == "os.indices.exist")
    assert idx.status == Status.RED


def test_missing_sensor_produces_red(monkeypatch):
    r = _healthy_os()
    r.sensors_present = ["10.0.0.11"]
    # Only sensor1 present, sensor2 missing
    import app.config as cfg
    original = cfg.settings.sensor_ips
    monkeypatch.setattr(cfg.settings, "SENSOR_LIST", "10.0.0.11,10.0.0.12")
    checks = run_opensearch_checks(r, {})
    missing = [c for c in checks if "sensor" in c.id and c.status == Status.RED]
    assert len(missing) >= 1


def test_high_search_latency_red():
    r = _healthy_os()
    r.search_latency_ms = 2500.0
    checks = run_opensearch_checks(r, {})
    sl = next(c for c in checks if c.id == "os.search.latency")
    assert sl.status == Status.RED


def test_unreachable_returns_early():
    r = OpenSearchScrapeResult()
    r.reachable = False
    r.error = "connection_refused"
    checks = run_opensearch_checks(r, {})
    assert len(checks) == 1
    assert checks[0].status == Status.RED
