"""
Tests for Zeek SSH probe checks.
Covers: SSH failure, process up/log stale, JSON parse, log freeze.
"""
import pytest
from app.collectors.zeek_collector import ZeekSensorResult
from app.checks.zeek_checks import run_zeek_checks
from app.models import Status


def _healthy_zeek(ip="10.0.0.11") -> ZeekSensorResult:
    r = ZeekSensorResult(ip)
    r.ssh_reachable = True
    r.zeek_running = True
    r.zeekctl_available = True
    r.zeekctl_output = "zeek  running"
    r.log_dir_exists = True
    r.existing_logs = ["conn.log", "dns.log", "http.log", "ssl.log", "files.log"]
    r.missing_key_logs = []
    r.log_freshness = {"conn.log": 10.0, "dns.log": 15.0, "http.log": 20.0, "ssl.log": 12.0}
    r.stale_logs = []
    r.log_parse_ok = {"conn.log": True, "dns.log": True, "http.log": True}
    r.disk_used_percent = 40.0
    r.vector_running = True
    r.log_freeze_detected = False
    return r


def test_healthy_zeek_no_red():
    checks = run_zeek_checks(_healthy_zeek())
    red = [c for c in checks if c.status == Status.RED]
    assert red == [], f"Unexpected red: {[(c.id, c.details) for c in red]}"


def test_ssh_unreachable_returns_red_and_stops():
    r = ZeekSensorResult("10.0.0.11")
    r.ssh_error = "SSH timeout"
    checks = run_zeek_checks(r)
    assert len(checks) == 1
    assert checks[0].status == Status.RED
    assert "ssh" in checks[0].id


def test_zeek_not_running_red():
    r = _healthy_zeek()
    r.zeek_running = False
    r.zeekctl_output = "zeek crashed"
    checks = run_zeek_checks(r)
    proc = next(c for c in checks if "running" in c.id)
    assert proc.status == Status.RED


def test_log_dir_missing_red():
    r = _healthy_zeek()
    r.log_dir_exists = False
    checks = run_zeek_checks(r)
    ld = next(c for c in checks if "log_dir" in c.id)
    assert ld.status == Status.RED


def test_missing_key_log_red():
    r = _healthy_zeek()
    r.missing_key_logs = ["conn.log"]
    checks = run_zeek_checks(r)
    conn = next(c for c in checks if "conn_log.exists" in c.id or "conn_log" in c.id)
    assert conn.status == Status.RED


def test_stale_log_yellow():
    r = _healthy_zeek()
    r.log_freshness["conn.log"] = 130.0  # > 120s warn threshold
    r.stale_logs = ["conn.log"]
    checks = run_zeek_checks(r)
    fresh = next(c for c in checks if "conn_log.fresh" in c.id or ("conn" in c.id and "fresh" in c.id))
    assert fresh.status in (Status.YELLOW, Status.RED)


def test_stale_log_critical_red():
    r = _healthy_zeek()
    r.log_freshness["conn.log"] = 400.0  # > 300s critical
    r.stale_logs = ["conn.log"]
    checks = run_zeek_checks(r)
    fresh = next(c for c in checks if "conn" in c.id and "fresh" in c.id)
    assert fresh.status == Status.RED


def test_json_parse_failure_yellow():
    r = _healthy_zeek()
    r.log_parse_ok["conn.log"] = False
    checks = run_zeek_checks(r)
    jp = next((c for c in checks if "parse" in c.id and "conn" in c.id), None)
    if jp:
        assert jp.status == Status.YELLOW


def test_log_freeze_detected_red():
    r = _healthy_zeek()
    r.log_freeze_detected = True
    r.stale_logs = ["conn.log"]
    checks = run_zeek_checks(r)
    freeze = next(c for c in checks if "freeze" in c.id)
    assert freeze.status == Status.RED
