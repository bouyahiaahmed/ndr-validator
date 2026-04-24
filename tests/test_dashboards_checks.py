"""
Tests for Dashboards checks.
Covers: reachable, TLS, 5xx, redirect loop, OpenSearch dependency.
"""
import pytest
from app.collectors.dashboards_collector import DashboardsScrapeResult
from app.checks.dashboards_checks import run_dashboards_checks
from app.models import Status


def _healthy_dash() -> DashboardsScrapeResult:
    r = DashboardsScrapeResult()
    r.reachable = True
    r.tls_ok = True
    r.status_code = 200
    r.body_looks_like_dashboards = True
    r.redirect_loop = False
    r.has_5xx = False
    r.static_asset_ok = True
    r.status_api_available = True
    r.status_api_overall = "green"
    r.auth_ok = True
    r.response_time_ms = 120.0
    r.error = None
    return r


def test_healthy_dash_all_green():
    checks = run_dashboards_checks(_healthy_dash(), opensearch_up=True)
    red = [c for c in checks if c.status == Status.RED]
    assert red == []


def test_unreachable_returns_red():
    r = DashboardsScrapeResult()
    r.error = "endpoint_unreachable"
    checks = run_dashboards_checks(r, opensearch_up=True)
    reach = next(c for c in checks if c.id == "dash.reachable")
    assert reach.status == Status.RED


def test_tls_failure_red():
    r = DashboardsScrapeResult()
    r.reachable = True
    r.tls_ok = False
    r.error = "certificate_trust_failure"
    checks = run_dashboards_checks(r, opensearch_up=True)
    tls = next(c for c in checks if c.id == "dash.tls")
    assert tls.status == Status.RED


def test_5xx_detected_red():
    r = _healthy_dash()
    r.has_5xx = True
    r.status_code = 503
    checks = run_dashboards_checks(r, opensearch_up=True)
    err = next(c for c in checks if c.id == "dash.5xx")
    assert err.status == Status.RED


def test_os_dependency_failure_adds_red():
    r = _healthy_dash()
    checks = run_dashboards_checks(r, opensearch_up=False)
    dep = next((c for c in checks if c.id == "dash.os_dependency"), None)
    assert dep is not None
    assert dep.status == Status.RED


def test_redirect_loop_produces_yellow():
    r = _healthy_dash()
    r.redirect_loop = True
    checks = run_dashboards_checks(r, opensearch_up=True)
    rl = next((c for c in checks if c.id == "dash.redirect_loop"), None)
    assert rl is not None
    assert rl.status == Status.YELLOW


def test_slow_response_time_red():
    r = _healthy_dash()
    r.response_time_ms = 4000.0
    checks = run_dashboards_checks(r, opensearch_up=True)
    rt = next(c for c in checks if c.id == "dash.response_time")
    assert rt.status == Status.RED


def test_status_api_yellow_propagates():
    r = _healthy_dash()
    r.status_api_overall = "yellow"
    checks = run_dashboards_checks(r, opensearch_up=True)
    sa = next((c for c in checks if c.id == "dash.status_api"), None)
    if sa:
        assert sa.status == Status.YELLOW
