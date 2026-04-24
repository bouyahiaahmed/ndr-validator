"""
Dashboards checks – layered evaluation of Dashboards probe results.
"""
from __future__ import annotations
from typing import List
from app.models import CheckResult, Component, Status
from app.collectors.dashboards_collector import DashboardsScrapeResult

C = Component.DASHBOARDS

def run_dashboards_checks(
    scrape: DashboardsScrapeResult,
    opensearch_up: bool = True,
) -> List[CheckResult]:
    checks: List[CheckResult] = []

    # 1. Reachable
    checks.append(CheckResult(
        id="dash.reachable", title="Dashboards reachable", component=C, severity="critical",
        status=Status.GREEN if scrape.reachable else Status.RED,
        details=scrape.error or "Reachable",
        remediation="Check Dashboards host/port and network connectivity.",
    ))
    if not scrape.reachable:
        return checks

    # 2. TLS
    checks.append(CheckResult(
        id="dash.tls", title="Dashboards TLS verification", component=C, severity="critical",
        status=Status.GREEN if scrape.tls_ok else Status.RED,
        details="TLS OK" if scrape.tls_ok else (scrape.error or "TLS failed"),
        remediation="Check DASHBOARDS_CA_CERT_PATH and Dashboards TLS config.",
    ))

    # 3. Response time
    rt = scrape.response_time_ms
    checks.append(CheckResult(
        id="dash.response_time", title="Dashboards response time", component=C,
        severity="warning", current_value=rt, threshold=3000,
        status=Status.GREEN if rt < 1000 else (Status.YELLOW if rt < 3000 else Status.RED),
        details=f"Response time: {rt:.0f}ms",
    ))

    # 4. Body looks like Dashboards
    checks.append(CheckResult(
        id="dash.body_sanity", title="Dashboards response body sanity", component=C,
        severity="warning",
        status=Status.GREEN if scrape.body_looks_like_dashboards else Status.YELLOW,
        details="Body resembles Dashboards UI" if scrape.body_looks_like_dashboards else "Unexpected response body",
        remediation="Verify DASHBOARDS_HOST and DASHBOARDS_BASE_PATH.",
    ))

    # 5. 5xx detection
    if scrape.has_5xx:
        checks.append(CheckResult(
            id="dash.5xx", title="Dashboards 5xx error", component=C, severity="critical",
            status=Status.RED, current_value=scrape.status_code,
            details=f"HTTP {scrape.status_code} from Dashboards",
            remediation="Check Dashboards logs and OpenSearch connectivity.",
        ))

    # 6. Redirect loop
    if scrape.redirect_loop:
        checks.append(CheckResult(
            id="dash.redirect_loop", title="Dashboards redirect loop detected", component=C,
            severity="warning", status=Status.YELLOW,
            details="Excessive redirects detected",
            remediation="Check Dashboards base path and reverse proxy config.",
        ))

    # 7. Static asset
    checks.append(CheckResult(
        id="dash.static_asset", title="Dashboards static asset fetch", component=C,
        severity="info",
        status=Status.GREEN if scrape.static_asset_ok else Status.YELLOW,
        details="Static asset fetched OK" if scrape.static_asset_ok else "Static asset not fetched",
    ))

    # 8. Optional status API
    if scrape.status_api_available:
        api_state = scrape.status_api_overall or "unknown"
        s = Status.GREEN if api_state in ("green", "ok", "available") else (
            Status.YELLOW if api_state in ("yellow", "degraded") else Status.RED)
        checks.append(CheckResult(
            id="dash.status_api", title="Dashboards /api/status", component=C,
            severity="info", status=s, current_value=api_state,
            details=f"Dashboards status API: {api_state}",
        ))

    # 9. Auth check
    checks.append(CheckResult(
        id="dash.auth", title="Dashboards authenticated access", component=C,
        severity="warning",
        status=Status.GREEN if scrape.auth_ok else Status.YELLOW,
        details="Auth OK" if scrape.auth_ok else "Auth check failed or not attempted",
        remediation="Verify DASHBOARDS_USERNAME/PASSWORD." if not scrape.auth_ok else "",
    ))

    # 10. OpenSearch dependency
    if not opensearch_up:
        checks.append(CheckResult(
            id="dash.os_dependency", title="Dashboards/OpenSearch dependency", component=C,
            severity="critical", status=Status.RED,
            details="Dashboards is up but OpenSearch is DOWN",
            remediation="Restore OpenSearch connectivity; Dashboards will be non-functional.",
        ))

    return checks
