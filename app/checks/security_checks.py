"""
Security checks – TLS certificate validity, auth configuration sanity.
These are lightweight checks derived from existing scrape results.
"""
from __future__ import annotations
from typing import List
from app.config import settings
from app.models import CheckResult, Component, Status

C = Component.CORRELATION  # security checks contribute to correlation component


def run_security_checks(
    dp_tls_ok: bool,
    os_tls_ok: bool,
    dash_tls_ok: bool,
    dp_error: str = "",
    os_error: str = "",
    dash_error: str = "",
) -> List[CheckResult]:
    checks: List[CheckResult] = []

    # TLS verification enforcement check
    if settings.ENABLE_DEBUG_INSECURE_SKIP_VERIFY:
        checks.append(CheckResult(
            id="sec.tls.debug_skip_verify_enabled",
            title="TLS verification disabled (DEBUG mode)",
            component=C, severity="critical", status=Status.RED,
            details="ENABLE_DEBUG_INSECURE_SKIP_VERIFY=true — TLS verification is globally disabled.",
            remediation="Set ENABLE_DEBUG_INSECURE_SKIP_VERIFY=false immediately in production.",
        ))
    else:
        checks.append(CheckResult(
            id="sec.tls.enforcement",
            title="TLS verification enforcement",
            component=C, severity="info", status=Status.GREEN,
            details="TLS verification is enabled (ENABLE_DEBUG_INSECURE_SKIP_VERIFY=false)",
        ))

    # Per-component TLS checks
    for name, ok, err in [
        ("DataPrepper", dp_tls_ok, dp_error),
        ("OpenSearch", os_tls_ok, os_error),
        ("Dashboards", dash_tls_ok, dash_error),
    ]:
        s = Status.GREEN if ok else Status.RED
        detail = "TLS OK" if ok else f"TLS failed: {err or 'unknown'}"
        hint = f"Check CA_CERT_PATH and {name} certificate." if not ok else ""
        checks.append(CheckResult(
            id=f"sec.tls.{name.lower()}",
            title=f"{name} TLS verification",
            component=C, severity="critical", status=s,
            details=detail, remediation=hint,
        ))

    return checks
