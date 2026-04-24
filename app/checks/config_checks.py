"""
Config checks – validates that the running configuration is coherent and complete.
Detects misconfigured or missing required settings before they cause silent failures.
"""
from __future__ import annotations
import os
from typing import List
from app.config import settings
from app.models import CheckResult, Component, Status

C = Component.CORRELATION


def run_config_checks() -> List[CheckResult]:
    checks: List[CheckResult] = []

    # Sensor list non-empty
    if not settings.sensor_ips:
        checks.append(CheckResult(
            id="cfg.sensors.list_empty",
            title="SENSOR_LIST is empty",
            component=C, severity="critical", status=Status.RED,
            details="No sensors configured — SENSOR_LIST is empty",
            remediation="Set SENSOR_LIST=<ip1>,<ip2>,... in .env",
        ))
    else:
        checks.append(CheckResult(
            id="cfg.sensors.list",
            title="Sensor list configured",
            component=C, severity="info", status=Status.GREEN,
            current_value=len(settings.sensor_ips),
            details=f"{len(settings.sensor_ips)} sensor(s) configured",
        ))

    # Expected sensor count
    if settings.EXPECTED_SENSOR_COUNT > 0 and len(settings.sensor_ips) < settings.EXPECTED_SENSOR_COUNT:
        checks.append(CheckResult(
            id="cfg.sensors.count_mismatch",
            title="Fewer sensors than expected",
            component=C, severity="warning", status=Status.YELLOW,
            current_value=len(settings.sensor_ips),
            threshold=settings.EXPECTED_SENSOR_COUNT,
            details=f"Configured {len(settings.sensor_ips)} sensors but EXPECTED_SENSOR_COUNT={settings.EXPECTED_SENSOR_COUNT}",
            remediation="Check SENSOR_LIST and EXPECTED_SENSOR_COUNT in .env",
        ))

    # CA cert exists
    ca_ok = os.path.isfile(settings.CA_CERT_PATH)
    checks.append(CheckResult(
        id="cfg.certs.ca_exists",
        title="CA certificate file exists",
        component=C, severity="critical",
        status=Status.GREEN if ca_ok else Status.RED,
        current_value=settings.CA_CERT_PATH,
        details=f"CA cert at {settings.CA_CERT_PATH}: {'found' if ca_ok else 'NOT FOUND'}",
        remediation=f"Mount your CA cert at {settings.CA_CERT_PATH}. See README cert mounting instructions." if not ca_ok else "",
    ))

    # SSH key exists when SSH enabled
    if settings.ENABLE_SENSOR_SSH:
        key_ok = os.path.isfile(settings.SENSOR_SSH_KEY_PATH)
        checks.append(CheckResult(
            id="cfg.ssh.key_exists",
            title="SSH key file exists",
            component=C, severity="critical",
            status=Status.GREEN if key_ok else Status.RED,
            current_value=settings.SENSOR_SSH_KEY_PATH,
            details=f"SSH key at {settings.SENSOR_SSH_KEY_PATH}: {'found' if key_ok else 'NOT FOUND'}",
            remediation=f"Mount SSH key at {settings.SENSOR_SSH_KEY_PATH}. See README SSH setup." if not key_ok else "",
        ))

    # Debug TLS flag
    if settings.ENABLE_DEBUG_INSECURE_SKIP_VERIFY:
        checks.append(CheckResult(
            id="cfg.security.tls_skip_verify",
            title="DANGER: TLS skip verify enabled",
            component=C, severity="critical", status=Status.RED,
            details="ENABLE_DEBUG_INSECURE_SKIP_VERIFY=true is active — never use in production",
            remediation="Set ENABLE_DEBUG_INSECURE_SKIP_VERIFY=false in .env",
        ))

    # Required log types non-empty
    if not settings.required_log_types_list:
        checks.append(CheckResult(
            id="cfg.policy.required_log_types_empty",
            title="REQUIRED_LOG_TYPES is empty",
            component=C, severity="warning", status=Status.YELLOW,
            details="No required log types configured — data quality checks will be skipped",
            remediation="Set REQUIRED_LOG_TYPES=conn,dns,http,ssl,files in .env",
        ))

    return checks
