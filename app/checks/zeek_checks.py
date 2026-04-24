"""
Zeek direct checks – evaluate SSH probe results into CheckResults.
"""
from __future__ import annotations
from typing import List
from app.config import settings
from app.models import CheckResult, Component, Status
from app.collectors.zeek_collector import ZeekSensorResult

C = Component.ZEEK

def run_zeek_checks(scrape: ZeekSensorResult) -> List[CheckResult]:
    checks: List[CheckResult] = []
    sensor = scrape.sensor_ip
    name = settings.sensor_display_name(sensor)

    # 1. SSH reachable
    checks.append(CheckResult(
        id=f"zeek.{sensor}.ssh", title=f"SSH reachable on {name}",
        component=C, severity="critical", sensor=sensor,
        status=Status.GREEN if scrape.ssh_reachable else Status.RED,
        details=scrape.ssh_error or "SSH OK",
        remediation="Check SENSOR_SSH_KEY_PATH, SENSOR_SSH_USER, and network connectivity.",
    ))
    if not scrape.ssh_reachable:
        return checks

    # 2. Zeek service running
    checks.append(CheckResult(
        id=f"zeek.{sensor}.running", title=f"Zeek running on {name}",
        component=C, severity="critical", sensor=sensor,
        status=Status.GREEN if scrape.zeek_running else Status.RED,
        details=(scrape.zeekctl_output or scrape.zeek_status_detail or "Zeek not running"),
        remediation="Start Zeek: 'zeekctl deploy' or 'systemctl start zeek'",
    ))

    # 3. zeekctl available (info only)
    if scrape.ssh_reachable:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.zeekctl", title=f"zeekctl available on {name}",
            component=C, severity="info", sensor=sensor,
            status=Status.GREEN if scrape.zeekctl_available else Status.YELLOW,
            details="zeekctl found" if scrape.zeekctl_available else "zeekctl not installed; using systemctl/pgrep fallback",
        ))

    # 4. Log directory exists
    checks.append(CheckResult(
        id=f"zeek.{sensor}.log_dir", title=f"Zeek log dir exists on {name}",
        component=C, severity="critical", sensor=sensor,
        status=Status.GREEN if scrape.log_dir_exists else Status.RED,
        current_value=settings.ZEEK_LOG_DIR,
        details=f"Log dir: {settings.ZEEK_LOG_DIR}",
        remediation=f"Verify ZEEK_LOG_DIR={settings.ZEEK_LOG_DIR} is correct and accessible.",
    ))
    if not scrape.log_dir_exists:
        return checks

    # 5. Key log files exist
    for lf in ["conn.log", "dns.log", "http.log", "ssl.log"]:
        missing = lf in scrape.missing_key_logs
        checks.append(CheckResult(
            id=f"zeek.{sensor}.log.{lf.replace('.', '_')}.exists",
            title=f"{lf} exists on {name}",
            component=C, severity="warning", sensor=sensor,
            status=Status.RED if missing else Status.GREEN,
            details=f"{lf} {'missing' if missing else 'present'}",
            remediation=f"Zeek may not be capturing {lf.split('.')[0]} traffic. Check Zeek policy." if missing else "",
        ))

    # 6. Log freshness
    for lf, age in scrape.log_freshness.items():
        stale = lf in scrape.stale_logs
        s = Status.RED if age > settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else (
            Status.YELLOW if stale else Status.GREEN)
        checks.append(CheckResult(
            id=f"zeek.{sensor}.log.{lf.replace('.', '_')}.fresh",
            title=f"{lf} freshness on {name}",
            component=C, severity="warning", sensor=sensor, status=s,
            current_value=age, threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
            details=f"{lf} last modified {age:.0f}s ago",
            remediation="Zeek may have stopped writing. Check zeekctl and interface capture." if stale else "",
        ))

    # 7. JSON parse check
    for lf, ok in scrape.log_parse_ok.items():
        checks.append(CheckResult(
            id=f"zeek.{sensor}.log.{lf.replace('.', '_')}.parse",
            title=f"{lf} JSON parse on {name}",
            component=C, severity="warning", sensor=sensor,
            status=Status.GREEN if ok else Status.YELLOW,
            details="Last log line is valid JSON" if ok else "Last log line failed JSON parse",
            remediation="Log may contain non-JSON (header line or format change)." if not ok else "",
        ))

    # 8. Disk usage
    if scrape.disk_used_percent is not None:
        free = 100.0 - scrape.disk_used_percent
        low_disk = free < settings.LOW_DISK_THRESHOLD_PERCENT
        checks.append(CheckResult(
            id=f"zeek.{sensor}.disk", title=f"Disk space on {name}",
            component=C, severity="warning", sensor=sensor,
            status=Status.YELLOW if low_disk else Status.GREEN,
            current_value=free, threshold=settings.LOW_DISK_THRESHOLD_PERCENT,
            details=f"Disk free: {free:.1f}%",
            remediation="Clear old Zeek logs or expand storage." if low_disk else "",
        ))

    # 9. Log freeze
    if scrape.log_freeze_detected:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.log_freeze", title=f"Log freeze detected on {name}",
            component=C, severity="critical", sensor=sensor, status=Status.RED,
            details=f"Zeek running but logs stale: {', '.join(scrape.stale_logs)}",
            remediation="Check Zeek process and interface. Run 'zeekctl status' and check capture interface.",
        ))

    # 10. Vector running on sensor
    if scrape.ssh_reachable:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.vector_running", title=f"Vector running on {name}",
            component=C, severity="warning", sensor=sensor,
            status=Status.GREEN if scrape.vector_running else Status.YELLOW,
            details="Vector process found" if scrape.vector_running else "Vector process not detected via SSH",
            remediation="Check Vector service status on sensor." if not scrape.vector_running else "",
        ))

    return checks
