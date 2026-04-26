"""
Zeek direct checks – evaluate SSH probe results into CheckResults.
Every non-green check carries a structured Diagnosis.
When ENABLE_SENSOR_SSH=false, all Zeek checks are UNKNOWN.
"""
from __future__ import annotations
from typing import List
from app.config import settings
from app.models import (
    CheckResult, Component, Diagnosis, Status,
    FIX_ANSIBLE_ZEEK, FIX_ANSIBLE_VECTOR, FIX_VALIDATOR,
)
from app.collectors.zeek_collector import ZeekSensorResult

C = Component.ZEEK


def run_zeek_checks(scrape: ZeekSensorResult) -> List[CheckResult]:
    checks: List[CheckResult] = []
    sensor = scrape.sensor_ip
    name = settings.sensor_display_name(sensor)

    # 1. SSH reachable
    if scrape.ssh_reachable:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.ssh", title=f"SSH reachable on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.GREEN, details="SSH OK",
        ))
    else:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.ssh", title=f"SSH reachable on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.RED,
            details=scrape.ssh_error or "SSH unreachable",
            remediation="Check SENSOR_SSH_KEY_PATH, SENSOR_SSH_USER, and network connectivity.",
            diagnosis=Diagnosis(
                problem=f"Validator cannot SSH to sensor '{name}'",
                evidence=f"SSH connect to {sensor}:{settings.SENSOR_SSH_PORT} failed: {scrape.ssh_error or 'timeout'}",
                impact="Cannot verify Zeek process status. All Zeek checks blocked.",
                probable_causes=[
                    "SSH key not mounted at SENSOR_SSH_KEY_PATH",
                    "Wrong SENSOR_SSH_USER or SENSOR_SSH_PORT",
                    "Sensor firewall blocking SSH from validator",
                    "Sensor not reachable from Docker container network",
                ],
                next_steps=[
                    f"Verify: ls -la {settings.SENSOR_SSH_KEY_PATH}",
                    f"Test: ssh -i {settings.SENSOR_SSH_KEY_PATH} -p {settings.SENSOR_SSH_PORT} {settings.SENSOR_SSH_USER}@{sensor}",
                    "Check docker-compose.yml volumes for SSH key mount",
                ],
                fix_location=FIX_VALIDATOR,
                confidence="high",
            ),
        ))
        return checks

    # 2. Zeek service running
    if scrape.zeek_running:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.running", title=f"Zeek running on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.GREEN,
            details=scrape.zeekctl_output or scrape.zeek_status_detail or "Zeek running",
        ))
    else:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.running", title=f"Zeek running on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.RED,
            details=scrape.zeekctl_output or scrape.zeek_status_detail or "Zeek not running",
            remediation="Start Zeek: 'zeekctl deploy' or 'systemctl start zeek'",
            diagnosis=Diagnosis(
                problem=f"Zeek process is not running on sensor '{name}'",
                evidence=f"zeekctl status / systemctl / pgrep: {scrape.zeek_status_detail or 'process not found'}",
                impact="BLOCKING: No network traffic capture on this sensor. Complete detection blind spot.",
                probable_causes=[
                    "Zeek process crashed or was stopped",
                    "Zeek failed to start (check zeekctl logs)",
                    "Interface not available for capture",
                    "zeekctl configuration error",
                ],
                next_steps=[
                    f"SSH to {name}: zeekctl status",
                    f"SSH to {name}: zeekctl deploy",
                    f"SSH to {name}: journalctl -u zeek -n 50",
                    f"SSH to {name}: zeekctl check (configuration check)",
                ],
                fix_location=FIX_ANSIBLE_ZEEK,
                confidence="high",
            ),
        ))

    # 3. zeekctl available (info only)
    if scrape.ssh_reachable:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.zeekctl", title=f"zeekctl available on {name}",
            component=C, severity="info", sensor=sensor,
            status=Status.GREEN if scrape.zeekctl_available else Status.YELLOW,
            details="zeekctl found" if scrape.zeekctl_available else "zeekctl not installed; using systemctl/pgrep fallback",
            diagnosis=Diagnosis(
                problem=f"zeekctl not found on sensor '{name}'",
                evidence="zeekctl command not found in PATH",
                impact="Zeek status checks use less reliable fallback methods.",
                probable_causes=["Zeek installed without zeekctl", "PATH not configured for zeekctl"],
                next_steps=["Install Zeek with full zeekctl: apt install zeek or equivalent"],
                fix_location=FIX_ANSIBLE_ZEEK,
                confidence="low",
            ) if not scrape.zeekctl_available else None,
        ))

    # 4. Log directory exists
    if scrape.log_dir_exists:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.log_dir", title=f"Zeek log dir exists on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.GREEN, current_value=settings.ZEEK_LOG_DIR,
            details=f"Log dir: {settings.ZEEK_LOG_DIR}",
        ))
    else:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.log_dir", title=f"Zeek log dir exists on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.RED,
            current_value=settings.ZEEK_LOG_DIR,
            details=f"Log dir missing: {settings.ZEEK_LOG_DIR}",
            remediation=f"Verify ZEEK_LOG_DIR={settings.ZEEK_LOG_DIR} is correct and accessible.",
            diagnosis=Diagnosis(
                problem=f"Zeek log directory '{settings.ZEEK_LOG_DIR}' does not exist on '{name}'",
                evidence=f"ls {settings.ZEEK_LOG_DIR} returned error",
                impact="Vector cannot read Zeek logs. No data will flow from this sensor.",
                probable_causes=[
                    f"ZEEK_LOG_DIR={settings.ZEEK_LOG_DIR} set to wrong path",
                    "Zeek writing to different directory",
                    "Zeek not yet started (dir created on first run)",
                ],
                next_steps=[
                    f"SSH to {name}: find /opt/zeek /usr/local/zeek -name 'conn.log' 2>/dev/null",
                    f"Update ZEEK_LOG_DIR in .env to match actual Zeek log path",
                ],
                fix_location=FIX_VALIDATOR,
                confidence="high",
            ),
        ))
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
            diagnosis=Diagnosis(
                problem=f"Zeek log file '{lf}' not found on sensor '{name}'",
                evidence=f"ls {settings.ZEEK_LOG_DIR}/{lf} returned not found",
                impact=f"No {lf.split('.')[0]} data from this sensor. Detection gap for this protocol.",
                probable_causes=[
                    f"Zeek policy not enabling {lf.split('.')[0]} logging (check local.zeek)",
                    "No traffic of this type on monitored interface",
                    "Zeek using compressed or rotated log paths",
                ],
                next_steps=[
                    f"SSH to {name}: cat /opt/zeek/share/zeek/site/local.zeek | grep {lf.split('.')[0]}",
                    f"Generate test traffic (e.g. curl http://... for http.log)",
                ],
                fix_location=FIX_ANSIBLE_ZEEK,
                confidence="low",
            ) if missing else None,
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
            diagnosis=Diagnosis(
                problem=f"Zeek log file '{lf}' is stale on sensor '{name}'",
                evidence=f"{lf} last modified {age:.0f}s ago (threshold: {settings.STALE_DATA_THRESHOLD_SECONDS}s)",
                impact="Zeek may not be capturing traffic. Vector will send stale data.",
                probable_causes=[
                    "No traffic of this type on the monitored interface",
                    "Zeek capture interface went down",
                    "Zeek process in error state",
                ],
                next_steps=[
                    f"SSH to {name}: zeekctl status",
                    f"SSH to {name}: tcpdump -i eth0 -c 10 (test interface capture)",
                ],
                fix_location=FIX_ANSIBLE_ZEEK,
                confidence="medium",
            ) if stale else None,
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
            diagnosis=Diagnosis(
                problem=f"Low disk space on sensor '{name}' ({free:.1f}% free)",
                evidence=f"Disk free = {free:.1f}% (threshold: {settings.LOW_DISK_THRESHOLD_PERCENT}%)",
                impact="Risk of Zeek stopping log writes when disk fills up.",
                probable_causes=[
                    "Old Zeek log archives not cleaned up",
                    "Log rotation not configured",
                ],
                next_steps=[
                    f"SSH to {name}: df -h",
                    f"SSH to {name}: du -sh {settings.ZEEK_LOG_DIR}/../*",
                    "Configure log rotation or increase disk size",
                ],
                fix_location=FIX_ANSIBLE_ZEEK,
                confidence="high",
            ) if low_disk else None,
        ))

    # 9. Log freeze
    if scrape.log_freeze_detected:
        checks.append(CheckResult(
            id=f"zeek.{sensor}.log_freeze", title=f"Log freeze detected on {name}",
            component=C, severity="critical", sensor=sensor, status=Status.RED,
            details=f"Zeek running but logs stale: {', '.join(scrape.stale_logs)}",
            remediation="Check Zeek process and interface. Run 'zeekctl status' and check capture interface.",
            diagnosis=Diagnosis(
                problem=f"Zeek is running on '{name}' but not writing fresh logs",
                evidence=f"Stale logs: {', '.join(scrape.stale_logs)} — Zeek process: running",
                impact="CRITICAL: Zeek is alive but not capturing traffic. Complete detection blind spot.",
                probable_causes=[
                    "Capture interface went down (cable unplugged, VLAN change)",
                    "Interface renamed after kernel update",
                    "Zeek capture permissions revoked",
                    "zeekctl crashed inner worker processes",
                ],
                next_steps=[
                    f"SSH to {name}: zeekctl status (check worker status)",
                    f"SSH to {name}: ip link show (check interface up status)",
                    f"SSH to {name}: zeekctl stop && zeekctl start",
                    f"SSH to {name}: tcpdump -i INTERFACE -c 5 (test live capture)",
                ],
                fix_location=FIX_ANSIBLE_ZEEK,
                confidence="high",
            ),
        ))

    # 10. Vector running on sensor
    if scrape.ssh_reachable:
        if scrape.vector_running:
            checks.append(CheckResult(
                id=f"zeek.{sensor}.vector_running", title=f"Vector running on {name}",
                component=C, severity="warning", sensor=sensor,
                status=Status.GREEN, details="Vector process found",
            ))
        else:
            checks.append(CheckResult(
                id=f"zeek.{sensor}.vector_running", title=f"Vector running on {name}",
                component=C, severity="warning", sensor=sensor,
                status=Status.YELLOW, details="Vector process not detected via SSH",
                remediation="Check Vector service status on sensor.",
                diagnosis=Diagnosis(
                    problem=f"Vector process not found on sensor '{name}' via SSH",
                    evidence="pgrep/systemctl check: vector process not running",
                    impact="No log forwarding from this sensor to Data Prepper.",
                    probable_causes=[
                        "Vector service stopped or crashed",
                        "Vector installed under different process name",
                    ],
                    next_steps=[
                        f"SSH to {name}: systemctl status vector",
                        f"SSH to {name}: ps aux | grep vector",
                        f"SSH to {name}: journalctl -u vector -n 20",
                    ],
                    fix_location=FIX_ANSIBLE_VECTOR,
                    confidence="medium",
                ),
            ))

    return checks
