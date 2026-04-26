"""
Vector checks – evaluate Vector scrape results into CheckResults.
Every non-green check carries a structured Diagnosis.
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Dict, List, Optional
from app.config import settings
from app.models import (
    CheckResult, Component, Diagnosis, Status,
    FIX_ANSIBLE_VECTOR,
)

if TYPE_CHECKING:
    from app.collectors.vector_collector import VectorScrapeResult

C = Component.VECTOR


def run_vector_checks(
    scrape: "VectorScrapeResult",
    prev_metrics: Optional[Dict[str, float]] = None,
    peer_sent: Optional[Dict[str, float]] = None,
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    sensor = scrape.sensor_ip
    name = settings.sensor_display_name(sensor)

    # 1. Endpoint reachable
    if scrape.reachable:
        checks.append(CheckResult(
            id=f"vector.{sensor}.reachable",
            title=f"Vector reachable on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.GREEN,
            details="Endpoint responding",
        ))
    else:
        checks.append(CheckResult(
            id=f"vector.{sensor}.reachable",
            title=f"Vector reachable on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.RED,
            details=scrape.error or "Endpoint unreachable",
            remediation="Check Vector is running and prometheus_exporter sink is configured on the sensor.",
            diagnosis=Diagnosis(
                problem=f"Vector metrics endpoint is unreachable on sensor '{name}'",
                evidence=f"HTTP GET {settings.vector_metrics_url(sensor)} failed: {scrape.error or 'no response'}",
                impact="Cannot monitor Vector pipeline on this sensor. Drop-rate and throughput checks will be UNKNOWN.",
                probable_causes=[
                    "Vector service is not running on the sensor",
                    f"prometheus_exporter sink not configured (expected port {settings.VECTOR_METRICS_PORT})",
                    "Firewall blocking port from validator container",
                    "Wrong SENSOR_LIST IP address",
                ],
                next_steps=[
                    f"SSH to {name}: systemctl status vector",
                    f"SSH to {name}: ss -tlnp | grep {settings.VECTOR_METRICS_PORT}",
                    "Check vector.toml for prometheus_exporter sink configuration",
                    f"Verify validator can reach {sensor}:{settings.VECTOR_METRICS_PORT}",
                ],
                fix_location=FIX_ANSIBLE_VECTOR,
                confidence="high",
            ),
        ))
        return checks

    # 2. Scrape parseable
    parse_ok = bool(scrape.families) and scrape.error is None
    if not parse_ok:
        checks.append(CheckResult(
            id=f"vector.{sensor}.parse",
            title=f"Vector metrics parseable on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.RED,
            details=scrape.error or "Parse failed",
            remediation="Verify Vector internal_metrics source and prometheus_exporter sink.",
            diagnosis=Diagnosis(
                problem=f"Vector Prometheus metrics payload could not be parsed on '{name}'",
                evidence=f"Parse error: {scrape.error or 'unknown'}",
                impact="All Vector-side checks will be unreliable or UNKNOWN.",
                probable_causes=[
                    "Vector internal_metrics source not configured",
                    "prometheus_exporter sink type mismatch (using prometheus_remote_write instead)",
                    "Vector version incompatibility with metric names",
                ],
                next_steps=[
                    f"curl http://{sensor}:{settings.VECTOR_METRICS_PORT}{settings.VECTOR_METRICS_PATH}",
                    "Verify vector.toml has [sources.internal_metrics] and [sinks.prom_exporter] of type prometheus_exporter",
                ],
                fix_location=FIX_ANSIBLE_VECTOR,
                confidence="high",
            ),
        ))
    else:
        checks.append(CheckResult(
            id=f"vector.{sensor}.parse",
            title=f"Vector metrics parseable on {name}",
            component=C, severity="critical", sensor=sensor,
            status=Status.GREEN,
            details="Prometheus payload parsed",
        ))

    # 3. Metric version detected
    checks.append(CheckResult(
        id=f"vector.{sensor}.metric_version",
        title=f"Vector metric version on {name}",
        component=C, severity="info", sensor=sensor,
        status=Status.GREEN if scrape.metric_version != "unknown" else Status.YELLOW,
        current_value=scrape.metric_version,
        details=f"Detected metric version: {scrape.metric_version}",
        diagnosis=Diagnosis(
            problem="Vector metric version could not be detected",
            evidence="No version label found in Prometheus metrics",
            impact="Minor – alias mapping may use fallback paths.",
            probable_causes=["Vector version is very old or very new"],
            next_steps=["Check Vector version: vector --version"],
            fix_location=FIX_ANSIBLE_VECTOR,
            confidence="low",
        ) if scrape.metric_version == "unknown" else None,
    ))

    # 4. Received events increasing
    prev = prev_metrics or {}
    prev_recv = prev.get("received_events", 0)
    recv_delta = scrape.received_events - prev_recv if prev_recv else None
    if recv_delta is not None:
        if recv_delta > 0:
            s = Status.GREEN
            diag = None
        elif recv_delta == 0:
            s = Status.YELLOW
            diag = Diagnosis(
                problem=f"Vector on '{name}' received zero new events since last scrape",
                evidence=f"received_events delta = 0 (cumulative: {scrape.received_events:.0f})",
                impact="If Zeek is generating logs, Vector may not be reading them. Silent data gap.",
                probable_causes=[
                    "No new Zeek log lines written (quiet traffic period)",
                    "Vector file source path does not match ZEEK_LOG_DIR",
                    f"Zeek log rotation moved files away from {settings.ZEEK_LOG_DIR}",
                ],
                next_steps=[
                    f"SSH to {name}: tail -f {settings.ZEEK_LOG_DIR}/conn.log",
                    "Check vector.toml file source paths match actual Zeek log locations",
                ],
                fix_location=FIX_ANSIBLE_VECTOR,
                confidence="low",
            )
        else:
            s = Status.RED
            diag = None

        checks.append(CheckResult(
            id=f"vector.{sensor}.recv_increasing",
            title=f"Vector input events on {name}",
            component=C, severity="warning", sensor=sensor, status=s,
            current_value=recv_delta, details=f"Received events delta: {recv_delta:.0f}",
            remediation="Check Zeek log source or file permissions on sensor." if s != Status.GREEN else "",
            diagnosis=diag,
        ))

    # 5. Sent events increasing
    prev_sent = prev.get("sent_events", 0)
    sent_delta = scrape.sent_events - prev_sent if prev_sent else None
    if sent_delta is not None:
        if sent_delta > 0:
            s = Status.GREEN
            diag = None
        elif sent_delta == 0:
            s = Status.YELLOW
            diag = Diagnosis(
                problem=f"Vector on '{name}' sent zero events to Data Prepper since last scrape",
                evidence=f"sent_events delta = 0",
                impact="Data Prepper receiving nothing from this sensor. Detection coverage gap.",
                probable_causes=[
                    "No input events (see recv_increasing check)",
                    "Vector sink errors preventing delivery",
                    "Data Prepper endpoint unreachable from sensor",
                ],
                next_steps=[
                    f"SSH to {name}: journalctl -u vector -n 50 | grep error",
                    "Check dp.metrics.reachable check status",
                ],
                fix_location=FIX_ANSIBLE_VECTOR,
                confidence="medium",
            )
        else:
            s = Status.RED
            diag = None

        checks.append(CheckResult(
            id=f"vector.{sensor}.sent_increasing",
            title=f"Vector output events on {name}",
            component=C, severity="warning", sensor=sensor, status=s,
            current_value=sent_delta, details=f"Sent events delta: {sent_delta:.0f}",
            remediation="Check Vector sink config and Data Prepper connectivity.",
            diagnosis=diag,
        ))

    # 6. Errors
    prev_err = prev.get("errors_total", 0)
    err_delta = scrape.errors_total - prev_err if prev_err else 0
    if err_delta > 0:
        checks.append(CheckResult(
            id=f"vector.{sensor}.errors",
            title=f"Vector errors on {name}",
            component=C, severity="warning", sensor=sensor, status=Status.YELLOW,
            current_value=err_delta, details=f"Error count delta: {err_delta:.0f}",
            remediation="Check Vector logs for error details.",
            diagnosis=Diagnosis(
                problem=f"Vector on '{name}' logged {err_delta:.0f} new errors",
                evidence=f"vector component error counter delta = {err_delta:.0f}",
                impact="Errors may indicate failed deliveries or parsing failures.",
                probable_causes=[
                    "Data Prepper endpoint TLS/auth errors",
                    "Malformed Zeek log lines causing parse errors",
                    "Network transient errors to Data Prepper",
                ],
                next_steps=[
                    f"SSH to {name}: journalctl -u vector -n 100 | grep -i error",
                    "Check corr.tls.mismatch check status",
                ],
                fix_location=FIX_ANSIBLE_VECTOR,
                confidence="medium",
            ),
        ))
    else:
        checks.append(CheckResult(
            id=f"vector.{sensor}.errors",
            title=f"Vector errors on {name}",
            component=C, severity="warning", sensor=sensor, status=Status.GREEN,
            current_value=0, details="No new errors",
        ))

    # 7. Input moves but output does not
    if recv_delta is not None and sent_delta is not None:
        if recv_delta > 0 and sent_delta == 0:
            checks.append(CheckResult(
                id=f"vector.{sensor}.input_no_output",
                title=f"Vector input without output on {name}",
                component=C, severity="critical", sensor=sensor, status=Status.RED,
                details=f"Received {recv_delta:.0f} events but sent 0",
                remediation="Check Vector sink configuration, Data Prepper endpoint, and TLS settings.",
                diagnosis=Diagnosis(
                    problem=f"Vector on '{name}' is receiving logs but NOT forwarding them",
                    evidence=f"recv_delta={recv_delta:.0f}, sent_delta=0",
                    impact="All logs from this sensor are being silently dropped. Complete NDR blind spot.",
                    probable_causes=[
                        "Data Prepper endpoint unreachable (wrong host/port/TLS)",
                        "Vector HTTP sink authentication failure",
                        "Upstream transform discarding everything (check filter logic)",
                        "Vector sink buffer full and blocking",
                    ],
                    next_steps=[
                        f"SSH to {name}: journalctl -u vector --since '5 min ago'",
                        "Check Data Prepper TLS and auth settings match Vector sink config",
                        "Check corr.tls.mismatch check for TLS handshake failures",
                        f"Test connectivity: curl -k https://DATAPREPPER_HOST:2021/health from {name}",
                    ],
                    fix_location=FIX_ANSIBLE_VECTOR,
                    confidence="high",
                ),
            ))

    # 8. Counter reset detection
    if prev_recv and scrape.received_events < prev_recv:
        checks.append(CheckResult(
            id=f"vector.{sensor}.counter_reset",
            title=f"Vector counter reset on {name}",
            component=C, severity="warning", sensor=sensor, status=Status.YELLOW,
            details=f"Counter dropped from {prev_recv:.0f} to {scrape.received_events:.0f}",
            remediation="Vector may have restarted. Monitor for stabilization.",
            diagnosis=Diagnosis(
                problem=f"Vector metrics counter reset detected on '{name}' (likely restart)",
                evidence=f"received_events decreased: {prev_recv:.0f} → {scrape.received_events:.0f}",
                impact="Delta calculations will be inaccurate for one cycle. Will self-correct.",
                probable_causes=["Vector service restarted", "Vector upgraded/redeployed"],
                next_steps=["Monitor next scrape cycle for stabilization"],
                fix_location=FIX_ANSIBLE_VECTOR,
                confidence="high",
            ),
        ))

    # 9. Peer comparison
    if peer_sent and len(peer_sent) > 1:
        values = [v for k, v in peer_sent.items() if k != sensor and v > 0]
        if values:
            avg = sum(values) / len(values)
            my_sent = peer_sent.get(sensor, 0)
            if avg > 0 and my_sent < avg * 0.3:
                checks.append(CheckResult(
                    id=f"vector.{sensor}.peer_imbalance",
                    title=f"Vector low throughput vs peers on {name}",
                    component=C, severity="warning", sensor=sensor, status=Status.YELLOW,
                    current_value=my_sent, threshold=avg * 0.3,
                    details=f"Sent {my_sent:.0f} vs peer avg {avg:.0f}",
                    remediation="Investigate if this sensor has fewer logs or a connectivity issue.",
                    diagnosis=Diagnosis(
                        problem=f"Sensor '{name}' sends significantly fewer events than peer sensors",
                        evidence=f"sent_events={my_sent:.0f}, peer average={avg:.0f} (<30%)",
                        impact="This sensor may be under-monitored compared to others.",
                        probable_causes=[
                            "Less network traffic on this sensor's interface",
                            "Zeek capturing a different interface or VLAN",
                            "Vector misconfigured to read fewer log files",
                        ],
                        next_steps=[
                            f"SSH to {name}: zeekctl status",
                            f"Compare interface config between {name} and peer sensors",
                        ],
                        fix_location=FIX_ANSIBLE_VECTOR,
                        confidence="low",
                    ),
                ))

    return checks
