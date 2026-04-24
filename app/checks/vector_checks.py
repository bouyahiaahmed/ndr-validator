"""
Vector checks – evaluate Vector scrape results into CheckResults.
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Dict, List, Optional
from app.config import settings
from app.models import CheckResult, Component, Status

if TYPE_CHECKING:
    from app.collectors.vector_collector import VectorScrapeResult

C = Component.VECTOR

def run_vector_checks(
    scrape: VectorScrapeResult,
    prev_metrics: Optional[Dict[str, float]] = None,
    peer_sent: Optional[Dict[str, float]] = None,
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    sensor = scrape.sensor_ip
    name = settings.sensor_display_name(sensor)

    # 1. Endpoint reachable
    checks.append(CheckResult(
        id=f"vector.{sensor}.reachable", title=f"Vector reachable on {name}",
        component=C, severity="critical", sensor=sensor,
        status=Status.GREEN if scrape.reachable else Status.RED,
        details=scrape.error or "Endpoint responding",
        remediation="Check Vector is running and prometheus_exporter sink is configured on the sensor.",
    ))
    if not scrape.reachable:
        return checks

    # 2. Scrape parseable
    parse_ok = bool(scrape.families) and scrape.error is None
    checks.append(CheckResult(
        id=f"vector.{sensor}.parse", title=f"Vector metrics parseable on {name}",
        component=C, severity="critical", sensor=sensor,
        status=Status.GREEN if parse_ok else Status.RED,
        details="Prometheus payload parsed" if parse_ok else (scrape.error or "Parse failed"),
        remediation="Verify Vector internal_metrics source and prometheus_exporter sink.",
    ))

    # 3. Metric version detected
    checks.append(CheckResult(
        id=f"vector.{sensor}.metric_version", title=f"Vector metric version on {name}",
        component=C, severity="info", sensor=sensor,
        status=Status.GREEN if scrape.metric_version != "unknown" else Status.YELLOW,
        current_value=scrape.metric_version,
        details=f"Detected metric version: {scrape.metric_version}",
    ))

    # 4. Received events increasing
    prev = prev_metrics or {}
    prev_recv = prev.get("received_events", 0)
    recv_delta = scrape.received_events - prev_recv if prev_recv else None
    if recv_delta is not None:
        s = Status.GREEN if recv_delta > 0 else (Status.YELLOW if recv_delta == 0 else Status.RED)
        checks.append(CheckResult(
            id=f"vector.{sensor}.recv_increasing", title=f"Vector input events on {name}",
            component=C, severity="warning", sensor=sensor, status=s,
            current_value=recv_delta, details=f"Received events delta: {recv_delta:.0f}",
            remediation="Check Zeek log source or file permissions on sensor." if s != Status.GREEN else "",
        ))

    # 5. Sent events increasing
    prev_sent = prev.get("sent_events", 0)
    sent_delta = scrape.sent_events - prev_sent if prev_sent else None
    if sent_delta is not None:
        s = Status.GREEN if sent_delta > 0 else (Status.YELLOW if sent_delta == 0 else Status.RED)
        checks.append(CheckResult(
            id=f"vector.{sensor}.sent_increasing", title=f"Vector output events on {name}",
            component=C, severity="warning", sensor=sensor, status=s,
            current_value=sent_delta, details=f"Sent events delta: {sent_delta:.0f}",
            remediation="Check Vector sink config and Data Prepper connectivity.",
        ))

    # 6. Errors increasing
    prev_err = prev.get("errors_total", 0)
    err_delta = scrape.errors_total - prev_err if prev_err else 0
    if err_delta > 0:
        checks.append(CheckResult(
            id=f"vector.{sensor}.errors", title=f"Vector errors on {name}",
            component=C, severity="warning", sensor=sensor, status=Status.YELLOW,
            current_value=err_delta, details=f"Error count delta: {err_delta:.0f}",
            remediation="Check Vector logs for error details.",
        ))
    else:
        checks.append(CheckResult(
            id=f"vector.{sensor}.errors", title=f"Vector errors on {name}",
            component=C, severity="warning", sensor=sensor, status=Status.GREEN,
            current_value=0, details="No new errors",
        ))

    # 7. Input moves but output does not
    if recv_delta is not None and sent_delta is not None:
        if recv_delta > 0 and sent_delta == 0:
            checks.append(CheckResult(
                id=f"vector.{sensor}.input_no_output", title=f"Vector input without output on {name}",
                component=C, severity="critical", sensor=sensor, status=Status.RED,
                details=f"Received {recv_delta:.0f} events but sent 0",
                remediation="Check Vector sink configuration, Data Prepper endpoint, and TLS settings.",
            ))

    # 8. Counter reset detection
    if prev_recv and scrape.received_events < prev_recv:
        checks.append(CheckResult(
            id=f"vector.{sensor}.counter_reset", title=f"Vector counter reset on {name}",
            component=C, severity="warning", sensor=sensor, status=Status.YELLOW,
            details=f"Counter dropped from {prev_recv:.0f} to {scrape.received_events:.0f}",
            remediation="Vector may have restarted. Monitor for stabilization.",
        ))

    # 9. Peer comparison
    if peer_sent and len(peer_sent) > 1:
        values = [v for k, v in peer_sent.items() if k != sensor and v > 0]
        if values:
            avg = sum(values) / len(values)
            my_sent = peer_sent.get(sensor, 0)
            if avg > 0 and my_sent < avg * 0.3:
                checks.append(CheckResult(
                    id=f"vector.{sensor}.peer_imbalance", title=f"Vector low throughput vs peers on {name}",
                    component=C, severity="warning", sensor=sensor, status=Status.YELLOW,
                    current_value=my_sent, threshold=avg * 0.3,
                    details=f"Sent {my_sent:.0f} vs peer avg {avg:.0f}",
                    remediation="Investigate if this sensor has fewer logs or a connectivity issue.",
                ))

    return checks
