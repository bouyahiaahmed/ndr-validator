"""
Data Prepper checks – evaluate DP scrape results into CheckResults.
"""
from __future__ import annotations
from typing import Dict, List, Optional
from app.config import settings
from app.models import CheckResult, Component, Status
from app.collectors.dataprepper_collector import DataPrepperScrapeResult

C = Component.DATAPREPPER

def run_dataprepper_checks(
    scrape: DataPrepperScrapeResult,
    prev: Optional[Dict[str, float]] = None,
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    p = prev or {}

    # 1. Metrics reachable
    checks.append(CheckResult(
        id="dp.metrics.reachable", title="Data Prepper metrics endpoint reachable",
        component=C, severity="critical",
        status=Status.GREEN if scrape.metrics_reachable else Status.RED,
        details=scrape.metrics_error or "Reachable",
        remediation="Verify Data Prepper is running and management port 4900 is accessible.",
    ))
    # 2. TLS ok
    if scrape.metrics_reachable:
        checks.append(CheckResult(
            id="dp.metrics.tls", title="Data Prepper TLS verification",
            component=C, severity="critical",
            status=Status.GREEN if scrape.metrics_tls_ok else Status.RED,
            details="TLS OK" if scrape.metrics_tls_ok else (scrape.metrics_error or "TLS failed"),
            remediation="Check CA certificate mount and Data Prepper TLS config.",
        ))
    # 3. Auth ok
    if scrape.metrics_reachable:
        checks.append(CheckResult(
            id="dp.metrics.auth", title="Data Prepper auth",
            component=C, severity="critical",
            status=Status.GREEN if scrape.metrics_auth_ok else Status.RED,
            details="Auth OK" if scrape.metrics_auth_ok else "Authentication failed",
            remediation="Verify DATAPREPPER_USERNAME/PASSWORD env vars.",
        ))
    if not scrape.metrics_auth_ok:
        return checks

    # 4. Parse ok
    parse_ok = bool(scrape.families) and scrape.metrics_error is None
    checks.append(CheckResult(
        id="dp.metrics.parse", title="Data Prepper metrics parse", component=C,
        severity="critical", status=Status.GREEN if parse_ok else Status.RED,
        details="Parsed OK" if parse_ok else (scrape.metrics_error or "Parse failed"),
    ))
    # 5. Ingest health
    checks.append(CheckResult(
        id="dp.ingest.reachable", title="Data Prepper ingest health",
        component=C, severity="critical",
        status=Status.GREEN if scrape.ingest_healthy else (Status.YELLOW if scrape.ingest_reachable else Status.RED),
        details="Healthy" if scrape.ingest_healthy else (scrape.ingest_error or "Unhealthy"),
        remediation="Check Data Prepper ingest port 2021 and health_check_service config.",
    ))
    # 6. Pipeline discovered
    checks.append(CheckResult(
        id="dp.pipelines.discovered", title="Data Prepper pipelines discovered",
        component=C, severity="warning",
        status=Status.GREEN if scrape.pipeline_names else Status.YELLOW,
        current_value=len(scrape.pipeline_names),
        details=f"Pipelines: {', '.join(scrape.pipeline_names) or 'none found'}",
    ))

    # Delta-based checks
    def _delta(key):
        return scrape.__dict__.get(key, 0) - p.get(key, scrape.__dict__.get(key, 0))

    # 7. Records processed increasing
    rp_d = _delta("records_processed")
    checks.append(CheckResult(
        id="dp.records.processed", title="Data Prepper records processed",
        component=C, severity="warning",
        status=Status.GREEN if rp_d > 0 else Status.YELLOW,
        current_value=rp_d, details=f"Delta: {rp_d:.0f}",
    ))
    # 8. HTTP requests received
    hr_d = _delta("http_requests_received")
    checks.append(CheckResult(
        id="dp.http.received", title="Data Prepper HTTP requests received",
        component=C, severity="warning",
        status=Status.GREEN if hr_d > 0 else Status.YELLOW,
        current_value=hr_d, details=f"Delta: {hr_d:.0f}",
    ))
    # 9. Request timeouts
    to_d = _delta("http_request_timeouts")
    checks.append(CheckResult(
        id="dp.http.timeouts", title="Data Prepper request timeouts",
        component=C, severity="warning",
        status=Status.GREEN if to_d == 0 else Status.YELLOW,
        current_value=to_d, details=f"Timeout delta: {to_d:.0f}",
        remediation="Investigate slow upstream senders or buffer pressure." if to_d > 0 else "",
    ))
    # 10. OpenSearch records in
    oi_d = _delta("os_records_in")
    checks.append(CheckResult(
        id="dp.os.records_in", title="Data Prepper OpenSearch records in",
        component=C, severity="warning",
        status=Status.GREEN if oi_d > 0 else Status.YELLOW,
        current_value=oi_d, details=f"Delta: {oi_d:.0f}",
    ))
    # 11. Document errors
    de_d = _delta("os_document_errors")
    t = settings.MAX_DP_DOCUMENT_ERROR_DELTA
    checks.append(CheckResult(
        id="dp.os.doc_errors", title="Data Prepper document errors",
        component=C, severity="critical",
        status=Status.GREEN if de_d <= t else Status.RED,
        current_value=de_d, threshold=t,
        details=f"Document error delta: {de_d:.0f}",
        remediation="Check index mappings and Data Prepper pipeline transform rules." if de_d > t else "",
    ))
    # 12. Bulk request failed
    bf_d = _delta("os_bulk_request_failed")
    t2 = settings.MAX_DP_BULK_FAILURE_DELTA
    checks.append(CheckResult(
        id="dp.os.bulk_failed", title="Data Prepper bulk request failures",
        component=C, severity="critical",
        status=Status.GREEN if bf_d <= t2 else Status.RED,
        current_value=bf_d, threshold=t2,
        details=f"Bulk failure delta: {bf_d:.0f}",
        remediation="Check OpenSearch cluster health and disk space." if bf_d > t2 else "",
    ))
    # 13. Pipeline latency
    lat = scrape.os_pipeline_latency
    checks.append(CheckResult(
        id="dp.pipeline.latency", title="Data Prepper pipeline latency",
        component=C, severity="warning",
        status=Status.GREEN if lat < settings.MAX_DP_PIPELINE_LATENCY_SECONDS_WARN else (
            Status.YELLOW if lat < settings.MAX_DP_PIPELINE_LATENCY_SECONDS_CRIT else Status.RED),
        current_value=lat, threshold=settings.MAX_DP_PIPELINE_LATENCY_SECONDS_WARN,
        details=f"Pipeline latency: {lat:.2f}s",
    ))
    # 14. Buffer usage
    bu = scrape.buffer_usage
    checks.append(CheckResult(
        id="dp.buffer.usage", title="Data Prepper buffer usage",
        component=C, severity="warning",
        status=Status.GREEN if bu < settings.MAX_DP_BUFFER_USAGE_RATIO_WARN else (
            Status.YELLOW if bu < settings.MAX_DP_BUFFER_USAGE_RATIO_CRIT else Status.RED),
        current_value=bu, threshold=settings.MAX_DP_BUFFER_USAGE_RATIO_WARN,
        details=f"Buffer usage ratio: {bu:.2f}",
        remediation="Consider increasing buffer size or optimizing sink throughput." if bu >= settings.MAX_DP_BUFFER_USAGE_RATIO_WARN else "",
    ))
    # 15. Buffer write failures
    bwf_d = _delta("buffer_write_failed")
    t3 = settings.MAX_DP_BUFFER_WRITE_FAILURE_DELTA
    checks.append(CheckResult(
        id="dp.buffer.write_failed", title="Data Prepper buffer write failures",
        component=C, severity="critical",
        status=Status.GREEN if bwf_d <= t3 else Status.RED,
        current_value=bwf_d, threshold=t3,
        details=f"Buffer write failure delta: {bwf_d:.0f}",
        remediation="Buffer is full. Increase buffer capacity or reduce ingest rate." if bwf_d > t3 else "",
    ))
    # 16. TLS handshake failures
    tf_d = _delta("tls_handshake_failure")
    t4 = settings.MAX_DP_TLS_HANDSHAKE_FAILURE_DELTA
    checks.append(CheckResult(
        id="dp.tls.handshake_failures", title="Data Prepper TLS handshake failures",
        component=C, severity="critical",
        status=Status.GREEN if tf_d <= t4 else Status.RED,
        current_value=tf_d, threshold=t4,
        details=f"TLS handshake failure delta: {tf_d:.0f}",
        remediation="Check Vector TLS config, CA cert trust chain, and protocol (HTTP vs HTTPS)." if tf_d > t4 else "",
    ))
    # 17. JVM heap
    if scrape.jvm_heap_max > 0:
        heap_pct = (scrape.jvm_heap_used / scrape.jvm_heap_max) * 100
        checks.append(CheckResult(
            id="dp.jvm.heap", title="Data Prepper JVM heap usage",
            component=C, severity="warning",
            status=Status.GREEN if heap_pct < settings.HIGH_HEAP_THRESHOLD_PERCENT else Status.YELLOW,
            current_value=heap_pct, threshold=settings.HIGH_HEAP_THRESHOLD_PERCENT,
            details=f"Heap: {heap_pct:.1f}%",
        ))
    # 18. DLQ files
    if settings.ENABLE_DP_DLQ_CHECK and scrape.dlq_nonempty_files:
        checks.append(CheckResult(
            id="dp.dlq.nonempty", title="Data Prepper DLQ non-empty files",
            component=C, severity="warning", status=Status.YELLOW,
            current_value=len(scrape.dlq_nonempty_files),
            details=f"DLQ files with data: {', '.join(scrape.dlq_nonempty_files[:5])}",
            remediation="Review DLQ files for rejected/failed events.",
        ))

    return checks
