"""
Data Prepper checks – evaluate DP scrape results into CheckResults.
Every non-green check carries a structured Diagnosis.
"""
from __future__ import annotations
from typing import Dict, List, Optional, Tuple
from app.config import settings
from app.models import (
    CheckResult, Component, Diagnosis, Status,
    FIX_DP, FIX_OS, FIX_VALIDATOR, FIX_ANSIBLE_VECTOR,
)
from app.collectors.dataprepper_collector import DataPrepperScrapeResult

C = Component.DATAPREPPER


def run_dataprepper_checks(
    scrape: DataPrepperScrapeResult,
    prev: Optional[Dict[str, float]] = None,
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    p = prev or {}

    # 1. Metrics reachable
    if scrape.metrics_reachable:
        checks.append(CheckResult(
            id="dp.metrics.reachable", title="Data Prepper metrics endpoint reachable",
            component=C, severity="critical", status=Status.GREEN,
            details="Reachable",
        ))
    else:
        checks.append(CheckResult(
            id="dp.metrics.reachable", title="Data Prepper metrics endpoint reachable",
            component=C, severity="critical", status=Status.RED,
            details=scrape.metrics_error or "Unreachable",
            remediation="Verify Data Prepper is running and management port 4900 is accessible with metricRegistries: [Prometheus].",
            diagnosis=Diagnosis(
                problem="Data Prepper management metrics endpoint is unreachable",
                evidence=f"GET {settings.dataprepper_metrics_url} failed: {scrape.metrics_error or 'no response'}",
                impact="Cannot validate Data Prepper pipeline health. Drop-rate and error checks will be UNKNOWN.",
                probable_causes=[
                    "Data Prepper container/service not running",
                    "Management port 4900 not exposed or firewall blocked",
                    "metricRegistries: [Prometheus] not set in data-prepper-config.yaml",
                    "Wrong DATAPREPPER_HOST or DATAPREPPER_METRICS_PORT",
                ],
                next_steps=[
                    f"On central-vm: docker ps | grep data-prepper",
                    f"On central-vm: curl -k -u admin:pass https://localhost:4900/metrics/sys | head -20",
                    "Check data-prepper-config.yaml for: metricRegistries: [Prometheus]",
                    "Verify DATAPREPPER_METRICS_PORT=4900 in validator .env",
                ],
                fix_location=FIX_DP,
                confidence="high",
            ),
        ))
        return checks

    # 2. TLS ok
    if scrape.metrics_reachable:
        if scrape.metrics_tls_ok:
            checks.append(CheckResult(
                id="dp.metrics.tls", title="Data Prepper TLS verification",
                component=C, severity="critical", status=Status.GREEN,
                details="TLS OK",
            ))
        else:
            checks.append(CheckResult(
                id="dp.metrics.tls", title="Data Prepper TLS verification",
                component=C, severity="critical", status=Status.RED,
                details=scrape.metrics_error or "TLS failed",
                remediation="Check CA certificate mount and Data Prepper TLS config.",
                diagnosis=Diagnosis(
                    problem="TLS certificate verification failed when connecting to Data Prepper",
                    evidence=f"TLS error: {scrape.metrics_error or 'certificate verification failed'}",
                    impact="Metrics endpoint blocked by TLS error. All DP checks degraded.",
                    probable_causes=[
                        "CA_CERT_PATH not mounted or wrong CA cert file",
                        "Data Prepper using self-signed cert not in CA bundle",
                        "Certificate expired",
                    ],
                    next_steps=[
                        "Verify CA_CERT_PATH=/certs/ca/ca.crt is mounted in docker-compose.yml",
                        "Check: openssl s_client -connect DATAPREPPER_HOST:4900 -CAfile /certs/ca/ca.crt",
                        "Confirm cert has not expired: openssl x509 -in /certs/ca/ca.crt -noout -dates",
                    ],
                    fix_location=FIX_DP,
                    confidence="high",
                ),
            ))

    # 3. Auth ok
    if scrape.metrics_reachable:
        if scrape.metrics_auth_ok:
            checks.append(CheckResult(
                id="dp.metrics.auth", title="Data Prepper auth",
                component=C, severity="critical", status=Status.GREEN,
                details="Auth OK",
            ))
        else:
            checks.append(CheckResult(
                id="dp.metrics.auth", title="Data Prepper auth",
                component=C, severity="critical", status=Status.RED,
                details="Authentication failed",
                remediation="Verify DATAPREPPER_USERNAME/PASSWORD env vars.",
                diagnosis=Diagnosis(
                    problem="Authentication to Data Prepper management endpoint failed",
                    evidence="HTTP 401/403 from Data Prepper metrics endpoint",
                    impact="Cannot read DP metrics. All DP checks blocked.",
                    probable_causes=[
                        "DATAPREPPER_USERNAME or DATAPREPPER_PASSWORD incorrect",
                        "Data Prepper basic auth changed after deployment",
                    ],
                    next_steps=[
                        "Check DATAPREPPER_USERNAME and DATAPREPPER_PASSWORD in .env",
                        "Verify credentials: curl -k -u USER:PASS https://DP_HOST:4900/metrics/sys",
                    ],
                    fix_location=FIX_VALIDATOR,
                    confidence="high",
                ),
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
    if scrape.ingest_health_404:
        checks.append(CheckResult(
            id="dp.ingest.reachable", title="Data Prepper ingest health",
            component=C, severity="warning", status=Status.YELLOW,
            details=(
                f"Health endpoint returned 404 – health_check_service may not expose "
                f"'{settings.DATAPREPPER_HEALTH_PATH}'. Metrics and ingestion appear healthy."
            ),
            remediation=(
                "Add health_check_service to your Data Prepper pipeline config, or "
                "set DATAPREPPER_HEALTH_PATH to the correct path."
            ),
            diagnosis=Diagnosis(
                problem="Data Prepper health endpoint not found (HTTP 404)",
                evidence=f"GET {settings.dataprepper_health_url} returned 404",
                impact="Cannot confirm ingestion health via /health. However, metrics show pipeline is running.",
                probable_causes=[
                    "health_check_service not added to Data Prepper pipeline YAML",
                    "DATAPREPPER_HEALTH_PATH set to wrong path",
                ],
                next_steps=[
                    "Add to pipeline YAML: health-check-pipeline: ... health_check_service:",
                    f"Or set DATAPREPPER_HEALTH_PATH to the actual health endpoint path",
                    "This is a WARNING, not blocking — metrics and ingestion are working",
                ],
                fix_location=FIX_DP,
                confidence="high",
            ),
        ))
    else:
        if scrape.ingest_healthy:
            checks.append(CheckResult(
                id="dp.ingest.reachable", title="Data Prepper ingest health",
                component=C, severity="critical", status=Status.GREEN,
                details="Healthy",
            ))
        else:
            checks.append(CheckResult(
                id="dp.ingest.reachable", title="Data Prepper ingest health",
                component=C, severity="critical",
                status=Status.YELLOW if scrape.ingest_reachable else Status.RED,
                details=scrape.ingest_error or "Unhealthy",
                remediation="Check Data Prepper ingest port 2021 and health_check_service config.",
                diagnosis=Diagnosis(
                    problem="Data Prepper ingest health endpoint reports unhealthy",
                    evidence=f"Health response: {scrape.ingest_error or 'unhealthy status'}",
                    impact="Data Prepper may not be accepting new log events.",
                    probable_causes=[
                        "Data Prepper pipeline in error state",
                        "OpenSearch sink unreachable causing pipeline back-pressure",
                        "Data Prepper out of memory",
                    ],
                    next_steps=[
                        "On central-vm: docker logs data-prepper --tail 100",
                        "Check dp.os.doc_errors and dp.buffer.usage checks",
                        "Check OpenSearch cluster health",
                    ],
                    fix_location=FIX_DP,
                    confidence="medium",
                ),
            ))

    # 6. Pipeline discovered
    checks.append(CheckResult(
        id="dp.pipelines.discovered", title="Data Prepper pipelines discovered",
        component=C, severity="warning",
        status=Status.GREEN if scrape.pipeline_names else Status.YELLOW,
        current_value=len(scrape.pipeline_names),
        details=f"Pipelines: {', '.join(scrape.pipeline_names) or 'none found'}",
        diagnosis=Diagnosis(
            problem="No Data Prepper pipelines could be discovered from metrics",
            evidence="No pipeline-prefixed metrics found in Prometheus output",
            impact="Drop-rate and throughput correlation checks will be inaccurate.",
            probable_causes=[
                "DATAPREPPER_PIPELINE_NAME not set and auto-detection failed",
                "Metrics naming convention changed in DP version",
            ],
            next_steps=[
                "Set DATAPREPPER_PIPELINE_NAME=your-pipeline-name in .env",
                "Check: curl -k -u ... https://DP_HOST:4900/metrics/sys | grep -i pipeline",
            ],
            fix_location=FIX_VALIDATOR,
            confidence="medium",
        ) if not scrape.pipeline_names else None,
    ))

    # Delta helper
    def _delta(key):
        return scrape.__dict__.get(key, 0) - p.get(key, scrape.__dict__.get(key, 0))

    # 7. Records processed
    rp_d = _delta("records_processed")
    checks.append(CheckResult(
        id="dp.records.processed", title="Data Prepper records processed",
        component=C, severity="warning",
        status=Status.GREEN if rp_d > 0 else Status.YELLOW,
        current_value=rp_d, details=f"Delta: {rp_d:.0f}",
        diagnosis=Diagnosis(
            problem="Data Prepper records_processed counter not increasing",
            evidence=f"records_processed delta = {rp_d:.0f}",
            impact="Data Prepper may not be receiving or processing new events.",
            probable_causes=[
                "No events being sent by Vector (check vector.sent_increasing)",
                "Pipeline paused or in error state",
                "Quiet traffic period",
            ],
            next_steps=[
                "Check Vector sent_events delta on all sensors",
                "Check dp.http.received delta",
            ],
            fix_location=FIX_DP,
            confidence="low",
        ) if rp_d == 0 else None,
    ))

    # 8. HTTP requests received
    hr_d = _delta("http_requests_received")
    checks.append(CheckResult(
        id="dp.http.received", title="Data Prepper HTTP requests received",
        component=C, severity="warning",
        status=Status.GREEN if hr_d > 0 else Status.YELLOW,
        current_value=hr_d, details=f"Delta: {hr_d:.0f}",
        diagnosis=Diagnosis(
            problem="Data Prepper HTTP ingest endpoint receiving no requests",
            evidence=f"http_requestsReceived delta = {hr_d:.0f}",
            impact="No data is reaching Data Prepper from Vector sensors.",
            probable_causes=[
                "Vector sink not pointing to correct Data Prepper host/port",
                "All sensors have zero sent_events (check vector checks)",
                "Network routing issue between sensor subnet and central-vm",
            ],
            next_steps=[
                "Check vector.sent_increasing on all sensors",
                "From sensor: curl -k https://DATAPREPPER_HOST:2021/log/ingest (test connectivity)",
            ],
            fix_location=FIX_ANSIBLE_VECTOR,
            confidence="medium",
        ) if hr_d == 0 else None,
    ))

    # 9. Request timeouts
    to_d = _delta("http_request_timeouts")
    checks.append(CheckResult(
        id="dp.http.timeouts", title="Data Prepper request timeouts",
        component=C, severity="warning",
        status=Status.GREEN if to_d == 0 else Status.YELLOW,
        current_value=to_d, details=f"Timeout delta: {to_d:.0f}",
        remediation="Investigate slow upstream senders or buffer pressure." if to_d > 0 else "",
        diagnosis=Diagnosis(
            problem=f"Data Prepper reporting {to_d:.0f} HTTP request timeouts",
            evidence=f"http_requestTimeouts delta = {to_d:.0f}",
            impact="Sensors may be retrying, causing duplicate or delayed data.",
            probable_causes=[
                "Data Prepper buffer full (check dp.buffer.usage)",
                "OpenSearch sink too slow, causing back-pressure",
                "Vector batch size too large for DP throughput",
            ],
            next_steps=[
                "Check dp.buffer.usage check",
                "Check OpenSearch cluster health and indexing speed",
            ],
            fix_location=FIX_DP,
            confidence="medium",
        ) if to_d > 0 else None,
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
    if de_d <= t:
        checks.append(CheckResult(
            id="dp.os.doc_errors", title="Data Prepper document errors",
            component=C, severity="critical", status=Status.GREEN,
            current_value=de_d, threshold=t, details=f"Document error delta: {de_d:.0f}",
        ))
    else:
        checks.append(CheckResult(
            id="dp.os.doc_errors", title="Data Prepper document errors",
            component=C, severity="critical", status=Status.RED,
            current_value=de_d, threshold=t,
            details=f"Document error delta: {de_d:.0f}",
            remediation="Check index mappings and Data Prepper pipeline transform rules.",
            diagnosis=Diagnosis(
                problem=f"Data Prepper is failing to index documents ({de_d:.0f} errors since last cycle)",
                evidence=f"opensearch_documentErrors delta = {de_d:.0f} (threshold: {t})",
                impact="BLOCKING: Documents are being rejected by OpenSearch. Data loss occurring.",
                probable_causes=[
                    "Index mapping conflict (field type mismatch)",
                    "Required field missing from Zeek → DP transform",
                    "OpenSearch index template not applied",
                    "Document size exceeding cluster limit",
                ],
                next_steps=[
                    "On central-vm: check Data Prepper logs for 'document_errors' or 'mapper_parsing_exception'",
                    "GET zeek-*/_mapping in OpenSearch Dashboards Dev Tools",
                    "Check if index template is applied: GET /_index_template/zeek*",
                    "Review recent changes to Data Prepper pipeline transform rules",
                ],
                fix_location=FIX_DP,
                confidence="high",
            ),
        ))

    # 12. Bulk request failed
    bf_d = _delta("os_bulk_request_failed")
    t2 = settings.MAX_DP_BULK_FAILURE_DELTA
    if bf_d <= t2:
        checks.append(CheckResult(
            id="dp.os.bulk_failed", title="Data Prepper bulk request failures",
            component=C, severity="critical", status=Status.GREEN,
            current_value=bf_d, threshold=t2, details=f"Bulk failure delta: {bf_d:.0f}",
        ))
    else:
        checks.append(CheckResult(
            id="dp.os.bulk_failed", title="Data Prepper bulk request failures",
            component=C, severity="critical", status=Status.RED,
            current_value=bf_d, threshold=t2,
            details=f"Bulk failure delta: {bf_d:.0f}",
            remediation="Check OpenSearch cluster health and disk space.",
            diagnosis=Diagnosis(
                problem=f"Data Prepper bulk indexing requests are failing ({bf_d:.0f} failures)",
                evidence=f"opensearch_bulkRequestFailed delta = {bf_d:.0f}",
                impact="BLOCKING: Batches of events not making it to OpenSearch. Significant data loss risk.",
                probable_causes=[
                    "OpenSearch cluster in RED or YELLOW state (check os.cluster.health)",
                    "OpenSearch disk full (check node disk metrics)",
                    "Index write block applied",
                    "Circuit breaker triggered by large bulk request",
                ],
                next_steps=[
                    "GET /_cluster/health in OpenSearch Dashboards",
                    "GET /_cat/nodes?h=name,disk.avail,disk.used_percent",
                    "On central-vm: docker logs data-prepper | grep bulk",
                    "Check for write blocks: GET /_cluster/settings",
                ],
                fix_location=FIX_OS,
                confidence="high",
            ),
        ))

    # 13. Pipeline latency
    lat, lat_source = _compute_safe_latency(scrape, p)
    if lat is None:
        checks.append(CheckResult(
            id="dp.pipeline.latency", title="Data Prepper pipeline latency",
            component=C, severity="info", status=Status.UNKNOWN,
            details=(
                f"Pipeline latency not yet calculable ({lat_source}). "
                "This is normal on the first scrape cycle; will compute on next cycle."
            ),
        ))
    else:
        s = Status.GREEN if lat < settings.MAX_DP_PIPELINE_LATENCY_SECONDS_WARN else (
            Status.YELLOW if lat < settings.MAX_DP_PIPELINE_LATENCY_SECONDS_CRIT else Status.RED)
        checks.append(CheckResult(
            id="dp.pipeline.latency", title="Data Prepper pipeline latency",
            component=C, severity="warning", status=s,
            current_value=round(lat, 3),
            threshold=settings.MAX_DP_PIPELINE_LATENCY_SECONDS_WARN,
            details=f"Pipeline latency: {lat:.3f}s (source: {lat_source})",
            remediation="Check OpenSearch sink throughput and buffer pressure." if s != Status.GREEN else "",
            diagnosis=Diagnosis(
                problem=f"Data Prepper pipeline latency is high ({lat:.3f}s)",
                evidence=f"PipelineLatency = {lat:.3f}s (warn: {settings.MAX_DP_PIPELINE_LATENCY_SECONDS_WARN}s, crit: {settings.MAX_DP_PIPELINE_LATENCY_SECONDS_CRIT}s)",
                impact="Events arrive in OpenSearch with significant delay. Near-real-time detection degraded.",
                probable_causes=[
                    "OpenSearch indexing slow (check cluster health and shard allocation)",
                    "Data Prepper buffer near capacity (check dp.buffer.usage)",
                    "High event volume overwhelming OpenSearch bulk API",
                ],
                next_steps=[
                    "Check dp.buffer.usage check",
                    "GET /_cat/thread_pool/write?v in OpenSearch",
                    "Consider increasing Data Prepper worker_threads or batch_size",
                ],
                fix_location=FIX_DP,
                confidence="medium",
            ) if s != Status.GREEN else None,
        ))

    # 14. Buffer usage
    bu = scrape.buffer_usage
    s = Status.GREEN if bu < settings.MAX_DP_BUFFER_USAGE_RATIO_WARN else (
        Status.YELLOW if bu < settings.MAX_DP_BUFFER_USAGE_RATIO_CRIT else Status.RED)
    checks.append(CheckResult(
        id="dp.buffer.usage", title="Data Prepper buffer usage",
        component=C, severity="warning", status=s,
        current_value=bu, threshold=settings.MAX_DP_BUFFER_USAGE_RATIO_WARN,
        details=f"Buffer usage ratio: {bu:.2f}",
        remediation="Consider increasing buffer size or optimizing sink throughput." if bu >= settings.MAX_DP_BUFFER_USAGE_RATIO_WARN else "",
        diagnosis=Diagnosis(
            problem=f"Data Prepper buffer is {'critically' if s == Status.RED else ''} full ({bu*100:.0f}%)",
            evidence=f"BlockingBuffer_bufferUsage = {bu:.2f}",
            impact="High buffer usage causes ingestion delays and eventual write failures.",
            probable_causes=[
                "OpenSearch indexing slower than ingestion rate",
                "OpenSearch cluster health issues causing slow writes",
                "Sudden spike in log volume from sensors",
            ],
            next_steps=[
                "Check dp.os.bulk_failed and os.cluster.health",
                "Consider increasing buffer_capacity in Data Prepper pipeline YAML",
            ],
            fix_location=FIX_DP,
            confidence="high",
        ) if s != Status.GREEN else None,
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
        diagnosis=Diagnosis(
            problem=f"Data Prepper buffer is dropping writes ({bwf_d:.0f} failures)",
            evidence=f"BlockingBuffer_recordsWriteFailed delta = {bwf_d:.0f}",
            impact="Events are being dropped at the buffer stage. Data loss occurring.",
            probable_causes=[
                "Buffer completely full — OpenSearch too slow to drain it",
                "Extremely high ingest rate spike",
            ],
            next_steps=[
                "Immediately check OpenSearch cluster health",
                "Reduce Vector ingest rate or increase DP buffer_capacity",
            ],
            fix_location=FIX_DP,
            confidence="high",
        ) if bwf_d > t3 else None,
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
        diagnosis=Diagnosis(
            problem=f"Data Prepper reporting TLS handshake failures ({tf_d:.0f} since last cycle)",
            evidence=f"armeria_server_tls_handshakes_total{{result=failure}} delta = {tf_d:.0f}",
            impact="Vector cannot establish secure connections to Data Prepper. Events dropped.",
            probable_causes=[
                "Vector configured for HTTP but Data Prepper requires HTTPS (TLS)",
                "CA certificate on sensors does not trust Data Prepper TLS cert",
                "Data Prepper certificate expired or hostname mismatch",
            ],
            next_steps=[
                "Check corr.tls.mismatch check for classification",
                "On sensor: check Vector sink tls.ca_file or tls.enabled setting",
                "On central-vm: verify Data Prepper cert is valid: openssl x509 -in cert.pem -noout -dates",
            ],
            fix_location=FIX_ANSIBLE_VECTOR,
            confidence="high",
        ) if tf_d > t4 else None,
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
            diagnosis=Diagnosis(
                problem=f"Data Prepper JVM heap usage is high ({heap_pct:.1f}%)",
                evidence=f"jvm_memory_bytes_used/max = {heap_pct:.1f}%",
                impact="Risk of OutOfMemoryError and pipeline stall.",
                probable_causes=[
                    "High event volume without GC keeping up",
                    "Memory leak in pipeline configuration",
                    "JVM heap size too small for workload",
                ],
                next_steps=[
                    "On central-vm: check Data Prepper JVM args (Xmx setting)",
                    "Consider increasing container memory allocation",
                ],
                fix_location=FIX_DP,
                confidence="medium",
            ) if heap_pct >= settings.HIGH_HEAP_THRESHOLD_PERCENT else None,
        ))

    # 18. DLQ files
    if settings.ENABLE_DP_DLQ_CHECK and scrape.dlq_nonempty_files:
        checks.append(CheckResult(
            id="dp.dlq.nonempty", title="Data Prepper DLQ non-empty files",
            component=C, severity="warning", status=Status.YELLOW,
            current_value=len(scrape.dlq_nonempty_files),
            details=f"DLQ files with data: {', '.join(scrape.dlq_nonempty_files[:5])}",
            remediation="Review DLQ files for rejected/failed events.",
            diagnosis=Diagnosis(
                problem=f"{len(scrape.dlq_nonempty_files)} non-empty DLQ file(s) found",
                evidence=f"Files: {', '.join(scrape.dlq_nonempty_files[:3])}",
                impact="Events that failed processing are accumulating in DLQ. Data loss if not addressed.",
                probable_causes=[
                    "Document mapping errors causing index failures",
                    "OpenSearch rejections",
                ],
                next_steps=[
                    f"cat {scrape.dlq_nonempty_files[0]} | head -5",
                    "Identify the failing document type and fix mapping",
                ],
                fix_location=FIX_DP,
                confidence="high",
            ),
        ))

    return checks


def _compute_safe_latency(
    scrape: DataPrepperScrapeResult,
    p: Dict[str, float],
) -> Tuple[Optional[float], str]:
    """Return (latency_seconds, source_description) or (None, reason)."""
    if scrape.os_pipeline_latency_max >= 0:
        return scrape.os_pipeline_latency_max, "max_per_polling_window"

    sum_now = scrape.os_pipeline_latency_sum
    count_now = scrape.os_pipeline_latency_count
    sum_prev = p.get("os_pipeline_latency_sum", sum_now)
    count_prev = p.get("os_pipeline_latency_count", count_now)

    sum_delta = sum_now - sum_prev
    count_delta = count_now - count_prev

    if count_delta > 0 and sum_delta >= 0:
        avg = sum_delta / count_delta
        return avg, f"delta_avg ({sum_delta:.3f}s / {count_delta:.0f} obs)"

    return None, "awaiting_second_scrape_cycle"
