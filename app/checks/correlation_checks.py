"""
Correlation checks – cross-stage pipeline integrity validation.
These are the most important checks: they detect silent drops, bottlenecks,
TLS/protocol mismatches, and end-to-end freshness gaps.
"""
from __future__ import annotations
import logging
from typing import Dict, List, Optional
from app.config import settings
from app.models import CheckResult, Component, Status
from app.utils.time import parse_iso_timestamp, seconds_ago

logger = logging.getLogger(__name__)
C = Component.CORRELATION


def run_correlation_checks(
    vector_results: list,        # List[VectorScrapeResult]
    dp_result,                   # DataPrepperScrapeResult
    os_result,                   # OpenSearchScrapeResult
    zeek_results: list,          # List[ZeekSensorResult]
    prev_vector: Optional[Dict[str, Dict[str, float]]] = None,
    prev_dp: Optional[Dict[str, float]] = None,
    prev_os: Optional[Dict[str, float]] = None,
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    pv = prev_vector or {}
    pd = prev_dp or {}
    po = prev_os or {}

    # ── 1. ZEEK → VECTOR correlation ────────────────────────────────
    if zeek_results and vector_results:
        for zr in zeek_results:
            if not zr.ssh_reachable:
                continue
            # Find matching Vector result
            vr = next((v for v in vector_results if v.sensor_ip == zr.sensor_ip), None)
            if vr is None:
                continue

            zeek_fresh = zr.zeek_running and not zr.stale_logs
            vector_moving = vr.reachable and (vr.sent_events > pv.get(zr.sensor_ip, {}).get("sent_events", 0))
            name = settings.sensor_display_name(zr.sensor_ip)

            if zeek_fresh and not vector_moving:
                checks.append(CheckResult(
                    id=f"corr.zeek_vector.{zr.sensor_ip}.writing_not_forwarding",
                    title=f"Zeek writing but Vector not forwarding on {name}",
                    component=C, severity="critical", sensor=zr.sensor_ip, status=Status.RED,
                    details="Zeek logs are fresh but Vector shows no outbound movement",
                    remediation="Check Vector file source paths match ZEEK_LOG_DIR. Verify Vector service and sink config.",
                ))
            elif not zeek_fresh and vector_moving:
                checks.append(CheckResult(
                    id=f"corr.zeek_vector.{zr.sensor_ip}.stale_but_forwarding",
                    title=f"Vector forwarding but Zeek logs stale on {name}",
                    component=C, severity="warning", sensor=zr.sensor_ip, status=Status.YELLOW,
                    details="Vector is sending events but Zeek logs are stale — possible stale data in transit or lag",
                    remediation="Verify Zeek is capturing live traffic. Vector may be draining buffered logs.",
                ))
            else:
                checks.append(CheckResult(
                    id=f"corr.zeek_vector.{zr.sensor_ip}.ok",
                    title=f"Zeek→Vector correlation OK on {name}",
                    component=C, severity="info", sensor=zr.sensor_ip, status=Status.GREEN,
                    details="Zeek writing and Vector forwarding",
                ))

    # ── 2. VECTOR → DATA PREPPER drop rate ───────────────────────────
    if vector_results and dp_result and dp_result.metrics_reachable:
        total_vector_sent_delta = 0.0
        for vr in vector_results:
            sensor_prev = pv.get(vr.sensor_ip, {})
            prev_sent = sensor_prev.get("sent_events", 0)
            delta = max(0, vr.sent_events - prev_sent) if prev_sent else 0
            total_vector_sent_delta += delta

        dp_received_delta = dp_result.http_requests_received - pd.get("http_requests_received", dp_result.http_requests_received)
        dp_processed_delta = dp_result.records_processed - pd.get("records_processed", dp_result.records_processed)

        if total_vector_sent_delta > 0 and dp_received_delta >= 0:
            # Events vs HTTP requests aren't 1:1 (batching), so use processed as proxy
            if dp_processed_delta >= 0:
                drop_pct = max(0, (total_vector_sent_delta - dp_processed_delta) / total_vector_sent_delta * 100)
                t = settings.MAX_VECTOR_TO_DP_DROP_PERCENT
                s = Status.GREEN if drop_pct <= t else (Status.YELLOW if drop_pct <= t * 3 else Status.RED)
                checks.append(CheckResult(
                    id="corr.vector_dp.drop_rate",
                    title="Vector→DataPrepper drop rate",
                    component=C, severity="critical", status=s,
                    current_value=round(drop_pct, 2), threshold=t,
                    details=f"Estimated drop: {drop_pct:.1f}% (Vector sent Δ={total_vector_sent_delta:.0f}, DP processed Δ={dp_processed_delta:.0f})",
                    remediation="Check Data Prepper connectivity, TLS config, and buffer pressure." if s != Status.GREEN else "",
                ))

        # Per-sensor imbalance
        sent_map: Dict[str, float] = {}
        for vr in vector_results:
            sensor_prev = pv.get(vr.sensor_ip, {})
            prev_sent = sensor_prev.get("sent_events", 0)
            sent_map[vr.sensor_ip] = max(0, vr.sent_events - prev_sent) if prev_sent else 0

        if len(sent_map) > 1:
            values = [v for v in sent_map.values() if v > 0]
            if values:
                avg = sum(values) / len(values)
                for ip, val in sent_map.items():
                    if avg > 0 and val < avg * 0.2:
                        name = settings.sensor_display_name(ip)
                        checks.append(CheckResult(
                            id=f"corr.vector_dp.sensor_imbalance.{ip}",
                            title=f"Sensor {name} severely low throughput vs peers",
                            component=C, severity="warning", sensor=ip, status=Status.YELLOW,
                            current_value=val, threshold=avg * 0.2,
                            details=f"Sent Δ={val:.0f} vs peer avg Δ={avg:.0f}",
                            remediation="Check Zeek, Vector, and network on this sensor.",
                        ))

    # ── 3. DATA PREPPER → OPENSEARCH drop rate ───────────────────────
    if dp_result and dp_result.metrics_reachable and os_result and os_result.reachable:
        dp_os_in_delta = dp_result.os_records_in - pd.get("os_records_in", dp_result.os_records_in)
        dp_doc_errors = dp_result.os_document_errors - pd.get("os_document_errors", dp_result.os_document_errors)
        os_count_delta = os_result.total_count - po.get("total_count", os_result.total_count)

        if dp_os_in_delta > 0 and os_count_delta >= 0:
            # Detect scope mismatch: DP metrics cover all pipelines/log types,
            # but OPENSEARCH_INDEX_PATTERN may be narrowed to specific log types.
            # A comma-separated pattern (e.g. zeek-conn-*,zeek-dns-*) but NOT a
            # broad wildcard (e.g. zeek-*) means the OS count only covers a subset.
            scope_ok = _dp_os_scopes_match()
            if not scope_ok:
                checks.append(CheckResult(
                    id="corr.dp_os.drop_rate",
                    title="DataPrepper→OpenSearch drop rate",
                    component=C, severity="warning", status=Status.UNKNOWN,
                    details=(
                        "Drop rate check skipped: Data Prepper metrics cover all pipeline log types "
                        "but OPENSEARCH_INDEX_PATTERN is narrowed to specific indices. "
                        "Set DP_TO_OS_CORRELATION_INDEX_PATTERN to the full pattern (e.g. zeek-*) "
                        "to enable this check."
                    ),
                    remediation=(
                        "Add DP_TO_OS_CORRELATION_INDEX_PATTERN=zeek-* (or matching scope) to .env."
                    ),
                ))
            else:
                drop_pct = max(0, (dp_os_in_delta - os_count_delta) / dp_os_in_delta * 100)
                t = settings.MAX_DP_TO_OS_DROP_PERCENT
                s = Status.GREEN if drop_pct <= t else (Status.YELLOW if drop_pct <= t * 3 else Status.RED)
                checks.append(CheckResult(
                    id="corr.dp_os.drop_rate",
                    title="DataPrepper→OpenSearch drop rate",
                    component=C, severity="critical", status=s,
                    current_value=round(drop_pct, 2), threshold=t,
                    details=f"Estimated drop: {drop_pct:.1f}% (DP sent Δ={dp_os_in_delta:.0f}, OS docs Δ={os_count_delta:.0f})",
                    remediation="Check OpenSearch cluster health, disk space, and index mappings." if s != Status.GREEN else "",
                ))

        # Indexing stall: OS reachable, DP sending, but OS not growing
        if dp_os_in_delta > 100 and os_count_delta == 0:
            checks.append(CheckResult(
                id="corr.dp_os.indexing_stall",
                title="OpenSearch indexing stall detected",
                component=C, severity="critical", status=Status.RED,
                details=f"DP sent {dp_os_in_delta:.0f} records but OS doc count unchanged",
                remediation="Check OpenSearch index lifecycle, shard status, and rejection logs.",
            ))

        if dp_doc_errors > 0:
            checks.append(CheckResult(
                id="corr.dp_os.doc_errors",
                title="Document errors at OpenSearch sink",
                component=C, severity="critical", status=Status.RED,
                current_value=dp_doc_errors,
                details=f"Document errors Δ={dp_doc_errors:.0f}",
                remediation="Check Data Prepper pipeline transform rules and index mappings.",
            ))

    # ── 4. END-TO-END FRESHNESS ──────────────────────────────────────
    if os_result and os_result.overall_latest_ts:
        ts = parse_iso_timestamp(str(os_result.overall_latest_ts))
        age = seconds_ago(ts)
        if age is not None:
            s = Status.GREEN if age < settings.STALE_DATA_THRESHOLD_SECONDS else (
                Status.YELLOW if age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED)
            checks.append(CheckResult(
                id="corr.e2e.freshness",
                title="End-to-end pipeline freshness",
                component=C, severity="critical", status=s,
                current_value=round(age, 1), threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                details=f"Latest data in OpenSearch is {age:.0f}s old",
                remediation="Trace pipeline stages for stalls." if s != Status.GREEN else "",
            ))

    # Worst sensor freshness
    if os_result and os_result.sensor_freshness:
        worst_age = 0.0
        worst_sensor = ""
        for sensor_key, ts_val in os_result.sensor_freshness.items():
            if ts_val:
                ts = parse_iso_timestamp(str(ts_val))
                age = seconds_ago(ts)
                if age and age > worst_age:
                    worst_age = age
                    worst_sensor = sensor_key
        if worst_sensor and worst_age > settings.STALE_DATA_THRESHOLD_SECONDS:
            s = Status.YELLOW if worst_age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED
            checks.append(CheckResult(
                id=f"corr.e2e.worst_sensor",
                title="Worst sensor freshness",
                component=C, severity="warning", status=s,
                current_value=round(worst_age, 1), threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                details=f"Sensor '{worst_sensor}' last data {worst_age:.0f}s ago",
            ))

    # Worst log type freshness
    if os_result and os_result.log_type_freshness:
        worst_age = 0.0
        worst_lt = ""
        for lt_key, ts_val in os_result.log_type_freshness.items():
            if ts_val:
                ts = parse_iso_timestamp(str(ts_val))
                age = seconds_ago(ts)
                if age and age > worst_age:
                    worst_age = age
                    worst_lt = lt_key
        if worst_lt and worst_age > settings.STALE_DATA_THRESHOLD_SECONDS:
            s = Status.YELLOW if worst_age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED
            checks.append(CheckResult(
                id="corr.e2e.worst_log_type",
                title="Worst log type freshness",
                component=C, severity="warning", status=s,
                current_value=round(worst_age, 1),
                details=f"Log type '{worst_lt}' last seen {worst_age:.0f}s ago",
            ))

    # ── 5. PROTOCOL/TLS MISMATCH DETECTION ──────────────────────────
    if dp_result and dp_result.metrics_reachable:
        tls_fail_delta = dp_result.tls_handshake_failure - pd.get("tls_handshake_failure", dp_result.tls_handshake_failure)
        success_delta = dp_result.http_success_requests - pd.get("http_success_requests", dp_result.http_success_requests)

        if tls_fail_delta > settings.MAX_DP_TLS_HANDSHAKE_FAILURE_DELTA:
            # Classify the likely cause
            if success_delta == 0:
                classification = "likely_plaintext_to_tls_port"
                hint = "Vector may be sending HTTP to a TLS-only port. Check Vector sink TLS settings."
            else:
                classification = "partial_tls_failure"
                hint = "Some connections failing TLS. Check CA cert trust chain and certificate validity."

            checks.append(CheckResult(
                id="corr.tls.mismatch",
                title="TLS/Protocol mismatch detected",
                component=C, severity="critical", status=Status.RED,
                current_value=tls_fail_delta,
                details=f"TLS handshake failures Δ={tls_fail_delta:.0f}, success Δ={success_delta:.0f}. Classification: {classification}",
                remediation=hint,
                metadata={"classification": classification},
            ))
        elif not dp_result.metrics_tls_ok:
            checks.append(CheckResult(
                id="corr.tls.dp_verify_fail",
                title="TLS verification failed reaching Data Prepper",
                component=C, severity="critical", status=Status.RED,
                details=f"CA verification failed: {dp_result.metrics_error}",
                remediation="Check CA_CERT_PATH and Data Prepper TLS certificate.",
                metadata={"classification": "certificate_trust_failure"},
            ))

    # ── 6. PIPELINE PRESSURE / BOTTLENECK DETECTION ─────────────────
    if dp_result and dp_result.metrics_reachable:
        bottleneck = None
        buf = dp_result.buffer_usage
        bwf = dp_result.buffer_write_failed - pd.get("buffer_write_failed", dp_result.buffer_write_failed)
        bwt = dp_result.buffer_write_timeouts - pd.get("buffer_write_timeouts", dp_result.buffer_write_timeouts)
        lat = dp_result.os_pipeline_latency
        bf  = dp_result.os_bulk_request_failed - pd.get("os_bulk_request_failed", dp_result.os_bulk_request_failed)

        if buf >= settings.MAX_DP_BUFFER_USAGE_RATIO_CRIT and bwf > 0:
            bottleneck = ("dataprepper_buffer", "Buffer is full and write failures are occurring. OpenSearch sink may be too slow.")
        elif bf > 0 and lat > settings.MAX_DP_PIPELINE_LATENCY_SECONDS_WARN:
            bottleneck = ("dataprepper_sink", "Bulk failures and high latency indicate OpenSearch is rejecting or slow.")
        elif os_result and os_result.cluster and os_result.cluster.get("status") == "red":
            bottleneck = ("opensearch_cluster", "OpenSearch cluster is RED — the sink is unavailable.")
        elif bwt > 0:
            bottleneck = ("dataprepper_buffer", "Buffer write timeouts — upstream pressure or slow sink.")

        if bottleneck:
            loc, explanation = bottleneck
            checks.append(CheckResult(
                id="corr.bottleneck.detected",
                title=f"Pipeline bottleneck: {loc}",
                component=C, severity="critical", status=Status.RED,
                details=explanation,
                remediation=f"Investigate {loc}. " + explanation,
                metadata={"bottleneck_location": loc},
            ))
        else:
            checks.append(CheckResult(
                id="corr.bottleneck.none",
                title="No pipeline bottleneck detected",
                component=C, severity="info", status=Status.GREEN,
                details="Buffer, latency and sink metrics within thresholds",
            ))

    return checks


def _dp_os_scopes_match() -> bool:
    """Return True when the OpenSearch query scope is compatible with DP metrics scope.

    If DP_TO_OS_CORRELATION_INDEX_PATTERN is set it represents the user's explicit
    confirmation that the scope aligns with what Data Prepper counts, so we trust it.

    Otherwise we apply a heuristic: if OPENSEARCH_INDEX_PATTERN contains multiple
    comma-separated patterns (narrowed subset), it likely under-counts compared to
    DP metrics which cover all log types.  A single wildcard pattern (e.g. zeek-*)
    is assumed to cover all log types.
    """
    corr_pattern = (settings.DP_TO_OS_CORRELATION_INDEX_PATTERN or "").strip()
    if corr_pattern:
        # User has explicitly configured a correlation pattern – trust it.
        return True

    os_pattern = (settings.OPENSEARCH_INDEX_PATTERN or "").strip()
    # If the OS pattern is a single wildcard covering all log types (e.g. zeek-*),
    # the scopes likely match.
    if "," not in os_pattern:
        return True

    # Multiple comma-separated patterns – likely a narrowed subset.
    return False
