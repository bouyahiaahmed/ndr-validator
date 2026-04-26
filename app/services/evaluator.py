"""
Evaluator service – orchestrates all collectors and checks into a StatusSummary.
This is the main scrape-cycle entry point called by the scheduler.
"""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Dict, List, Optional

from app.config import settings
from app.models import (
    CheckResult, Component, ComponentStatus, HistoryRecord,
    MetricSnapshot, PipelineRates, SensorStatus, Status, StatusSummary, UrgentFinding,
)
from app.collectors.vector_collector import scrape_all_sensors, get_flat_metrics as vec_flat
from app.collectors.dataprepper_collector import scrape_dataprepper, get_flat_metrics as dp_flat
from app.collectors.opensearch_collector import scrape_opensearch, get_flat_metrics as os_flat
from app.collectors.dashboards_collector import scrape_dashboards
from app.collectors.zeek_collector import probe_all_sensors
from app.checks.vector_checks import run_vector_checks
from app.checks.dataprepper_checks import run_dataprepper_checks
from app.checks.opensearch_checks import run_opensearch_checks
from app.checks.dashboards_checks import run_dashboards_checks
from app.checks.zeek_checks import run_zeek_checks
from app.checks.data_quality_checks import run_data_quality_checks
from app.checks.correlation_checks import run_correlation_checks
from app.checks.freshness_checks import run_sensor_liveness_checks, run_detection_coverage_checks
from app.services.readiness import compute_readiness
from app import db
from app import metrics as prom
from app.utils.time import utcnow

logger = logging.getLogger(__name__)

# In-memory cache of the latest StatusSummary
_latest_summary: Optional[StatusSummary] = None
_scheduler_ready: bool = False


def get_latest_summary() -> Optional[StatusSummary]:
    return _latest_summary


def is_scheduler_ready() -> bool:
    return _scheduler_ready


def mark_scheduler_ready() -> None:
    global _scheduler_ready
    _scheduler_ready = True


async def run_scrape_cycle() -> StatusSummary:
    """Run a full scrape and evaluation cycle. Returns the StatusSummary."""
    global _latest_summary
    start = time.monotonic()
    all_checks: List[CheckResult] = []

    # ── Load previous snapshots for delta computation ────────────────
    prev_vector: Dict[str, Dict[str, float]] = {}
    for sip in settings.sensor_ips:
        snap = await db.get_latest_snapshot(f"vector:{sip}")
        if snap:
            prev_vector[sip] = snap.metrics

    prev_dp_snap = await db.get_latest_snapshot("dataprepper")
    prev_dp = prev_dp_snap.metrics if prev_dp_snap else {}

    prev_os_snap = await db.get_latest_snapshot("opensearch")
    prev_os = prev_os_snap.metrics if prev_os_snap else {}

    # ── Scrape all components concurrently ───────────────────────────
    (
        vector_results,
        dp_result,
        os_result,
        dash_result,
        zeek_results,
    ) = await asyncio.gather(
        scrape_all_sensors(),
        scrape_dataprepper(),
        scrape_opensearch(),
        scrape_dashboards(),
        probe_all_sensors(),
        return_exceptions=False,
    )

    # ── Run checks per component ─────────────────────────────────────

    # Vector checks (per sensor)
    peer_sent: Dict[str, float] = {
        vr.sensor_ip: vr.sent_events for vr in vector_results
    }
    vector_sensor_checks: Dict[str, List[CheckResult]] = {}
    for vr in vector_results:
        vchks = run_vector_checks(vr, prev_vector.get(vr.sensor_ip), peer_sent)
        vector_sensor_checks[vr.sensor_ip] = vchks
        all_checks.extend(vchks)

    # Data Prepper checks
    dp_checks = run_dataprepper_checks(dp_result, prev_dp)
    all_checks.extend(dp_checks)

    # OpenSearch checks
    os_checks = run_opensearch_checks(os_result, prev_os)
    all_checks.extend(os_checks)

    # Dashboards checks
    os_up = os_result.reachable and os_result.auth_ok
    dash_checks = run_dashboards_checks(dash_result, opensearch_up=os_up)
    all_checks.extend(dash_checks)

    # Zeek checks
    zeek_sensor_checks: Dict[str, List[CheckResult]] = {}
    for zr in zeek_results:
        zchks = run_zeek_checks(zr)
        zeek_sensor_checks[zr.sensor_ip] = zchks
        all_checks.extend(zchks)

    # Data quality checks
    dq_checks = run_data_quality_checks(os_result)
    all_checks.extend(dq_checks)

    # Correlation checks
    corr_checks = run_correlation_checks(
        vector_results, dp_result, os_result, zeek_results,
        prev_vector, prev_dp, prev_os,
    )
    all_checks.extend(corr_checks)

    # Split freshness checks
    liveness_checks = run_sensor_liveness_checks(os_result.sensor_liveness_freshness)
    all_checks.extend(liveness_checks)
    coverage_checks = run_detection_coverage_checks(os_result.log_type_freshness)
    all_checks.extend(coverage_checks)

    # Production readiness score
    readiness = compute_readiness(all_checks, ssh_enabled=settings.ENABLE_SENSOR_SSH)

    # ── Persist snapshots ────────────────────────────────────────────
    for vr in vector_results:
        await db.save_snapshot(MetricSnapshot(
            source=f"vector:{vr.sensor_ip}", metrics=vec_flat(vr),
        ))
    await db.save_snapshot(MetricSnapshot(source="dataprepper", metrics=dp_flat(dp_result)))
    await db.save_snapshot(MetricSnapshot(source="opensearch", metrics=os_flat(os_result)))

    # ── Build component statuses ─────────────────────────────────────
    component_statuses = _build_component_statuses(
        all_checks, vector_results, zeek_results,
    )

    # ── Build sensor statuses ────────────────────────────────────────
    sensor_statuses = _build_sensor_statuses(
        vector_sensor_checks, zeek_sensor_checks, vector_results,
    )

    # ── Overall status ───────────────────────────────────────────────
    overall = _compute_overall_status(component_statuses)

    # ── Top urgent findings ──────────────────────────────────────────
    urgent = _top_urgent(all_checks, 10)

    # ── Pipeline rates ───────────────────────────────────────────────
    rates = _compute_rates(vector_results, dp_result, os_result, prev_vector, prev_dp, prev_os)

    # ── Build summary ────────────────────────────────────────────────
    summary = StatusSummary(
        timestamp=utcnow(),
        config_fingerprint=settings.config_fingerprint,
        overall_status=overall,
        components=component_statuses,
        sensors=sensor_statuses,
        checks=all_checks,
        urgent_findings=urgent,
        rates=rates,
        readiness=readiness,
    )
    _latest_summary = summary

    # ── Persist history ──────────────────────────────────────────────
    comp_status_map = {cs.name.value: cs.status.value for cs in component_statuses}
    red_c = sum(1 for c in all_checks if c.status == Status.RED)
    yel_c = sum(1 for c in all_checks if c.status == Status.YELLOW)
    grn_c = sum(1 for c in all_checks if c.status == Status.GREEN)
    await db.save_history(HistoryRecord(
        overall_status=overall,
        component_statuses=comp_status_map,
        check_count=len(all_checks),
        red_count=red_c,
        yellow_count=yel_c,
        green_count=grn_c,
    ))

    # ── Update Prometheus metrics ────────────────────────────────────
    prom.overall_status_gauge.set(prom.status_to_int(overall.value))
    prom.checks_total_gauge.set(len(all_checks))
    prom.checks_red_gauge.set(red_c)
    prom.checks_yellow_gauge.set(yel_c)
    prom.checks_green_gauge.set(grn_c)
    for cs in component_statuses:
        prom.component_status_gauge.labels(component=cs.name.value).set(
            prom.status_to_int(cs.status.value)
        )
    for chk in all_checks:
        prom.check_status_gauge.labels(
            check_id=chk.id, component=chk.component.value
        ).set(prom.status_to_int(chk.status.value))
    if rates.vector_to_dp_drop_percent is not None:
        prom.vector_to_dp_drop_percent.set(rates.vector_to_dp_drop_percent)
    if rates.dp_to_os_drop_percent is not None:
        prom.dp_to_os_drop_percent.set(rates.dp_to_os_drop_percent)
    if rates.overall_freshness_seconds is not None:
        prom.pipeline_freshness_seconds.set(rates.overall_freshness_seconds)

    duration = time.monotonic() - start
    prom.scrape_total.inc()
    prom.scrape_duration_seconds.observe(duration)
    if red_c > 0:
        prom.scrape_errors_total.inc()

    logger.info(
        "Scrape cycle complete in %.2fs: overall=%s red=%d yellow=%d green=%d",
        duration, overall.value, red_c, yel_c, grn_c,
    )
    return summary


def _build_component_statuses(
    all_checks: List[CheckResult],
    vector_results: list,
    zeek_results: list,
) -> List[ComponentStatus]:
    comps: Dict[Component, List[CheckResult]] = {c: [] for c in Component}
    for chk in all_checks:
        comps[chk.component].append(chk)

    result = []
    for comp, chks in comps.items():
        if not chks:
            result.append(ComponentStatus(name=comp, status=Status.UNKNOWN))
            continue
        worst = Status.GREEN
        for c in chks:
            worst = Status.worst(worst, c.status)
        reds = [c for c in chks if c.status == Status.RED]
        summary = f"{len(reds)} critical issue(s)" if reds else f"{len(chks)} checks OK"
        result.append(ComponentStatus(name=comp, status=worst, checks=chks, summary=summary))
    return result


def _build_sensor_statuses(
    vector_sensor_checks: Dict[str, List[CheckResult]],
    zeek_sensor_checks: Dict[str, List[CheckResult]],
    vector_results: list,
) -> List[SensorStatus]:
    all_sensors = set(settings.sensor_ips)
    for vr in vector_results:
        all_sensors.add(vr.sensor_ip)

    result = []
    for sip in sorted(all_sensors):
        chks = []
        chks.extend(vector_sensor_checks.get(sip, []))
        chks.extend(zeek_sensor_checks.get(sip, []))
        worst = Status.UNKNOWN
        for c in chks:
            worst = Status.worst(worst, c.status)
        if worst == Status.UNKNOWN and chks:
            worst = Status.GREEN
        result.append(SensorStatus(
            sensor_ip=sip,
            display_name=settings.sensor_display_name(sip),
            status=worst,
            checks=chks,
        ))
    return result


def _compute_overall_status(component_statuses: List[ComponentStatus]) -> Status:
    worst = Status.GREEN
    for cs in component_statuses:
        worst = Status.worst(worst, cs.status)
    return worst


def _top_urgent(checks: List[CheckResult], n: int) -> List[UrgentFinding]:
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    status_order = {Status.RED: 0, Status.YELLOW: 1, Status.GREEN: 2, Status.UNKNOWN: 3}
    bad = [c for c in checks if c.status in (Status.RED, Status.YELLOW)]
    bad.sort(key=lambda c: (
        status_order.get(c.status, 9),
        severity_order.get(c.severity, 9),
    ))
    return [
        UrgentFinding(
            rank=i + 1, check_id=c.id, title=c.title, component=c.component,
            status=c.status, details=c.details, remediation=c.remediation, sensor=c.sensor,
        )
        for i, c in enumerate(bad[:n])
    ]


def _compute_rates(
    vector_results, dp_result, os_result, prev_vector, prev_dp, prev_os
) -> PipelineRates:
    from app.utils.time import parse_iso_timestamp, seconds_ago
    rates = PipelineRates()

    # Vector sent delta
    for vr in vector_results:
        prev = prev_vector.get(vr.sensor_ip, {})
        d = max(0, vr.sent_events - prev.get("sent_events", vr.sent_events))
        rates.vector_total_sent_delta += d

    # DP processed delta
    rates.dp_records_processed_delta = max(
        0, dp_result.records_processed - prev_dp.get("records_processed", dp_result.records_processed)
    )
    rates.dp_records_in_opensearch_delta = max(
        0, dp_result.os_records_in - prev_dp.get("os_records_in", dp_result.os_records_in)
    )

    # OS doc count delta – use correlation pattern count when configured
    corr_pattern = (settings.DP_TO_OS_CORRELATION_INDEX_PATTERN or "").strip()
    if corr_pattern and os_result.dp_corr_total_count > 0:
        prev_count = prev_os.get("dp_corr_total_count", os_result.dp_corr_total_count)
        rates.os_doc_count_delta = max(0, os_result.dp_corr_total_count - prev_count)
    else:
        prev_count = prev_os.get("total_count", os_result.total_count)
        rates.os_doc_count_delta = max(0, os_result.total_count - prev_count)

    # Drop percentages
    if rates.vector_total_sent_delta > 0 and rates.dp_records_processed_delta >= 0:
        d = (rates.vector_total_sent_delta - rates.dp_records_processed_delta) / rates.vector_total_sent_delta * 100
        rates.vector_to_dp_drop_percent = max(0, round(d, 2))
    if rates.dp_records_in_opensearch_delta > 0 and rates.os_doc_count_delta >= 0:
        d = (rates.dp_records_in_opensearch_delta - rates.os_doc_count_delta) / rates.dp_records_in_opensearch_delta * 100
        rates.dp_to_os_drop_percent = max(0, round(d, 2))

    # Freshness
    if os_result.overall_latest_ts:
        ts = parse_iso_timestamp(str(os_result.overall_latest_ts))
        rates.overall_freshness_seconds = seconds_ago(ts)

    # Worst sensor
    worst_age = 0.0
    worst_name = None
    for k, ts_val in os_result.sensor_freshness.items():
        if ts_val:
            ts = parse_iso_timestamp(str(ts_val))
            age = seconds_ago(ts)
            if age and age > worst_age:
                worst_age = age
                worst_name = k
    if worst_name:
        rates.worst_sensor_freshness_seconds = worst_age
        rates.worst_sensor_name = worst_name

    # Worst log type
    worst_age = 0.0
    worst_lt = None
    for k, ts_val in os_result.log_type_freshness.items():
        if ts_val:
            ts = parse_iso_timestamp(str(ts_val))
            age = seconds_ago(ts)
            if age and age > worst_age:
                worst_age = age
                worst_lt = k
    if worst_lt:
        rates.worst_log_type_freshness_seconds = worst_age
        rates.worst_log_type_name = worst_lt

    rates.dp_pipeline_latency_seconds = dp_result.os_pipeline_latency
    rates.dp_buffer_usage_ratio = dp_result.buffer_usage
    rates.os_search_latency_ms = os_result.search_latency_ms

    return rates
