"""
Freshness checks – split into two independent concepts:

1. Sensor LIVENESS  – is the sensor alive at all?
   Uses SENSOR_LIVENESS_INDEX_PATTERN (broad, e.g. zeek-*).
   A sensor is alive if ANY log type is fresh in that pattern.
   Example: dhcp/analyzer logs fresh → sensor alive even if conn/http absent.

2. Detection COVERAGE – are the expected detection log types arriving?
   Uses DETECTION_FRESHNESS_INDEX_PATTERN (falls back to OPENSEARCH_INDEX_PATTERN).
   Log types in CONTINUOUS_REQUIRED_LOG_TYPES → RED if stale.
   All other log types → YELLOW if stale (quiet traffic, policy gap, etc.).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.config import settings
from app.models import (
    CheckResult, Component, Diagnosis, Status,
    FIX_ANSIBLE_ZEEK, FIX_ANSIBLE_VECTOR, FIX_TRAFFIC, FIX_VALIDATOR,
)
from app.utils.time import parse_iso_timestamp, seconds_ago

C = Component.OPENSEARCH


# ─── Sensor Liveness ─────────────────────────────────────────────────────────

def run_sensor_liveness_checks(
    sensor_liveness_freshness: Dict[str, Optional[str]],
) -> List[CheckResult]:
    """
    Evaluate sensor liveness from the broad SENSOR_LIVENESS_INDEX_PATTERN.

    A sensor is GREEN if ANY document is fresh, regardless of log type.
    This prevents false "sensor dead" alerts when conn/http are quiet but
    dhcp/analyzer/other logs are flowing.
    """
    checks: List[CheckResult] = []
    pattern = settings.sensor_liveness_pattern
    stale_warn = settings.STALE_DATA_THRESHOLD_SECONDS
    stale_crit = settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS

    # Sensors we expect to see
    all_keys: List[str] = list(
        set(settings.sensor_ips) | set(sensor_liveness_freshness.keys())
    )

    for sensor_key in sorted(all_keys):
        name = settings.sensor_display_name(sensor_key)
        ts_val = sensor_liveness_freshness.get(sensor_key)

        if ts_val is None:
            # No data at all in the liveness pattern → sensor dead
            checks.append(CheckResult(
                id=f"freshness.sensor_liveness.{sensor_key}",
                title=f"Sensor liveness: {name}",
                component=C, severity="critical", sensor=sensor_key,
                status=Status.RED,
                details=(
                    f"No data from sensor '{name}' in index pattern '{pattern}'. "
                    "Sensor may be offline, Zeek not running, or Vector not forwarding."
                ),
                remediation=(
                    "1. SSH to sensor and check: systemctl status zeek vector\n"
                    "2. Check Vector logs for sink errors\n"
                    "3. Verify SENSOR_LIVENESS_INDEX_PATTERN matches your index naming"
                ),
                diagnosis=Diagnosis(
                    problem=f"Sensor '{name}' has no data in OpenSearch liveness pattern",
                    evidence=f"Index pattern '{pattern}': 0 documents from this sensor",
                    impact="This sensor is not contributing to NDR detection. Blind spot in coverage.",
                    probable_causes=[
                        "Zeek process not running on sensor",
                        "Vector not running or misconfigured on sensor",
                        "Network connectivity issue between sensor and Data Prepper",
                        "Index pattern SENSOR_LIVENESS_INDEX_PATTERN does not match actual indices",
                    ],
                    next_steps=[
                        f"SSH to {name}: systemctl status zeek",
                        f"SSH to {name}: systemctl status vector",
                        f"SSH to {name}: journalctl -u vector -n 50",
                        "Check Data Prepper logs for ingestion errors",
                        f"Verify '{pattern}' matches your Zeek index names in OpenSearch",
                    ],
                    fix_location=FIX_ANSIBLE_ZEEK,
                    confidence="high",
                ),
            ))
        else:
            ts = parse_iso_timestamp(str(ts_val))
            age = seconds_ago(ts)
            if age is not None:
                if age < stale_warn:
                    s = Status.GREEN
                    diag = None
                elif age < stale_crit:
                    s = Status.YELLOW
                    diag = Diagnosis(
                        problem=f"Sensor '{name}' data is becoming stale",
                        evidence=f"Last document from '{name}' in '{pattern}' is {age:.0f}s old (warn threshold: {stale_warn}s)",
                        impact="Detection may lag real-time traffic. Alert freshness degraded.",
                        probable_causes=[
                            "Zeek capturing traffic but Vector sink lagging",
                            "Temporary network congestion between sensor and Data Prepper",
                            "Data Prepper buffer pressure causing delays",
                        ],
                        next_steps=[
                            f"Check Vector on {name}: journalctl -u vector -n 20",
                            "Check Data Prepper buffer metrics in /status",
                            "Monitor if age recovers on next scrape cycle",
                        ],
                        fix_location=FIX_ANSIBLE_VECTOR,
                        confidence="medium",
                    )
                else:
                    s = Status.RED
                    diag = Diagnosis(
                        problem=f"Sensor '{name}' is critically stale",
                        evidence=f"Last document from '{name}' is {age:.0f}s old (critical threshold: {stale_crit}s)",
                        impact="This sensor is effectively blind. NDR coverage gap.",
                        probable_causes=[
                            "Zeek stopped writing logs",
                            "Vector failed or stopped forwarding",
                            "Data Prepper pipeline stalled",
                        ],
                        next_steps=[
                            f"SSH to {name}: systemctl status zeek vector",
                            f"SSH to {name}: ls -la {settings.ZEEK_LOG_DIR}",
                            "Check Vector and Data Prepper logs for errors",
                        ],
                        fix_location=FIX_ANSIBLE_ZEEK,
                        confidence="high",
                    )

                checks.append(CheckResult(
                    id=f"freshness.sensor_liveness.{sensor_key}",
                    title=f"Sensor liveness: {name}",
                    component=C, severity="critical", sensor=sensor_key, status=s,
                    current_value=round(age, 1),
                    threshold=stale_warn,
                    details=f"Sensor '{name}' last data {age:.0f}s ago (pattern: {pattern})",
                    remediation=(
                        "Check Zeek, Vector, and pipeline for this sensor."
                        if s != Status.GREEN else ""
                    ),
                    diagnosis=diag,
                ))

    return checks


# ─── Detection Coverage ───────────────────────────────────────────────────────

def run_detection_coverage_checks(
    log_type_freshness: Dict[str, Optional[str]],
) -> List[CheckResult]:
    """
    Evaluate detection coverage from DETECTION_FRESHNESS_INDEX_PATTERN.

    Log types in CONTINUOUS_REQUIRED_LOG_TYPES → RED if stale (blocking gap).
    All other required log types → YELLOW if stale.
    Unknown log types being stale → YELLOW with traffic-quiet explanation.
    """
    checks: List[CheckResult] = []
    pattern = settings.detection_freshness_pattern
    stale_warn = settings.STALE_DATA_THRESHOLD_SECONDS
    stale_crit = settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS
    continuous_required = set(settings.continuous_required_log_types_list)

    # All required log types from config
    for lt in settings.required_log_types_list:
        ts_val = log_type_freshness.get(lt)
        is_continuous = lt in continuous_required

        if ts_val is None:
            # Absent from OpenSearch
            s = Status.RED if is_continuous else Status.YELLOW
            sev = "critical" if is_continuous else "warning"
            checks.append(CheckResult(
                id=f"freshness.detection_coverage.{lt}",
                title=f"Detection coverage: {lt} log type",
                component=C, severity=sev, status=s,
                details=f"No '{lt}' data in detection pattern '{pattern}'",
                remediation=(
                    f"Check Zeek policy for {lt}, Vector routing, and Data Prepper pipeline."
                ),
                diagnosis=Diagnosis(
                    problem=f"No '{lt}' log type data in OpenSearch",
                    evidence=f"Index pattern '{pattern}': 0 '{lt}' documents found",
                    impact=(
                        f"{'CRITICAL: ' if is_continuous else ''}Detection coverage gap for {lt} traffic. "
                        f"{'Alerts depending on this log type will not fire.' if is_continuous else 'May indicate quiet traffic or policy gap.'}"
                    ),
                    probable_causes=[
                        f"No network traffic generating {lt} events on monitored interfaces",
                        f"Zeek policy does not enable {lt} logging (check local.zeek)",
                        "Vector filter dropping this log type before sending to Data Prepper",
                        f"Data Prepper routing not indexing {lt} to this index pattern",
                    ],
                    next_steps=[
                        f"Generate test {lt} traffic (e.g. curl http://... for http, dig for dns)",
                        f"On sensor: ls {settings.ZEEK_LOG_DIR}/{lt}.log",
                        "Check Vector config for drop/filter transforms on this log type",
                        "Check Data Prepper pipeline config for routing rules",
                    ],
                    fix_location=FIX_TRAFFIC,
                    confidence="low",  # Could be traffic, policy, or pipeline
                ),
            ))
            continue

        ts = parse_iso_timestamp(str(ts_val))
        age = seconds_ago(ts)
        if age is not None:
            if age < stale_warn:
                s = Status.GREEN
                diag = None
            elif age < stale_crit:
                s = Status.YELLOW
                diag = Diagnosis(
                    problem=f"Detection log type '{lt}' is becoming stale",
                    evidence=f"Last '{lt}' document is {age:.0f}s old (warn threshold: {stale_warn}s)",
                    impact="Detection coverage for this log type may be lagging.",
                    probable_causes=[
                        "Reduced network traffic for this protocol",
                        "Vector sink lag or buffer pressure",
                        "Data Prepper pipeline latency",
                    ],
                    next_steps=[
                        "Generate test traffic for this protocol",
                        "Check sensor Vector logs for sink backpressure",
                    ],
                    fix_location=FIX_TRAFFIC,
                    confidence="low",
                )
            else:
                # Critically stale
                s = Status.RED if is_continuous else Status.YELLOW
                sev_note = "CRITICAL gap" if is_continuous else "Coverage gap"
                diag = Diagnosis(
                    problem=f"{sev_note}: '{lt}' log type critically stale",
                    evidence=f"Last '{lt}' document is {age:.0f}s old (critical threshold: {stale_crit}s)",
                    impact=(
                        f"{'Blocking: ' if is_continuous else ''}Detection for {lt} traffic has stopped. "
                        "Possible sensor, policy, or pipeline issue."
                    ),
                    probable_causes=[
                        "Zeek no longer writing this log type (interface issue or policy change)",
                        "Vector filter change that started dropping this type",
                        "Data Prepper routing regression",
                        "No traffic for extended period (lab environment)",
                    ],
                    next_steps=[
                        f"Generate {lt} test traffic and wait one scrape interval",
                        f"On sensor: tail -f {settings.ZEEK_LOG_DIR}/{lt}.log",
                        "Review recent Zeek policy or Vector config changes",
                        "Check correlation checks in /checks/actionable",
                    ],
                    fix_location=FIX_ANSIBLE_ZEEK,
                    confidence="medium",
                )

            checks.append(CheckResult(
                id=f"freshness.detection_coverage.{lt}",
                title=f"Detection coverage: {lt} log type",
                component=C,
                severity="critical" if is_continuous and s == Status.RED else "warning",
                status=s,
                current_value=round(age, 1),
                threshold=stale_warn,
                details=f"Log type '{lt}' last seen {age:.0f}s ago (pattern: {pattern})",
                diagnosis=diag,
            ))

    return checks


# ─── Legacy overall freshness (kept for backward compat with rate computation) ─

def run_freshness_checks(
    overall_latest_ts: Optional[str],
    sensor_freshness: Dict[str, Optional[str]],
    log_type_freshness: Dict[str, Optional[str]],
) -> List[CheckResult]:
    """
    Legacy entry point – retained for backward compatibility.
    Delegates to the new split functions; the evaluator now calls them directly.
    """
    checks: List[CheckResult] = []
    # Overall freshness
    if overall_latest_ts:
        ts = parse_iso_timestamp(overall_latest_ts)
        age = seconds_ago(ts)
        if age is not None:
            s = (
                Status.GREEN if age < settings.STALE_DATA_THRESHOLD_SECONDS
                else Status.YELLOW if age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS
                else Status.RED
            )
            checks.append(CheckResult(
                id="freshness.overall",
                title="Overall pipeline data freshness",
                component=C, severity="critical", status=s,
                current_value=round(age, 1),
                threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                details=f"Latest document is {age:.0f}s old",
                remediation="Check pipeline for stalls if age exceeds threshold." if s != Status.GREEN else "",
            ))
    return checks
