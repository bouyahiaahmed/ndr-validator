"""
Freshness checks – standalone freshness evaluation module.
Called from the evaluator; complements correlation checks with per-component views.
"""
from __future__ import annotations
from typing import Dict, List, Optional
from datetime import datetime, timezone
from app.config import settings
from app.models import CheckResult, Component, Status
from app.utils.time import parse_iso_timestamp, seconds_ago


def run_freshness_checks(
    overall_latest_ts: Optional[str],
    sensor_freshness: Dict[str, Optional[str]],
    log_type_freshness: Dict[str, Optional[str]],
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    C = Component.OPENSEARCH

    # Overall freshness
    if overall_latest_ts:
        ts = parse_iso_timestamp(overall_latest_ts)
        age = seconds_ago(ts)
        if age is not None:
            s = Status.GREEN if age < settings.STALE_DATA_THRESHOLD_SECONDS else (
                Status.YELLOW if age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED)
            checks.append(CheckResult(
                id="freshness.overall",
                title="Overall pipeline data freshness",
                component=C, severity="critical", status=s,
                current_value=round(age, 1),
                threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                details=f"Latest document is {age:.0f}s old",
                remediation="Check pipeline for stalls if age exceeds threshold." if s != Status.GREEN else "",
            ))

    # Per-sensor freshness
    for sensor_key, ts_val in sensor_freshness.items():
        if ts_val is None:
            checks.append(CheckResult(
                id=f"freshness.sensor.{sensor_key}",
                title=f"Freshness for sensor {sensor_key}",
                component=C, severity="warning", status=Status.RED,
                details=f"No recent data from sensor '{sensor_key}'",
                remediation="Check Zeek, Vector, and pipeline for this sensor.",
            ))
            continue
        ts = parse_iso_timestamp(str(ts_val))
        age = seconds_ago(ts)
        if age is not None:
            s = Status.GREEN if age < settings.STALE_DATA_THRESHOLD_SECONDS else (
                Status.YELLOW if age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED)
            checks.append(CheckResult(
                id=f"freshness.sensor.{sensor_key}",
                title=f"Freshness for sensor {sensor_key}",
                component=C, severity="warning", status=s,
                current_value=round(age, 1),
                threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                details=f"Sensor '{sensor_key}' last data {age:.0f}s ago",
            ))

    # Per-log-type freshness
    for lt_key, ts_val in log_type_freshness.items():
        if ts_val is None:
            checks.append(CheckResult(
                id=f"freshness.log_type.{lt_key}",
                title=f"Freshness for log type '{lt_key}'",
                component=C, severity="warning", status=Status.YELLOW,
                details=f"No recent '{lt_key}' data in OpenSearch",
                remediation=f"Check Zeek captures for {lt_key} and pipeline routing.",
            ))
            continue
        ts = parse_iso_timestamp(str(ts_val))
        age = seconds_ago(ts)
        if age is not None:
            s = Status.GREEN if age < settings.STALE_DATA_THRESHOLD_SECONDS else (
                Status.YELLOW if age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED)
            checks.append(CheckResult(
                id=f"freshness.log_type.{lt_key}",
                title=f"Freshness for log type '{lt_key}'",
                component=C, severity="warning", status=s,
                current_value=round(age, 1),
                details=f"Log type '{lt_key}' last seen {age:.0f}s ago",
            ))

    return checks
