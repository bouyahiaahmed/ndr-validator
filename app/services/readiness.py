"""
Production readiness scoring service.

Computes a 0-100 score and readiness level from the set of CheckResults
and scrape context flags (SSH enabled, etc.).

Score starts at 100.
  -15 per blocking issue
  -3  per warning
  Clamped to [0, 100].

Level thresholds:
  90-100 → production_ready
  70-89  → production_candidate
  40-69  → lab_ready
  0-39   → not_ready
"""
from __future__ import annotations

import fnmatch
from typing import List

from app.config import settings
from app.models import CheckResult, ProductionReadiness, ReadinessLevel, Status

# ─── Check IDs (or glob patterns) that are BLOCKING when RED ─────────────────
# These map directly to production blocking criteria from the spec.
_BLOCKING_PATTERNS = [
    "vector.*.reachable",           # Vector unreachable
    "dp.metrics.reachable",         # Data Prepper metrics unreachable
    "dp.os.doc_errors",             # DP document errors
    "dp.os.bulk_failed",            # DP bulk failures
    "corr.dp_os.doc_errors",        # DP document errors (correlation view)
    "corr.tls.mismatch",            # TLS/protocol mismatch
    "corr.tls.dp_verify_fail",      # TLS cert trust failure
    "freshness.sensor_liveness.*",  # No recent data from a sensor
    # os.cluster.health RED → blocking; YELLOW (single-node replica) → warning only
]

# Check IDs that are blocking ONLY when Zeek SSH is enabled
_BLOCKING_SSH_PATTERNS = [
    "zeek.*.running",               # Zeek not running (only meaningful with SSH)
]

# Check IDs that produce WARNINGS (never blocking)
_WARNING_PATTERNS = [
    "os.cluster.active_shards",     # Single-node replica shards
    "os.cluster.unassigned",        # Unassigned replicas (single-node)
    "dp.ingest.reachable",          # Health endpoint 404 (yellow)
    "freshness.detection_coverage.*",  # Quiet log type
    "dashboards.*",                 # Dashboards issues
]


def _matches_any(check_id: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatch(check_id, p) for p in patterns)


def compute_readiness(
    checks: List[CheckResult],
    ssh_enabled: bool = False,
) -> ProductionReadiness:
    """Compute the ProductionReadiness from all checks."""
    blocking_issues: List[str] = []
    warnings: List[str] = []
    passed_checks: List[str] = []

    # OpenSearch cluster health is special: RED is blocking, YELLOW is a warning
    for chk in checks:
        cid = chk.id

        # OpenSearch cluster RED → blocking
        if cid == "os.cluster.health" and chk.status == Status.RED:
            blocking_issues.append(f"{chk.title}: {chk.details}")
            continue

        # OpenSearch cluster YELLOW → warning only (single-node replicas)
        if cid == "os.cluster.health" and chk.status == Status.YELLOW:
            warnings.append(f"{chk.title}: {chk.details}")
            continue

        if chk.status == Status.RED:
            if _matches_any(cid, _BLOCKING_PATTERNS):
                blocking_issues.append(f"{chk.title}: {chk.details}")
            elif ssh_enabled and _matches_any(cid, _BLOCKING_SSH_PATTERNS):
                blocking_issues.append(f"{chk.title}: {chk.details}")
            elif _matches_any(cid, _WARNING_PATTERNS):
                warnings.append(f"{chk.title}: {chk.details}")
            elif chk.severity == "critical":
                # Any other critical RED is blocking
                blocking_issues.append(f"{chk.title}: {chk.details}")
            else:
                warnings.append(f"{chk.title}: {chk.details}")

        elif chk.status == Status.YELLOW:
            if _matches_any(cid, _WARNING_PATTERNS):
                warnings.append(f"{chk.title}: {chk.details}")
            elif ssh_enabled and _matches_any(cid, _BLOCKING_SSH_PATTERNS):
                warnings.append(f"{chk.title}: {chk.details}")
            else:
                warnings.append(f"{chk.title}: {chk.details}")

        elif chk.status == Status.GREEN:
            if chk.severity in ("critical", "warning"):
                passed_checks.append(chk.title)

        # UNKNOWN: if SSH is disabled and it's a Zeek check, it's expected
        elif chk.status == Status.UNKNOWN:
            if not ssh_enabled and _matches_any(cid, ["zeek.*"]):
                pass  # expected – SSH probe not enabled
            # else: don't count towards passed or blocking

    # Score computation
    score = 100
    score -= len(blocking_issues) * 15
    score -= len(warnings) * 3
    score = max(0, min(100, score))

    # Readiness level
    if score >= 90 and not blocking_issues:
        level = ReadinessLevel.PRODUCTION_READY
    elif score >= 70 and not blocking_issues:
        level = ReadinessLevel.PRODUCTION_CANDIDATE
    elif score >= 40:
        level = ReadinessLevel.LAB_READY
    else:
        level = ReadinessLevel.NOT_READY

    # Special case: if SSH is disabled, we cannot confirm Zeek status.
    # Cap at production_candidate even if score is 100.
    if not ssh_enabled and level == ReadinessLevel.PRODUCTION_READY:
        level = ReadinessLevel.PRODUCTION_CANDIDATE

    return ProductionReadiness(
        score=score,
        readiness_level=level,
        blocking_issues=blocking_issues,
        warnings=warnings,
        passed_checks=passed_checks,
    )
