"""
Tests for status aggregation.
Covers: overall status computation, urgent findings ranking, component rollup.
"""
import pytest
from datetime import datetime, timezone
from app.models import (
    CheckResult, Component, ComponentStatus, Status, StatusSummary,
    PipelineRates, UrgentFinding, SensorStatus,
)
from app.services.evaluator import (
    _build_component_statuses, _compute_overall_status, _top_urgent,
)


def _check(id, comp, status, severity="warning", title=None, details="", remediation=""):
    return CheckResult(
        id=id, title=title or id, component=comp, severity=severity,
        status=status, details=details, remediation=remediation,
    )


def test_overall_green_when_all_green():
    comps = [
        ComponentStatus(name=Component.ZEEK, status=Status.GREEN),
        ComponentStatus(name=Component.VECTOR, status=Status.GREEN),
    ]
    assert _compute_overall_status(comps) == Status.GREEN


def test_overall_yellow_when_any_yellow():
    comps = [
        ComponentStatus(name=Component.ZEEK, status=Status.GREEN),
        ComponentStatus(name=Component.VECTOR, status=Status.YELLOW),
    ]
    assert _compute_overall_status(comps) == Status.YELLOW


def test_overall_red_when_any_red():
    comps = [
        ComponentStatus(name=Component.ZEEK, status=Status.GREEN),
        ComponentStatus(name=Component.VECTOR, status=Status.YELLOW),
        ComponentStatus(name=Component.OPENSEARCH, status=Status.RED),
    ]
    assert _compute_overall_status(comps) == Status.RED


def test_red_overrides_yellow():
    comps = [
        ComponentStatus(name=Component.ZEEK, status=Status.YELLOW),
        ComponentStatus(name=Component.VECTOR, status=Status.RED),
        ComponentStatus(name=Component.OPENSEARCH, status=Status.YELLOW),
    ]
    assert _compute_overall_status(comps) == Status.RED


def test_component_rollup_worst_status():
    checks = [
        _check("a", Component.VECTOR, Status.GREEN),
        _check("b", Component.VECTOR, Status.YELLOW),
        _check("c", Component.VECTOR, Status.RED, severity="critical"),
    ]
    comps = _build_component_statuses(checks, [], [])
    vec = next(c for c in comps if c.name == Component.VECTOR)
    assert vec.status == Status.RED


def test_component_all_green_stays_green():
    checks = [
        _check("a", Component.ZEEK, Status.GREEN),
        _check("b", Component.ZEEK, Status.GREEN),
    ]
    comps = _build_component_statuses(checks, [], [])
    zeek = next(c for c in comps if c.name == Component.ZEEK)
    assert zeek.status == Status.GREEN


def test_top_urgent_ranks_red_before_yellow():
    checks = [
        _check("y1", Component.VECTOR, Status.YELLOW, severity="critical"),
        _check("r1", Component.OPENSEARCH, Status.RED, severity="warning"),
        _check("y2", Component.ZEEK, Status.YELLOW, severity="warning"),
        _check("r2", Component.DATAPREPPER, Status.RED, severity="critical"),
    ]
    findings = _top_urgent(checks, 10)
    statuses = [f.status for f in findings]
    # All reds come before yellows
    first_yellow_idx = next((i for i, s in enumerate(statuses) if s == Status.YELLOW), len(statuses))
    last_red_idx = max((i for i, s in enumerate(statuses) if s == Status.RED), default=-1)
    assert last_red_idx < first_yellow_idx


def test_top_urgent_limited_to_n():
    checks = [_check(f"c{i}", Component.VECTOR, Status.RED) for i in range(20)]
    findings = _top_urgent(checks, 10)
    assert len(findings) == 10


def test_top_urgent_green_not_included():
    checks = [
        _check("g1", Component.VECTOR, Status.GREEN),
        _check("g2", Component.ZEEK, Status.GREEN),
    ]
    findings = _top_urgent(checks, 10)
    assert findings == []


def test_status_summary_serializable():
    summary = StatusSummary(
        timestamp=datetime.now(timezone.utc),
        config_fingerprint="abcd1234",
        overall_status=Status.GREEN,
        components=[ComponentStatus(name=Component.ZEEK, status=Status.GREEN)],
        sensors=[],
        checks=[_check("x", Component.ZEEK, Status.GREEN)],
        urgent_findings=[],
        rates=PipelineRates(),
    )
    d = summary.model_dump()
    assert d["overall_status"] == "green"
    assert d["config_fingerprint"] == "abcd1234"
    assert len(d["checks"]) == 1
