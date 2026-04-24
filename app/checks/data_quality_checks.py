"""
Data quality and schema checks – validates document content in OpenSearch.
"""
from __future__ import annotations
import logging
from typing import Dict, List, Optional
from app.config import settings
from app.models import CheckResult, Component, Status
from app.collectors.opensearch_collector import OpenSearchScrapeResult
from app.utils.field_utils import get_field

logger = logging.getLogger(__name__)
C = Component.DATA_QUALITY

# Expected field types for sanity checks
EXPECTED_FIELD_TYPES: Dict[str, str] = {
    "@timestamp": "date",
    "source.ip": "ip",
    "destination.ip": "ip",
}

# Per-log-type expected fields
LOG_TYPE_REQUIRED_FIELDS: Dict[str, List[str]] = {
    "conn": ["source.ip", "destination.ip", "source.port", "destination.port"],
    "dns": ["dns.question.name"],
    "http": ["http.request.method", "http.response.status_code"],
    "ssl": ["tls.version", "tls.server.subject"],
}


def run_data_quality_checks(scrape: OpenSearchScrapeResult) -> List[CheckResult]:
    checks: List[CheckResult] = []

    if not scrape.auth_ok or not scrape.reachable:
        return checks

    # 1. Required fields in field_caps
    if scrape.field_caps_data and "fields" in scrape.field_caps_data:
        fields_map = scrape.field_caps_data["fields"]
        for rf in settings.required_fields_list:
            present = rf in fields_map
            checks.append(CheckResult(
                id=f"dq.field.{_safe_id(rf)}.exists",
                title=f"Required field '{rf}' indexed",
                component=C, severity="warning",
                status=Status.GREEN if present else Status.RED,
                details=f"Field '{rf}' {'found' if present else 'missing'} in field_caps",
                remediation=f"Check Data Prepper transform and index mapping for field '{rf}'." if not present else "",
            ))
            # 2. Field type sanity
            if present and rf in EXPECTED_FIELD_TYPES:
                expected_type = EXPECTED_FIELD_TYPES[rf]
                actual_types = list(fields_map[rf].keys())
                type_ok = expected_type in actual_types
                checks.append(CheckResult(
                    id=f"dq.field.{_safe_id(rf)}.type",
                    title=f"Field '{rf}' type correctness",
                    component=C, severity="warning",
                    status=Status.GREEN if type_ok else Status.YELLOW,
                    current_value=str(actual_types),
                    details=f"Field '{rf}': expected={expected_type}, actual={actual_types}",
                    remediation=f"Mapping drift: field '{rf}' changed type. Check index template." if not type_ok else "",
                ))

    # 3. Recent documents retrievable
    has_recent = scrape.recent_docs is not None and scrape.recent_count > 0
    checks.append(CheckResult(
        id="dq.recent_docs",
        title="Recent documents retrievable",
        component=C, severity="warning",
        status=Status.GREEN if has_recent else Status.YELLOW,
        current_value=scrape.recent_count,
        details=f"{scrape.recent_count} docs in last 5 minutes",
        remediation="Pipeline may be stalled or data is very infrequent." if not has_recent else "",
    ))

    # 4. Required fields non-null in recent sample
    if scrape.recent_docs and "hits" in scrape.recent_docs:
        hits = scrape.recent_docs["hits"].get("hits", [])
        if hits:
            for rf in settings.required_fields_list:
                null_count = 0
                for h in hits:
                    src = h.get("_source", {})
                    val = get_field(src, rf)
                    if val is None or val == "":
                        null_count += 1
                pct_ok = (len(hits) - null_count) / len(hits) * 100 if hits else 0
                s = Status.GREEN if null_count == 0 else (
                    Status.YELLOW if pct_ok >= 50 else Status.RED)
                checks.append(CheckResult(
                    id=f"dq.field.{_safe_id(rf)}.coverage",
                    title=f"Field '{rf}' coverage in recent docs",
                    component=C, severity="warning", status=s,
                    current_value=round(pct_ok, 1),
                    details=f"Field '{rf}' populated in {pct_ok:.0f}% of sampled docs ({len(hits) - null_count}/{len(hits)})",
                    remediation=f"Field '{rf}' has null values. Check enrichment pipeline." if s != Status.GREEN else "",
                ))

    # 5. Required log types present in recent data
    for lt in settings.required_log_types_list:
        present = lt in scrape.log_types_present
        checks.append(CheckResult(
            id=f"dq.log_type.{lt}",
            title=f"Log type '{lt}' present in recent data",
            component=C, severity="warning",
            status=Status.GREEN if present else Status.YELLOW,
            details=f"'{lt}' {'found' if present else 'missing'} in recent aggregation",
            remediation=f"Zeek may not be capturing {lt} or Data Prepper routing is misconfigured." if not present else "",
        ))

    # 6. Required sensors present in recent data
    for sip in settings.sensor_ips:
        name = settings.sensor_display_name(sip)
        present = sip in scrape.sensors_present or name in scrape.sensors_present
        checks.append(CheckResult(
            id=f"dq.sensor.{sip}",
            title=f"Sensor '{name}' present in recent data",
            component=C, severity="critical",
            status=Status.GREEN if present else Status.RED,
            details=f"Sensor '{name}' {'found' if present else 'missing'} in recent data",
            remediation=f"No recent data from sensor '{name}'. Check full pipeline for this sensor." if not present else "",
        ))

    return checks


def _safe_id(field: str) -> str:
    return field.replace(".", "_").replace("@", "at_").replace("-", "_")
