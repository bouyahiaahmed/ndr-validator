"""
OpenSearch checks – evaluate cluster, index, and search results.
"""
from __future__ import annotations
from typing import Dict, List, Optional
from app.config import settings
from app.models import CheckResult, Component, Status
from app.collectors.opensearch_collector import OpenSearchScrapeResult
from app.utils.time import parse_iso_timestamp, seconds_ago

C = Component.OPENSEARCH

def run_opensearch_checks(
    scrape: OpenSearchScrapeResult,
    prev: Optional[Dict[str, float]] = None,
) -> List[CheckResult]:
    checks: List[CheckResult] = []
    p = prev or {}

    # 1. Reachable
    checks.append(CheckResult(
        id="os.reachable", title="OpenSearch reachable", component=C, severity="critical",
        status=Status.GREEN if scrape.reachable else Status.RED,
        details=scrape.error or "Reachable",
        remediation="Check OpenSearch host, port, and network connectivity.",
    ))
    if not scrape.reachable:
        return checks

    # 2. TLS
    checks.append(CheckResult(
        id="os.tls", title="OpenSearch TLS verification", component=C, severity="critical",
        status=Status.GREEN if scrape.tls_ok else Status.RED,
        details="TLS OK" if scrape.tls_ok else (scrape.error or "TLS failed"),
        remediation="Check CA_CERT_PATH and OpenSearch TLS configuration.",
    ))
    # 3. Auth
    checks.append(CheckResult(
        id="os.auth", title="OpenSearch authentication", component=C, severity="critical",
        status=Status.GREEN if scrape.auth_ok else Status.RED,
        details="Auth OK" if scrape.auth_ok else "Auth failed",
        remediation="Verify OPENSEARCH_USERNAME/PASSWORD.",
    ))
    if not scrape.auth_ok:
        return checks

    # 4. Cluster health
    if scrape.cluster:
        cs = scrape.cluster.get("status", "unknown")
        s = {"green": Status.GREEN, "yellow": Status.YELLOW, "red": Status.RED}.get(cs, Status.UNKNOWN)
        checks.append(CheckResult(
            id="os.cluster.health", title="OpenSearch cluster health", component=C,
            severity="critical", status=s, current_value=cs,
            details=f"Cluster status: {cs}",
            remediation="Check unassigned shards and node availability." if s != Status.GREEN else "",
        ))
        # 5. Nodes
        n_nodes = scrape.cluster.get("number_of_nodes", 0)
        checks.append(CheckResult(
            id="os.cluster.nodes", title="OpenSearch node count", component=C,
            severity="warning", status=Status.GREEN if n_nodes > 0 else Status.RED,
            current_value=n_nodes, details=f"Nodes: {n_nodes}",
        ))
        # 6. Active shards percent
        asp = scrape.cluster.get("active_shards_percent_as_number", 0)
        unassigned = scrape.cluster.get("unassigned_shards", 0)
        active_primary = scrape.cluster.get("active_primary_shards", -1)
        # Single-node clusters cannot assign replica shards; this is expected.
        # Only escalate to RED if primary shards are unassigned.
        single_node_replica_issue = (
            n_nodes == 1
            and unassigned > 0
            and active_primary > 0  # primaries ARE assigned, only replicas aren't
        )
        if single_node_replica_issue:
            shard_status = Status.YELLOW
            shard_detail = (
                f"Active shards: {asp:.1f}% – single-node cluster has "
                f"{unassigned} unassigned replica shard(s) (expected)."
            )
            shard_remediation = (
                "Single-node lab: run 'PUT zeek-*/_settings {\"number_of_replicas\": 0}' "
                "to resolve replica assignment and reach 100% active shards."
            )
        else:
            shard_status = Status.GREEN if asp >= 100 else (
                Status.YELLOW if asp >= 80 else Status.RED)
            shard_detail = f"Active shards: {asp:.1f}%"
            shard_remediation = "Check unassigned shards and node availability." if shard_status != Status.GREEN else ""
        checks.append(CheckResult(
            id="os.cluster.active_shards", title="OpenSearch active shards %", component=C,
            severity="warning", status=shard_status,
            current_value=asp, details=shard_detail,
            remediation=shard_remediation,
        ))
        # 7. Unassigned shards
        us = scrape.cluster.get("unassigned_shards", 0)
        checks.append(CheckResult(
            id="os.cluster.unassigned", title="OpenSearch unassigned shards", component=C,
            severity="warning",
            status=Status.GREEN if us == 0 else (Status.YELLOW if single_node_replica_issue else Status.YELLOW),
            current_value=us, details=f"Unassigned shards: {us}",
            remediation=shard_remediation if us > 0 else "",
        ))

    # 8. Node heap/disk
    if scrape.nodes:
        for node in scrape.nodes:
            nname = node.get("name", "unknown")
            heap = node.get("heap.percent")
            if heap is not None:
                try:
                    hp = float(heap)
                    checks.append(CheckResult(
                        id=f"os.node.{nname}.heap", title=f"OS node {nname} heap", component=C,
                        severity="warning",
                        status=Status.GREEN if hp < settings.HIGH_HEAP_THRESHOLD_PERCENT else Status.YELLOW,
                        current_value=hp, threshold=settings.HIGH_HEAP_THRESHOLD_PERCENT,
                        details=f"Heap: {hp}%",
                    ))
                except (ValueError, TypeError):
                    pass

    # 9. Indices exist
    has_indices = scrape.indices and len(scrape.indices) > 0
    checks.append(CheckResult(
        id="os.indices.exist", title="Zeek indices exist", component=C,
        severity="critical", status=Status.GREEN if has_indices else Status.RED,
        current_value=len(scrape.indices) if scrape.indices else 0,
        details=f"{len(scrape.indices)} indices found" if has_indices else "No zeek-* indices",
        remediation="Check Data Prepper OpenSearch sink and index template." if not has_indices else "",
    ))

    # 10. Doc count growth
    prev_count = p.get("total_count", 0)
    if prev_count > 0:
        delta = scrape.total_count - prev_count
        checks.append(CheckResult(
            id="os.docs.growth", title="OpenSearch doc count growth", component=C,
            severity="warning",
            status=Status.GREEN if delta > 0 else (Status.YELLOW if delta == 0 else Status.GREEN),
            current_value=delta, details=f"Doc count delta: {delta}",
            remediation="Possible indexing stall." if delta == 0 else "",
        ))

    # 11. Search latency
    sl = scrape.search_latency_ms
    checks.append(CheckResult(
        id="os.search.latency", title="OpenSearch search latency", component=C,
        severity="warning",
        status=Status.GREEN if sl < settings.MAX_OS_SEARCH_LATENCY_MS_WARN else (
            Status.YELLOW if sl < settings.MAX_OS_SEARCH_LATENCY_MS_CRIT else Status.RED),
        current_value=sl, threshold=settings.MAX_OS_SEARCH_LATENCY_MS_WARN,
        details=f"Search latency: {sl:.0f}ms",
    ))

    # 12. Overall freshness
    if scrape.overall_latest_ts:
        ts = parse_iso_timestamp(scrape.overall_latest_ts)
        age = seconds_ago(ts)
        if age is not None:
            s = Status.GREEN if age < settings.STALE_DATA_THRESHOLD_SECONDS else (
                Status.YELLOW if age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED)
            checks.append(CheckResult(
                id="os.freshness.overall", title="OpenSearch data freshness", component=C,
                severity="critical", status=s, current_value=age,
                threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                details=f"Latest doc age: {age:.0f}s",
                remediation="Pipeline may be stalled or lagging." if s != Status.GREEN else "",
            ))

    # 13. Per-sensor freshness
    for sensor_ip in settings.sensor_ips:
        name = settings.sensor_display_name(sensor_ip)
        ts_str = scrape.sensor_freshness.get(sensor_ip) or scrape.sensor_freshness.get(name)
        if ts_str:
            ts = parse_iso_timestamp(str(ts_str))
            age = seconds_ago(ts)
            if age is not None:
                s = Status.GREEN if age < settings.STALE_DATA_THRESHOLD_SECONDS else (
                    Status.YELLOW if age < settings.CRITICAL_STALE_DATA_THRESHOLD_SECONDS else Status.RED)
                checks.append(CheckResult(
                    id=f"os.freshness.sensor.{sensor_ip}", title=f"Data freshness for {name}",
                    component=C, severity="warning", status=s, sensor=sensor_ip,
                    current_value=age, threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                    details=f"Latest doc age: {age:.0f}s",
                ))
        elif sensor_ip in settings.sensor_ips:
            checks.append(CheckResult(
                id=f"os.freshness.sensor.{sensor_ip}", title=f"Data freshness for {name}",
                component=C, severity="critical", status=Status.RED, sensor=sensor_ip,
                details="No recent data from this sensor",
                remediation="Check Zeek, Vector, and Data Prepper pipeline for this sensor.",
            ))

    # 14. Required sensors present
    missing_sensors = [s for s in settings.sensor_ips if s not in scrape.sensors_present and settings.sensor_display_name(s) not in scrape.sensors_present]
    if missing_sensors:
        names = [settings.sensor_display_name(s) for s in missing_sensors]
        checks.append(CheckResult(
            id="os.sensors.missing", title="Missing sensors in recent data", component=C,
            severity="critical", status=Status.RED,
            current_value=len(missing_sensors), details=f"Missing: {', '.join(names)}",
            remediation="Investigate pipeline for missing sensors.",
        ))

    # 15. Required log types present
    missing_lt = [lt for lt in settings.required_log_types_list if lt not in scrape.log_types_present]
    if missing_lt:
        checks.append(CheckResult(
            id="os.log_types.missing", title="Missing log types in recent data", component=C,
            severity="warning", status=Status.YELLOW,
            details=f"Missing: {', '.join(missing_lt)}",
            remediation="Check Zeek configuration and Data Prepper routing.",
        ))

    # 16. Field caps check
    if scrape.field_caps_data and "fields" in scrape.field_caps_data:
        fields = scrape.field_caps_data["fields"]
        for rf in settings.required_fields_list:
            if rf not in fields:
                checks.append(CheckResult(
                    id=f"os.field.{rf}", title=f"Required field '{rf}' exists",
                    component=C, severity="warning", status=Status.YELLOW,
                    details=f"Field '{rf}' not found in field_caps",
                    remediation="Check index mappings and Data Prepper transformations.",
                ))

    return checks
