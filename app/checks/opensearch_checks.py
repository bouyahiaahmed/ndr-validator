"""
OpenSearch checks – evaluate cluster, index, and search results.
Every non-green check carries a structured Diagnosis.
"""
from __future__ import annotations
from typing import Dict, List, Optional
from app.config import settings
from app.models import (
    CheckResult, Component, Diagnosis, Status,
    FIX_OS, FIX_VALIDATOR, FIX_DP,
)
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
    if scrape.reachable:
        checks.append(CheckResult(
            id="os.reachable", title="OpenSearch reachable", component=C, severity="critical",
            status=Status.GREEN, details="Reachable",
        ))
    else:
        checks.append(CheckResult(
            id="os.reachable", title="OpenSearch reachable", component=C, severity="critical",
            status=Status.RED,
            details=scrape.error or "Unreachable",
            remediation="Check OpenSearch host, port, and network connectivity.",
            diagnosis=Diagnosis(
                problem="OpenSearch cluster is unreachable",
                evidence=f"GET {settings.opensearch_base_url}/_cluster/health failed: {scrape.error or 'no response'}",
                impact="BLOCKING: All data storage and search is unavailable. Complete NDR failure.",
                probable_causes=[
                    "OpenSearch container/service not running",
                    "Wrong OPENSEARCH_HOST or OPENSEARCH_PORT in .env",
                    "Firewall blocking port 9200",
                    "Docker network misconfiguration",
                ],
                next_steps=[
                    "On central-vm: docker ps | grep opensearch",
                    "On central-vm: curl -k https://localhost:9200/_cluster/health",
                    "Check OPENSEARCH_HOST and OPENSEARCH_PORT in validator .env",
                ],
                fix_location=FIX_OS,
                confidence="high",
            ),
        ))
        return checks

    # 2. TLS
    if scrape.tls_ok:
        checks.append(CheckResult(
            id="os.tls", title="OpenSearch TLS verification", component=C, severity="critical",
            status=Status.GREEN, details="TLS OK",
        ))
    else:
        checks.append(CheckResult(
            id="os.tls", title="OpenSearch TLS verification", component=C, severity="critical",
            status=Status.RED,
            details=scrape.error or "TLS failed",
            remediation="Check CA_CERT_PATH and OpenSearch TLS configuration.",
            diagnosis=Diagnosis(
                problem="TLS certificate verification failed for OpenSearch",
                evidence=f"TLS error: {scrape.error or 'certificate verification failed'}",
                impact="Cannot securely connect to OpenSearch. Data reads/writes blocked.",
                probable_causes=[
                    "CA_CERT_PATH not mounted or pointing to wrong file",
                    "OpenSearch self-signed cert not trusted by CA bundle",
                    "Certificate expired",
                ],
                next_steps=[
                    "openssl s_client -connect OPENSEARCH_HOST:9200 -CAfile /certs/ca/ca.crt",
                    "Verify CA cert includes the OpenSearch signing CA",
                    "Check certificate expiry dates",
                ],
                fix_location=FIX_OS,
                confidence="high",
            ),
        ))

    # 3. Auth
    if scrape.auth_ok:
        checks.append(CheckResult(
            id="os.auth", title="OpenSearch authentication", component=C, severity="critical",
            status=Status.GREEN, details="Auth OK",
        ))
    else:
        checks.append(CheckResult(
            id="os.auth", title="OpenSearch authentication", component=C, severity="critical",
            status=Status.RED,
            details="Auth failed",
            remediation="Verify OPENSEARCH_USERNAME/PASSWORD.",
            diagnosis=Diagnosis(
                problem="Authentication to OpenSearch failed",
                evidence="HTTP 401/403 from OpenSearch cluster health endpoint",
                impact="Cannot query OpenSearch. All index and freshness checks blocked.",
                probable_causes=[
                    "OPENSEARCH_USERNAME or OPENSEARCH_PASSWORD incorrect in .env",
                    "OpenSearch security plugin credentials changed",
                ],
                next_steps=[
                    "curl -k -u admin:YOURPASS https://OS_HOST:9200/_cluster/health",
                    "Check OPENSEARCH_USERNAME/PASSWORD in validator .env",
                ],
                fix_location=FIX_VALIDATOR,
                confidence="high",
            ),
        ))
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
            diagnosis=Diagnosis(
                problem=f"OpenSearch cluster is in '{cs}' state",
                evidence=f"GET /_cluster/health returned status='{cs}'",
                impact=(
                    "BLOCKING: Cluster RED means primary shards are unassigned. Indexing will fail."
                    if s == Status.RED else
                    "WARNING: Cluster YELLOW means replica shards are unassigned (common on single-node)."
                ),
                probable_causes=(
                    [
                        "Primary shard unassigned (node failure)",
                        "Disk full causing write block",
                        "Node crash or OOM",
                    ] if s == Status.RED else [
                        "Single-node cluster with replica shards > 0 (expected in lab)",
                        "A data node left the cluster",
                    ]
                ),
                next_steps=(
                    [
                        "GET /_cluster/health?pretty in Dashboards Dev Tools",
                        "GET /_cat/shards?h=index,shard,prirep,state,unassigned.reason",
                        "GET /_cat/nodes?v to check node availability",
                        "Check OpenSearch logs: docker logs opensearch-node1 --tail 100",
                    ] if s == Status.RED else [
                        "For single-node lab: PUT zeek-*/_settings {\"number_of_replicas\": 0}",
                        "GET /_cat/shards?v to identify unassigned replicas",
                    ]
                ),
                fix_location=FIX_OS,
                confidence="high",
            ) if s != Status.GREEN else None,
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
        single_node_replica_issue = (
            n_nodes == 1
            and unassigned > 0
            and active_primary > 0
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
            shard_diag = Diagnosis(
                problem="OpenSearch replica shards unassigned on single-node cluster",
                evidence=f"{unassigned} replica shards unassigned, {active_primary} primary shards active",
                impact="WARNING only: Primary shards are active. This is expected on a single-node lab. Not a blocking issue.",
                probable_causes=[
                    "Index templates created with number_of_replicas=1 but only one node exists",
                ],
                next_steps=[
                    f"PUT /zeek-*/_settings {{\"number_of_replicas\": 0}} in Dashboards Dev Tools",
                    "Or add a second OpenSearch node to allow replica assignment",
                ],
                fix_location=FIX_OS,
                confidence="high",
            )
        else:
            shard_status = Status.GREEN if asp >= 100 else (
                Status.YELLOW if asp >= 80 else Status.RED)
            shard_detail = f"Active shards: {asp:.1f}%"
            shard_remediation = "Check unassigned shards and node availability." if shard_status != Status.GREEN else ""
            shard_diag = Diagnosis(
                problem=f"OpenSearch active shard percentage is low ({asp:.1f}%)",
                evidence=f"active_shards_percent = {asp:.1f}%, unassigned_shards = {unassigned}",
                impact="Some shards unavailable. Read/write requests may fail for affected indices.",
                probable_causes=[
                    "Node failure left shards unassigned",
                    "Disk full triggering write block",
                ],
                next_steps=[
                    "GET /_cat/shards?h=index,shard,prirep,state,unassigned.reason",
                    "GET /_cat/nodes?v to check node health",
                ],
                fix_location=FIX_OS,
                confidence="high",
            ) if shard_status != Status.GREEN else None

        checks.append(CheckResult(
            id="os.cluster.active_shards", title="OpenSearch active shards %", component=C,
            severity="warning", status=shard_status,
            current_value=asp, details=shard_detail,
            remediation=shard_remediation,
            diagnosis=shard_diag,
        ))

        # 7. Unassigned shards
        us = scrape.cluster.get("unassigned_shards", 0)
        checks.append(CheckResult(
            id="os.cluster.unassigned", title="OpenSearch unassigned shards", component=C,
            severity="warning",
            status=Status.GREEN if us == 0 else Status.YELLOW,
            current_value=us, details=f"Unassigned shards: {us}",
            remediation=shard_remediation if us > 0 else "",
            diagnosis=shard_diag if us > 0 else None,
        ))

    # 8. Node heap/disk
    if scrape.nodes:
        for node in scrape.nodes:
            nname = node.get("name", "unknown")
            heap = node.get("heap.percent")
            if heap is not None:
                try:
                    hp = float(heap)
                    s = Status.GREEN if hp < settings.HIGH_HEAP_THRESHOLD_PERCENT else Status.YELLOW
                    checks.append(CheckResult(
                        id=f"os.node.{nname}.heap", title=f"OS node {nname} heap", component=C,
                        severity="warning", status=s,
                        current_value=hp, threshold=settings.HIGH_HEAP_THRESHOLD_PERCENT,
                        details=f"Heap: {hp}%",
                        diagnosis=Diagnosis(
                            problem=f"OpenSearch node '{nname}' heap usage is high ({hp:.0f}%)",
                            evidence=f"heap.percent = {hp:.0f}%",
                            impact="Risk of OutOfMemoryError and circuit breaker triggering.",
                            probable_causes=[
                                "High query load or large aggregations",
                                "JVM heap size too small for data volume",
                            ],
                            next_steps=[
                                "GET /_nodes/stats/jvm?pretty",
                                "Consider increasing OpenSearch heap (ES_JAVA_OPTS=-Xms4g -Xmx4g)",
                            ],
                            fix_location=FIX_OS,
                            confidence="medium",
                        ) if s != Status.GREEN else None,
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
        diagnosis=Diagnosis(
            problem=f"No indices matching '{settings.OPENSEARCH_INDEX_PATTERN}' found in OpenSearch",
            evidence=f"GET /_cat/indices/{settings.OPENSEARCH_INDEX_PATTERN} returned 0 results",
            impact="No Zeek data in OpenSearch. Detection system has no data to query.",
            probable_causes=[
                "Data Prepper never successfully indexed any documents",
                "Wrong OPENSEARCH_INDEX_PATTERN in .env (check actual index names)",
                "Data Prepper OpenSearch sink misconfigured (wrong index prefix)",
                "Fresh deployment — pipeline never ran",
            ],
            next_steps=[
                "GET /_cat/indices?v in Dashboards Dev Tools to see all indices",
                "Check Data Prepper pipeline YAML for index_prefix or index setting",
                "Check dp.os.doc_errors and dp.os.bulk_failed checks",
                "Set OPENSEARCH_INDEX_PATTERN to match actual index names",
            ],
            fix_location=FIX_DP,
            confidence="medium",
        ) if not has_indices else None,
    ))

    # 10. Doc count growth
    prev_count = p.get("total_count", 0)
    if prev_count > 0:
        delta = scrape.total_count - prev_count
        s = Status.GREEN if delta > 0 else Status.YELLOW
        checks.append(CheckResult(
            id="os.docs.growth", title="OpenSearch doc count growth", component=C,
            severity="warning", status=s,
            current_value=delta, details=f"Doc count delta: {delta}",
            remediation="Possible indexing stall." if delta == 0 else "",
            diagnosis=Diagnosis(
                problem="OpenSearch document count is not increasing",
                evidence=f"total_count delta = {delta} (prev: {prev_count:.0f}, now: {scrape.total_count})",
                impact="Data Prepper may not be writing new documents. Detection data stale.",
                probable_causes=[
                    "No new events from Vector sensors",
                    "Data Prepper pipeline paused or in error state",
                    "OpenSearch write block applied",
                ],
                next_steps=[
                    "Check dp.records.processed delta",
                    "Check corr.dp_os.indexing_stall check",
                ],
                fix_location=FIX_DP,
                confidence="low",
            ) if delta == 0 else None,
        ))

    # 11. Search latency
    sl = scrape.search_latency_ms
    s = Status.GREEN if sl < settings.MAX_OS_SEARCH_LATENCY_MS_WARN else (
        Status.YELLOW if sl < settings.MAX_OS_SEARCH_LATENCY_MS_CRIT else Status.RED)
    checks.append(CheckResult(
        id="os.search.latency", title="OpenSearch search latency", component=C,
        severity="warning", status=s,
        current_value=sl, threshold=settings.MAX_OS_SEARCH_LATENCY_MS_WARN,
        details=f"Search latency: {sl:.0f}ms",
        diagnosis=Diagnosis(
            problem=f"OpenSearch search latency is high ({sl:.0f}ms)",
            evidence=f"Search request latency = {sl:.0f}ms (warn: {settings.MAX_OS_SEARCH_LATENCY_MS_WARN}ms)",
            impact="Dashboard queries and validator freshness checks will be slow.",
            probable_causes=[
                "High cluster load",
                "GC pauses",
                "Large index size without enough shards",
            ],
            next_steps=[
                "GET /_nodes/hot_threads in Dashboards Dev Tools",
                "Check cluster heap usage (os.node.*.heap checks)",
            ],
            fix_location=FIX_OS,
            confidence="medium",
        ) if s != Status.GREEN else None,
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
                diagnosis=Diagnosis(
                    problem=f"OpenSearch has no fresh data (latest document is {age:.0f}s old)",
                    evidence=f"Latest @timestamp across {settings.OPENSEARCH_INDEX_PATTERN}: {age:.0f}s ago",
                    impact="Detection data is stale. Dashboards and alerts may show outdated information.",
                    probable_causes=[
                        "Vector not sending events (check vector checks)",
                        "Data Prepper pipeline stalled",
                        "OpenSearch indexing failures (check dp.os.doc_errors)",
                    ],
                    next_steps=[
                        "Check vector.*.sent_increasing checks for all sensors",
                        "Check dp.records.processed delta",
                        "Check corr.e2e.freshness check",
                    ],
                    fix_location=FIX_DP,
                    confidence="medium",
                ) if s != Status.GREEN else None,
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
                    id=f"os.freshness.sensor.{sensor_ip}",
                    title=f"Data freshness for {name}",
                    component=C, severity="warning", status=s, sensor=sensor_ip,
                    current_value=age, threshold=settings.STALE_DATA_THRESHOLD_SECONDS,
                    details=f"Latest doc age: {age:.0f}s",
                ))
        elif sensor_ip in settings.sensor_ips:
            checks.append(CheckResult(
                id=f"os.freshness.sensor.{sensor_ip}",
                title=f"Data freshness for {name}",
                component=C, severity="critical", status=Status.RED, sensor=sensor_ip,
                details="No recent data from this sensor",
                remediation="Check Zeek, Vector, and Data Prepper pipeline for this sensor.",
                diagnosis=Diagnosis(
                    problem=f"No data from sensor '{name}' in OpenSearch detection pattern",
                    evidence=f"No documents with sensor_id='{name}' in {settings.OPENSEARCH_INDEX_PATTERN}",
                    impact="This sensor is not contributing to detection. Coverage gap.",
                    probable_causes=[
                        "Zeek not running on sensor",
                        "Vector not forwarding from this sensor",
                        "OPENSEARCH_SENSOR_ID_FIELD does not match actual field name",
                    ],
                    next_steps=[
                        f"Check freshness.sensor_liveness.{sensor_ip} check",
                        f"Verify OPENSEARCH_SENSOR_ID_FIELD={settings.OPENSEARCH_SENSOR_ID_FIELD} matches index mapping",
                    ],
                    fix_location=FIX_VALIDATOR,
                    confidence="medium",
                ),
            ))

    # 14. Required sensors present
    missing_sensors = [
        s for s in settings.sensor_ips
        if s not in scrape.sensors_present
        and settings.sensor_display_name(s) not in scrape.sensors_present
    ]
    if missing_sensors:
        names = [settings.sensor_display_name(s) for s in missing_sensors]
        checks.append(CheckResult(
            id="os.sensors.missing", title="Missing sensors in recent data", component=C,
            severity="critical", status=Status.RED,
            current_value=len(missing_sensors), details=f"Missing: {', '.join(names)}",
            remediation="Investigate pipeline for missing sensors.",
            diagnosis=Diagnosis(
                problem=f"Sensors {', '.join(names)} not found in OpenSearch data",
                evidence=f"No docs with {settings.OPENSEARCH_SENSOR_ID_FIELD} in {{{', '.join(names)}}} in {settings.OPENSEARCH_INDEX_PATTERN}",
                impact="These sensors are not contributing to detection.",
                probable_causes=[
                    "Sensor pipeline (Zeek→Vector→DP) not working for these sensors",
                    "OPENSEARCH_SENSOR_ID_FIELD does not match actual ECS/Zeek field",
                    "Sensors configured in SENSOR_LIST but not deployed yet",
                ],
                next_steps=[
                    f"Check sensor liveness checks for: {', '.join(names)}",
                    f"Verify field: GET zeek-*/_field_caps?fields={settings.OPENSEARCH_SENSOR_ID_FIELD}",
                ],
                fix_location=FIX_VALIDATOR,
                confidence="medium",
            ),
        ))

    # 15. Required log types present
    missing_lt = [lt for lt in settings.required_log_types_list if lt not in scrape.log_types_present]
    if missing_lt:
        checks.append(CheckResult(
            id="os.log_types.missing", title="Missing log types in recent data", component=C,
            severity="warning", status=Status.YELLOW,
            details=f"Missing: {', '.join(missing_lt)}",
            remediation="Check Zeek configuration and Data Prepper routing.",
            diagnosis=Diagnosis(
                problem=f"Log types {', '.join(missing_lt)} absent from OpenSearch",
                evidence=f"No docs with {settings.OPENSEARCH_LOG_TYPE_FIELD} in {{{', '.join(missing_lt)}}}",
                impact="Detection coverage gaps for these log types.",
                probable_causes=[
                    "No traffic generating these log types",
                    "Zeek policy not enabling these log types",
                    "Data Prepper routing not indexing these types",
                ],
                next_steps=[
                    "Generate test traffic for each missing log type",
                    "Check freshness.detection_coverage.* checks",
                ],
                fix_location="traffic / lab environment",
                confidence="low",
            ),
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
                    diagnosis=Diagnosis(
                        problem=f"Required ECS/Zeek field '{rf}' not present in any index",
                        evidence=f"/{settings.OPENSEARCH_INDEX_PATTERN}/_field_caps?fields={rf} returned no mapping",
                        impact="Dashboards and detection rules relying on this field will not work.",
                        probable_causes=[
                            "Data Prepper transform not mapping this field",
                            "Zeek not writing this field in current config",
                            "Wrong field name in REQUIRED_FIELDS env var",
                        ],
                        next_steps=[
                            f"GET zeek-*/_mapping in Dashboards and search for the field",
                            "Check Data Prepper pipeline transform for field mapping",
                            f"Update REQUIRED_FIELDS in .env if field name differs",
                        ],
                        fix_location=FIX_DP,
                        confidence="medium",
                    ),
                ))

    return checks
