"""
OpenSearch collector – queries cluster, node, and index APIs.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from app.config import settings
from app.utils.opensearch import (
    cluster_health, cat_nodes, cat_indices, cat_count,
    node_stats, cluster_stats, field_caps, search_recent,
    count_recent, aggs_by_field, latest_timestamp_per_field,
)

logger = logging.getLogger(__name__)

class OpenSearchScrapeResult:
    def __init__(self):
        self.reachable = False
        self.tls_ok = False
        self.auth_ok = False
        self.error: Optional[str] = None
        self.latency_ms = 0.0
        self.cluster: Optional[Dict] = None
        self.nodes: Optional[List] = None
        self.indices: Optional[List] = None
        self.total_count: int = 0
        self.node_stats_data: Optional[Dict] = None
        self.cluster_stats_data: Optional[Dict] = None
        self.field_caps_data: Optional[Dict] = None
        self.recent_docs: Optional[Dict] = None
        self.recent_count: int = 0
        self.search_latency_ms = 0.0
        self.sensor_freshness: Dict[str, Optional[float]] = {}
        self.log_type_freshness: Dict[str, Optional[float]] = {}
        self.overall_latest_ts: Optional[str] = None
        self.sensors_present: List[str] = []
        self.log_types_present: List[str] = []

async def scrape_opensearch() -> OpenSearchScrapeResult:
    result = OpenSearchScrapeResult()
    # Cluster health
    data, lat, err = await cluster_health()
    result.latency_ms = lat
    if err:
        result.error = err
        if "auth" in str(err).lower():
            result.reachable = True
            result.tls_ok = True
        elif "certificate" in str(err).lower() or "tls" in str(err).lower():
            result.reachable = True
        return result
    result.reachable = True
    result.tls_ok = True
    result.auth_ok = True
    result.cluster = data
    # Cat nodes
    nodes_data, _, _ = await cat_nodes()
    result.nodes = nodes_data if isinstance(nodes_data, list) else None
    # Cat indices
    idx_data, _, _ = await cat_indices()
    result.indices = idx_data if isinstance(idx_data, list) else None
    # Total count
    cnt_data, _, _ = await cat_count()
    if isinstance(cnt_data, list) and cnt_data:
        try:
            result.total_count = int(cnt_data[0].get("count", 0))
        except (ValueError, TypeError):
            pass
    # Node stats
    ns_data, _, _ = await node_stats()
    result.node_stats_data = ns_data
    # Cluster stats
    cs_data, _, _ = await cluster_stats()
    result.cluster_stats_data = cs_data
    # Field caps for required fields
    fc_data, _, _ = await field_caps(settings.required_fields_list)
    result.field_caps_data = fc_data
    # Recent search
    recent, s_lat, _ = await search_recent(size=5, time_range_seconds=300)
    result.recent_docs = recent
    result.search_latency_ms = s_lat
    if recent and "hits" in recent:
        result.recent_count = recent["hits"].get("total", {}).get("value", 0)
        hits = recent["hits"].get("hits", [])
        if hits:
            result.overall_latest_ts = hits[0].get("_source", {}).get(settings.OPENSEARCH_TIMESTAMP_FIELD)
    # Sensor freshness
    sf_data, _, _ = await latest_timestamp_per_field(settings.OPENSEARCH_SENSOR_ID_FIELD)
    if sf_data and "aggregations" in sf_data:
        for bucket in sf_data["aggregations"].get("groups", {}).get("buckets", []):
            key = bucket.get("key", "")
            ts_val = bucket.get("latest", {}).get("value_as_string")
            result.sensors_present.append(key)
            result.sensor_freshness[key] = ts_val
    # Log type freshness
    lt_data, _, _ = await latest_timestamp_per_field(settings.OPENSEARCH_LOG_TYPE_FIELD)
    if lt_data and "aggregations" in lt_data:
        for bucket in lt_data["aggregations"].get("groups", {}).get("buckets", []):
            key = bucket.get("key", "")
            ts_val = bucket.get("latest", {}).get("value_as_string")
            result.log_types_present.append(key)
            result.log_type_freshness[key] = ts_val
    return result

def get_flat_metrics(result: OpenSearchScrapeResult) -> Dict[str, float]:
    m: Dict[str, float] = {"total_count": float(result.total_count), "search_latency_ms": result.search_latency_ms}
    if result.cluster:
        m["active_shards_percent"] = result.cluster.get("active_shards_percent_as_number", 0)
        m["unassigned_shards"] = result.cluster.get("unassigned_shards", 0)
        m["number_of_nodes"] = result.cluster.get("number_of_nodes", 0)
    return m
