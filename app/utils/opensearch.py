"""
OpenSearch client utilities – typed wrappers for cluster, index, and search APIs.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional, Tuple
from app.config import settings
from app.utils.http import fetch_json, post_json

logger = logging.getLogger(__name__)

def _base() -> str:
    return settings.opensearch_base_url

def _auth() -> Tuple[str, str]:
    return (settings.OPENSEARCH_USERNAME, settings.OPENSEARCH_PASSWORD)

def _ca() -> str:
    return settings.CA_CERT_PATH

async def cluster_health() -> Tuple[Optional[Dict], float, Optional[str]]:
    return await fetch_json(f"{_base()}/_cluster/health", _ca(), _auth())

async def cat_nodes() -> Tuple[Optional[Any], float, Optional[str]]:
    return await fetch_json(
        f"{_base()}/_cat/nodes?format=json&h=name,heap.percent,disk.avail,cpu,load_1m,node.role",
        _ca(), _auth(),
    )

async def cat_indices(pattern: Optional[str] = None) -> Tuple[Optional[Any], float, Optional[str]]:
    pat = pattern or settings.OPENSEARCH_INDEX_PATTERN
    return await fetch_json(
        f"{_base()}/_cat/indices/{pat}?format=json&s=index&h=index,health,status,docs.count,store.size,pri,rep",
        _ca(), _auth(),
    )

async def cat_count(pattern: Optional[str] = None) -> Tuple[Optional[Any], float, Optional[str]]:
    pat = pattern or settings.OPENSEARCH_INDEX_PATTERN
    return await fetch_json(f"{_base()}/_cat/count/{pat}?format=json", _ca(), _auth())

async def node_stats() -> Tuple[Optional[Dict], float, Optional[str]]:
    return await fetch_json(f"{_base()}/_nodes/stats", _ca(), _auth())

async def cluster_stats() -> Tuple[Optional[Dict], float, Optional[str]]:
    return await fetch_json(f"{_base()}/_cluster/stats", _ca(), _auth())

async def field_caps(fields: List[str], index: Optional[str] = None) -> Tuple[Optional[Dict], float, Optional[str]]:
    idx = index or settings.OPENSEARCH_INDEX_PATTERN
    return await fetch_json(f"{_base()}/{idx}/_field_caps?fields={','.join(fields)}", _ca(), _auth())

async def search_recent(
    index: Optional[str] = None,
    size: int = 10,
    time_range_seconds: int = 300,
    extra_query: Optional[Dict] = None,
) -> Tuple[Optional[Dict], float, Optional[str]]:
    idx = index or settings.OPENSEARCH_INDEX_PATTERN
    ts = settings.OPENSEARCH_TIMESTAMP_FIELD
    # unmapped_type prevents shard exceptions on indices that lack @timestamp mapping
    q: Dict[str, Any] = {
        "size": size,
        "sort": [{ts: {"order": "desc", "unmapped_type": "date"}}],
        "query": {"bool": {"must": [{"range": {ts: {"gte": f"now-{time_range_seconds}s"}}}]}},
    }
    if extra_query:
        q["query"]["bool"]["must"].append(extra_query)
    return await post_json(f"{_base()}/{idx}/_search", q, _ca(), _auth())


async def search_latest(index: Optional[str] = None) -> Tuple[Optional[Dict], float, Optional[str]]:
    """Fetch the single most-recent document across all matching indices.

    Intentionally uses NO time-range filter so stale-data detection works
    even when the pipeline has been idle for longer than any rolling window.
    unmapped_type:date is required for indices that lack @timestamp mapping.
    """
    idx = index or settings.OPENSEARCH_INDEX_PATTERN
    ts = settings.OPENSEARCH_TIMESTAMP_FIELD
    q: Dict[str, Any] = {
        "size": 1,
        "sort": [{ts: {"order": "desc", "unmapped_type": "date"}}],
        "query": {"match_all": {}},
        "_source": [ts],
    }
    return await post_json(f"{_base()}/{idx}/_search", q, _ca(), _auth())


async def count_recent(index: Optional[str] = None, time_range_seconds: int = 300) -> Tuple[Optional[Dict], float, Optional[str]]:
    idx = index or settings.OPENSEARCH_INDEX_PATTERN
    ts = settings.OPENSEARCH_TIMESTAMP_FIELD
    return await post_json(
        f"{_base()}/{idx}/_count",
        {"query": {"range": {ts: {"gte": f"now-{time_range_seconds}s"}}}},
        _ca(), _auth(),
    )

async def aggs_by_field(
    field: str,
    index: Optional[str] = None,
    time_range_seconds: int = 300,
    size: int = 50,
) -> Tuple[Optional[Dict], float, Optional[str]]:
    idx = index or settings.OPENSEARCH_INDEX_PATTERN
    ts = settings.OPENSEARCH_TIMESTAMP_FIELD
    q = {
        "size": 0,
        "query": {"range": {ts: {"gte": f"now-{time_range_seconds}s"}}},
        "aggs": {"by_field": {"terms": {"field": field, "size": size}}},
    }
    return await post_json(f"{_base()}/{idx}/_search", q, _ca(), _auth())

async def latest_timestamp_per_field(
    group_field: str,
    index: Optional[str] = None,
) -> Tuple[Optional[Dict], float, Optional[str]]:
    """Return the latest @timestamp per distinct value of group_field.

    Uses match_all (no time range) so freshness is correctly reported even
    when all data is older than any rolling window.
    """
    idx = index or settings.OPENSEARCH_INDEX_PATTERN
    ts = settings.OPENSEARCH_TIMESTAMP_FIELD
    q = {
        "size": 0,
        "query": {"match_all": {}},
        "aggs": {
            "groups": {
                "terms": {"field": group_field, "size": 50},
                "aggs": {"latest": {"max": {"field": ts}}},
            }
        },
    }
    return await post_json(f"{_base()}/{idx}/_search", q, _ca(), _auth())
