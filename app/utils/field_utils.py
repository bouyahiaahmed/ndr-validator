"""
Field lookup utilities for OpenSearch document _source dicts.

OpenSearch documents may store fields as:
  - Literal dotted keys:  {"id.orig_h": "1.1.1.1"}   (raw Zeek JSON)
  - Nested objects:       {"id": {"orig_h": "1.1.1.1"}} (ECS-style)

get_field() tries the exact key first, then dotted-path traversal, so
it works transparently regardless of how the pipeline stores the field.
"""
from __future__ import annotations
from typing import Any, Optional


def get_field(doc: dict, dotted_key: str) -> Optional[Any]:
    """Return the value of *dotted_key* from *doc*, or None if absent.

    Lookup order:
    1. Exact key match  →  doc["id.orig_h"]
    2. Nested traversal →  doc["id"]["orig_h"]

    This handles both raw Zeek documents (literal dotted keys) and
    ECS-normalised documents (nested objects) without any configuration.
    """
    if not isinstance(doc, dict):
        return None

    # 1. Exact key – handles literal dotted Zeek fields ("id.orig_h")
    if dotted_key in doc:
        return doc[dotted_key]

    # 2. Nested path traversal – handles ECS nested objects
    parts = dotted_key.split(".")
    cur: Any = doc
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur
