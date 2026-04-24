"""
Prometheus text exposition format parser.
Parses text/plain Prometheus metrics into structured Python dicts.
Handles comments, HELP, TYPE, label parsing, and multi-line values.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Regex for metric lines:  metric_name{label="value",...} value [timestamp]
_METRIC_RE = re.compile(
    r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)'
    r'(?:\{(?P<labels>[^}]*)\})?'
    r'\s+(?P<value>\S+)'
    r'(?:\s+(?P<timestamp>\S+))?$'
)

_LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


class MetricSample:
    """A single metric sample with name, labels, and value."""

    __slots__ = ("name", "labels", "value", "timestamp")

    def __init__(
        self,
        name: str,
        labels: Dict[str, str],
        value: float,
        timestamp: Optional[float] = None,
    ):
        self.name = name
        self.labels = labels
        self.value = value
        self.timestamp = timestamp

    def __repr__(self) -> str:
        return f"MetricSample({self.name}, {self.labels}, {self.value})"


class MetricFamily:
    """A group of samples sharing a metric name with optional help and type."""

    __slots__ = ("name", "help_text", "type", "samples")

    def __init__(
        self,
        name: str,
        help_text: str = "",
        type: str = "untyped",
        samples: Optional[List[MetricSample]] = None,
    ):
        self.name = name
        self.help_text = help_text
        self.type = type
        self.samples = samples or []

    def __repr__(self) -> str:
        return f"MetricFamily({self.name}, type={self.type}, samples={len(self.samples)})"


def parse_labels(label_str: str) -> Dict[str, str]:
    """Parse Prometheus label string into a dict."""
    if not label_str:
        return {}
    return dict(_LABEL_RE.findall(label_str))


def parse_prometheus_text(text: str) -> Dict[str, MetricFamily]:
    """
    Parse Prometheus text exposition format into MetricFamily dicts.
    
    Returns a dict keyed by metric family name.
    Robust against malformed lines – logs warnings but does not crash.
    """
    families: Dict[str, MetricFamily] = {}
    current_name: Optional[str] = None
    current_help: str = ""
    current_type: str = "untyped"

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # HELP line
        if line.startswith("# HELP "):
            parts = line[7:].split(" ", 1)
            current_name = parts[0]
            current_help = parts[1] if len(parts) > 1 else ""
            continue

        # TYPE line
        if line.startswith("# TYPE "):
            parts = line[7:].split(" ", 1)
            current_name = parts[0]
            current_type = parts[1] if len(parts) > 1 else "untyped"
            continue

        # Skip other comments
        if line.startswith("#"):
            continue

        # Metric line
        match = _METRIC_RE.match(line)
        if not match:
            logger.debug("Skipping unparseable metric line: %s", line[:120])
            continue

        name = match.group("name")
        labels = parse_labels(match.group("labels") or "")
        value_str = match.group("value")
        ts_str = match.group("timestamp")

        # Parse value
        try:
            if value_str in ("NaN", "Nan", "nan"):
                value = float("nan")
            elif value_str in ("+Inf", "Inf"):
                value = float("inf")
            elif value_str == "-Inf":
                value = float("-inf")
            else:
                value = float(value_str)
        except ValueError:
            logger.debug("Skipping metric with unparseable value: %s = %s", name, value_str)
            continue

        timestamp = None
        if ts_str:
            try:
                timestamp = float(ts_str)
            except ValueError:
                pass

        # Strip histogram/summary suffixes for family name
        base_name = name
        for suffix in ("_total", "_count", "_sum", "_bucket", "_created", "_info"):
            if name.endswith(suffix) and name != suffix:
                candidate = name[: -len(suffix)]
                if candidate == current_name:
                    base_name = candidate
                    break

        # If we have TYPE context matching
        family_name = current_name if current_name and name.startswith(current_name) else name

        if family_name not in families:
            families[family_name] = MetricFamily(
                name=family_name,
                help_text=current_help if current_name == family_name else "",
                type=current_type if current_name == family_name else "untyped",
            )

        sample = MetricSample(name=name, labels=labels, value=value, timestamp=timestamp)
        families[family_name].samples.append(sample)

    logger.debug("Parsed %d metric families from Prometheus text", len(families))
    return families


def extract_flat_metrics(
    families: Dict[str, MetricFamily],
    alias_map: Optional[Dict[str, str]] = None,
) -> Dict[str, float]:
    """
    Extract a flat dict of metric_name -> value.
    For counters and gauges, takes the value of the first sample (or sums across labels).
    Applies alias mapping if provided.
    """
    result: Dict[str, float] = {}

    for family_name, family in families.items():
        for sample in family.samples:
            key = sample.name
            if sample.labels:
                label_suffix = ",".join(f'{k}={v}' for k, v in sorted(sample.labels.items()))
                key = f"{sample.name}{{{label_suffix}}}"
            result[key] = sample.value
            # Also store without labels for simple lookups
            if sample.name not in result:
                result[sample.name] = sample.value
            else:
                # For counters, we might want the sum; keep first seen for now
                pass

    # Apply alias mapping
    if alias_map:
        for alias, canonical in alias_map.items():
            if alias in result and canonical not in result:
                result[canonical] = result[alias]

    return result


def find_metric_value(
    families: Dict[str, MetricFamily],
    metric_name: str,
    label_filters: Optional[Dict[str, str]] = None,
    aliases: Optional[List[str]] = None,
) -> Optional[float]:
    """
    Find a specific metric value, optionally filtering by labels.
    Tries the primary name first, then aliases.
    """
    names_to_try = [metric_name] + (aliases or [])

    for name in names_to_try:
        for family_name, family in families.items():
            for sample in family.samples:
                if sample.name == name or family_name == name:
                    if label_filters:
                        if all(
                            sample.labels.get(k) == v for k, v in label_filters.items()
                        ):
                            return sample.value
                    else:
                        return sample.value
    return None


def sum_metric_values(
    families: Dict[str, MetricFamily],
    metric_name: str,
    label_filters: Optional[Dict[str, str]] = None,
    aliases: Optional[List[str]] = None,
) -> float:
    """Sum all sample values for a metric name, optionally filtered by labels."""
    total = 0.0
    found = False
    names_to_try = [metric_name] + (aliases or [])

    for name in names_to_try:
        for family_name, family in families.items():
            for sample in family.samples:
                if sample.name == name or family_name == name:
                    if label_filters:
                        if all(
                            sample.labels.get(k) == v for k, v in label_filters.items()
                        ):
                            total += sample.value
                            found = True
                    else:
                        total += sample.value
                        found = True
        if found:
            break

    return total


def discover_pipeline_names(families: Dict[str, MetricFamily]) -> List[str]:
    """
    Discover Data Prepper pipeline names from metric prefixes.
    Looks for patterns like <pipeline_name>_recordsProcessed_total.
    """
    pipeline_names: set = set()
    pipeline_suffixes = [
        "_recordsProcessed_total",
        "_http_requestsReceived_total",
        "_opensearch_recordsIn_total",
        "_BlockingBuffer_recordsInBuffer",
    ]

    for family_name in families:
        for suffix in pipeline_suffixes:
            if family_name.endswith(suffix):
                prefix = family_name[: -len(suffix)]
                if prefix:
                    pipeline_names.add(prefix)
                break

    return sorted(pipeline_names)


def get_samples_by_label(
    families: Dict[str, MetricFamily],
    metric_name: str,
    label_key: str,
) -> Dict[str, float]:
    """Return a dict of label_value -> metric_value for a given label key."""
    result: Dict[str, float] = {}
    for family_name, family in families.items():
        for sample in family.samples:
            if sample.name == metric_name or family_name == metric_name:
                label_val = sample.labels.get(label_key)
                if label_val is not None:
                    result[label_val] = sample.value
    return result
