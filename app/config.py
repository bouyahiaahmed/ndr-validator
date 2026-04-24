"""
Centralized configuration loaded from environment variables.
Uses pydantic-settings for typed, validated configuration.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All application settings loaded from environment / .env file."""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    # ── Core ──────────────────────────────────────────────────────────
    APP_ENV: str = "prod"
    LOG_LEVEL: str = "INFO"
    SCRAPE_INTERVAL_SECONDS: int = 30
    REQUEST_TIMEOUT_SECONDS: int = 5
    SQLITE_DB_PATH: str = "/data/validator.db"
    TZ: str = "UTC"

    # ── Sensors ───────────────────────────────────────────────────────
    SENSOR_LIST: str = ""
    EXPECTED_SENSOR_COUNT: int = 0
    SENSOR_NAME_MAP_JSON: str = "{}"

    # ── SSH ────────────────────────────────────────────────────────────
    ENABLE_SENSOR_SSH: bool = False
    SENSOR_SSH_USER: str = "vagrant"
    SENSOR_SSH_PORT: int = 22
    SENSOR_SSH_KEY_PATH: str = "/run/secrets/sensor_ssh_key"
    # Path to a known_hosts file for SSH host key verification.
    # Empty string = disable host key verification only when ENABLE_DEBUG_INSECURE_SKIP_VERIFY=true,
    # otherwise asyncssh system defaults are used.
    SENSOR_SSH_KNOWN_HOSTS_PATH: str = ""
    SENSOR_SSH_CONNECT_TIMEOUT_SECONDS: int = 5
    ZEEK_LOG_DIR: str = "/opt/zeek/logs/current"
    ZEEK_SERVICE_NAME: str = "zeek"
    VECTOR_SERVICE_NAME: str = "vector"

    # ── Vector ────────────────────────────────────────────────────────
    VECTOR_METRICS_SCHEME: str = "http"
    VECTOR_METRICS_PORT: int = 9598
    VECTOR_METRICS_PATH: str = "/metrics"

    # ── Data Prepper Management ───────────────────────────────────────
    DATAPREPPER_HOST: str = "dataprepper"
    DATAPREPPER_METRICS_SCHEME: str = "https"
    DATAPREPPER_METRICS_PORT: int = 4900
    DATAPREPPER_METRICS_PATH: str = "/metrics/sys"
    DATAPREPPER_USERNAME: str = "admin"
    DATAPREPPER_PASSWORD: str = "admin"

    # ── Data Prepper Ingest ───────────────────────────────────────────
    DATAPREPPER_INGEST_SCHEME: str = "https"
    DATAPREPPER_INGEST_PORT: int = 2021
    DATAPREPPER_INGEST_PATH: str = "/log/ingest"
    DATAPREPPER_HEALTH_PATH: str = "/health"
    DATAPREPPER_INGEST_USERNAME: str = "vector"
    DATAPREPPER_INGEST_PASSWORD: str = "vector"
    DATAPREPPER_HEALTH_REQUIRES_AUTH: bool = True
    DATAPREPPER_PIPELINE_NAME: str = ""

    # ── OpenSearch ────────────────────────────────────────────────────
    OPENSEARCH_SCHEME: str = "https"
    OPENSEARCH_HOST: str = "opensearch-node1"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_USERNAME: str = "admin"
    OPENSEARCH_PASSWORD: str = "admin"
    OPENSEARCH_INDEX_PATTERN: str = "zeek-*"
    OPENSEARCH_SENSOR_ID_FIELD: str = "host.name.keyword"
    OPENSEARCH_LOG_TYPE_FIELD: str = "log_type.keyword"
    OPENSEARCH_TIMESTAMP_FIELD: str = "@timestamp"

    # ── Dashboards ────────────────────────────────────────────────────
    DASHBOARDS_SCHEME: str = "https"
    DASHBOARDS_HOST: str = "dashboards"
    DASHBOARDS_PORT: int = 5601
    DASHBOARDS_BASE_PATH: str = ""
    DASHBOARDS_USERNAME: str = "admin"
    DASHBOARDS_PASSWORD: str = "admin"
    DASHBOARDS_STATUS_PATH: str = "/api/status"
    DASHBOARDS_ENABLE_STATUS_API_CHECK: bool = True

    # ── Certificates ──────────────────────────────────────────────────
    CA_CERT_PATH: str = "/certs/ca/ca.crt"
    OPENSEARCH_CLIENT_CERT_PATH: str = ""
    OPENSEARCH_CLIENT_KEY_PATH: str = ""
    DATAPREPPER_CLIENT_CERT_PATH: str = ""
    DATAPREPPER_CLIENT_KEY_PATH: str = ""
    DASHBOARDS_CA_CERT_PATH: str = "/certs/ca/ca.crt"

    # ── Thresholds ────────────────────────────────────────────────────
    STALE_DATA_THRESHOLD_SECONDS: int = 120
    CRITICAL_STALE_DATA_THRESHOLD_SECONDS: int = 300
    MAX_VECTOR_TO_DP_DROP_PERCENT: float = 5.0
    MAX_DP_TO_OS_DROP_PERCENT: float = 5.0
    MAX_DP_PIPELINE_LATENCY_SECONDS_WARN: float = 5.0
    MAX_DP_PIPELINE_LATENCY_SECONDS_CRIT: float = 30.0
    MAX_DP_BUFFER_USAGE_RATIO_WARN: float = 0.7
    MAX_DP_BUFFER_USAGE_RATIO_CRIT: float = 0.9
    MAX_DP_BUFFER_WRITE_FAILURE_DELTA: int = 0
    MAX_DP_DOCUMENT_ERROR_DELTA: int = 0
    MAX_DP_BULK_FAILURE_DELTA: int = 0
    MAX_DP_TLS_HANDSHAKE_FAILURE_DELTA: int = 0
    MAX_OS_SEARCH_LATENCY_MS_WARN: int = 500
    MAX_OS_SEARCH_LATENCY_MS_CRIT: int = 2000
    LOW_DISK_THRESHOLD_PERCENT: float = 15.0
    HIGH_HEAP_THRESHOLD_PERCENT: float = 85.0
    REQUIRED_LOG_TYPES: str = "conn,dns,http,ssl,files"
    REQUIRED_FIELDS: str = "@timestamp,source.ip,destination.ip,network.protocol"
    ENABLE_DEBUG_INSECURE_SKIP_VERIFY: bool = False

    # ── DLQ ───────────────────────────────────────────────────────────
    ENABLE_DP_DLQ_CHECK: bool = True
    DP_DLQ_GLOB: str = "/tmp/dp-dlq-*.log"

    # ── Derived helpers ───────────────────────────────────────────────

    @property
    def sensor_ips(self) -> List[str]:
        if not self.SENSOR_LIST.strip():
            return []
        return [s.strip() for s in self.SENSOR_LIST.split(",") if s.strip()]

    @property
    def sensor_name_map(self) -> Dict[str, str]:
        try:
            return json.loads(self.SENSOR_NAME_MAP_JSON)
        except (json.JSONDecodeError, TypeError):
            return {}

    @property
    def required_log_types_list(self) -> List[str]:
        return [s.strip() for s in self.REQUIRED_LOG_TYPES.split(",") if s.strip()]

    @property
    def required_fields_list(self) -> List[str]:
        return [s.strip() for s in self.REQUIRED_FIELDS.split(",") if s.strip()]

    @property
    def config_fingerprint(self) -> str:
        """SHA-256 fingerprint of significant config values for change detection."""
        sig = json.dumps(
            {
                "sensors": self.SENSOR_LIST,
                "dp_host": self.DATAPREPPER_HOST,
                "os_host": self.OPENSEARCH_HOST,
                "dash_host": self.DASHBOARDS_HOST,
                "index": self.OPENSEARCH_INDEX_PATTERN,
                "interval": self.SCRAPE_INTERVAL_SECONDS,
            },
            sort_keys=True,
        )
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    def sensor_display_name(self, ip: str) -> str:
        return self.sensor_name_map.get(ip, ip)

    @property
    def opensearch_base_url(self) -> str:
        return f"{self.OPENSEARCH_SCHEME}://{self.OPENSEARCH_HOST}:{self.OPENSEARCH_PORT}"

    @property
    def dataprepper_metrics_url(self) -> str:
        return (
            f"{self.DATAPREPPER_METRICS_SCHEME}://"
            f"{self.DATAPREPPER_HOST}:{self.DATAPREPPER_METRICS_PORT}"
            f"{self.DATAPREPPER_METRICS_PATH}"
        )

    @property
    def dataprepper_health_url(self) -> str:
        return (
            f"{self.DATAPREPPER_INGEST_SCHEME}://"
            f"{self.DATAPREPPER_HOST}:{self.DATAPREPPER_INGEST_PORT}"
            f"{self.DATAPREPPER_HEALTH_PATH}"
        )

    @property
    def dashboards_base_url(self) -> str:
        base = f"{self.DASHBOARDS_SCHEME}://{self.DASHBOARDS_HOST}:{self.DASHBOARDS_PORT}"
        if self.DASHBOARDS_BASE_PATH:
            base += self.DASHBOARDS_BASE_PATH.rstrip("/")
        return base

    def vector_metrics_url(self, sensor_ip: str) -> str:
        return (
            f"{self.VECTOR_METRICS_SCHEME}://"
            f"{sensor_ip}:{self.VECTOR_METRICS_PORT}"
            f"{self.VECTOR_METRICS_PATH}"
        )


# Singleton – import and use this everywhere
settings = Settings()
