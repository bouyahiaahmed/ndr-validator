# NDR Pipeline Validator

A production-grade, Dockerized pipeline integrity validator for NDR environments running
**Zeek → Vector → Data Prepper → OpenSearch → OpenSearch Dashboards**.

It continuously detects **silent failures, schema drift, stale data, protocol mismatches,
buffer pressure, and operational degradation** across all pipeline stages — not just surface-level health.

---

## Why This Exists

Monitoring dashboards tell you when something is visibly broken. This validator tells you when
your pipeline is _quietly losing data_ — Vector forwarding but Data Prepper rejecting, Data Prepper
processing but OpenSearch not indexing, one sensor stale while the rest look healthy.

---

## Architecture

```
┌──────────┐   file    ┌────────┐  HTTP/TLS ┌──────────────┐  bulk  ┌─────────────┐  ┌───────────┐
│   Zeek   │──────────▶│ Vector │──────────▶│ Data Prepper │───────▶│  OpenSearch │  │ Dashboards│
│(per sensor)│         │(per sensor)│        │  (central)   │        │  (cluster)  │  │   (UI)    │
└──────────┘           └────────┘           └──────────────┘        └─────────────┘  └───────────┘
                            ▲ Prometheus          ▲ Prometheus HTTPS
                            │ http:9598           │ https:4900
                 ┌──────────────────────────────────────────┐
                 │         NDR Pipeline Validator            │
                 │  FastAPI + SQLite + Async scrape loop     │
                 │  GET /status  GET /checks  GET /metrics   │
                 └──────────────────────────────────────────┘
```

---

## Features

| Category | What it checks |
|---|---|
| **Zeek** | SSH probe: process, zeekctl, log dir, log freshness, JSON parse, disk, freeze |
| **Vector** | Per-sensor metrics: received/sent events (current + legacy names), errors, resets, peer imbalance |
| **Data Prepper** | TLS/auth, records processed, buffer usage/failures, doc errors, TLS handshakes, JVM heap, DLQ |
| **OpenSearch** | Cluster health, nodes, heap/disk/CPU, index existence, doc growth, search latency, freshness |
| **Dashboards** | Reachability, TLS, body sanity, static assets, optional /api/status, 5xx, redirect loops |
| **Correlation** | Zeek→Vector, Vector→DP drop%, DP→OS drop%, E2E freshness, TLS mismatch classification, bottleneck detection |
| **Data Quality** | Required fields presence, coverage, type drift, log type and sensor inventory |

---

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your hosts, credentials, and certificate paths

# 2. Place your CA certificate
mkdir -p certs/ca
cp /path/to/your/ca.crt certs/ca/ca.crt

# 3. (Optional) SSH key for Zeek sensor probing
mkdir -p secrets
cp /path/to/sensor_ssh_key secrets/sensor_ssh_key
chmod 600 secrets/sensor_ssh_key

# 4. Build and run
docker compose up -d --build

# 5. Check it's running
curl http://localhost:8000/healthz
# {"status":"ok"}

# 6. Wait 30s for first scrape, then
curl http://localhost:8000/status | python -m json.tool
```

Open `http://localhost:8000` for the web UI.

---

## Running Tests

```bash
# Install dev dependencies
pip install -r requirements.txt pytest pytest-asyncio

# Run all tests
pytest -v

# Run a specific test file
pytest tests/test_correlation_checks.py -v

# Run with coverage
pip install pytest-cov
pytest --cov=app --cov-report=term-missing
```

---

## API Reference

### `GET /healthz`
Process-level liveness.
```json
{"status": "ok"}
```

### `GET /readyz`
Readiness: DB + scheduler initialized.
```json
{"ready": true, "db": true, "scheduler": true}
```

### `GET /status`
Full status summary.
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0",
  "config_fingerprint": "a3f7c2d1",
  "overall_status": "yellow",
  "components": [
    {"name": "zeek", "status": "green", "summary": "5 checks OK"},
    {"name": "vector", "status": "yellow", "summary": "1 critical issue(s)"},
    {"name": "dataprepper", "status": "green", "summary": "12 checks OK"},
    {"name": "opensearch", "status": "green", "summary": "18 checks OK"},
    {"name": "dashboards", "status": "green", "summary": "8 checks OK"},
    {"name": "correlation", "status": "yellow", "summary": "1 critical issue(s)"}
  ],
  "urgent_findings": [
    {
      "rank": 1,
      "check_id": "corr.vector_dp.sensor_imbalance.10.0.0.12",
      "title": "Sensor sensor2 severely low throughput vs peers",
      "component": "correlation",
      "status": "yellow",
      "details": "Sent Δ=12 vs peer avg Δ=8900",
      "remediation": "Check Zeek, Vector, and network on this sensor."
    }
  ],
  "rates": {
    "vector_total_sent_delta": 27400,
    "dp_records_processed_delta": 27350,
    "vector_to_dp_drop_percent": 0.18,
    "dp_to_os_drop_percent": 0.1,
    "overall_freshness_seconds": 18.4,
    "os_search_latency_ms": 112.0,
    "dp_buffer_usage_ratio": 0.12,
    "dp_pipeline_latency_seconds": 0.42
  }
}
```

### `GET /checks?component=vector&status=red`
All check results, filterable by component and status.

### `GET /checks/{id}`
Single check by ID.

### `GET /components/{name}`
All checks for a single component (zeek, vector, dataprepper, opensearch, dashboards, correlation, data_quality).

### `GET /sensors/{sensor_ip}`
All checks for a single sensor.

### `GET /history?limit=100`
Historical status records from SQLite.

### `GET /metrics`
Prometheus metrics for the validator itself (scrape this with your own Prometheus).

---

## Example curl calls

```bash
# Get overall status
curl -s http://localhost:8000/status | jq .overall_status

# Get all RED checks
curl -s "http://localhost:8000/checks?status=red" | jq '[.[] | {id, title, details, remediation}]'

# Get all checks for Data Prepper
curl -s "http://localhost:8000/checks?component=dataprepper" | jq .

# Get sensor2 checks
curl -s "http://localhost:8000/sensors/10.0.0.12" | jq .

# Get Prometheus metrics
curl -s http://localhost:8000/metrics | grep ndr_

# Get history
curl -s "http://localhost:8000/history?limit=10" | jq '[.[] | {timestamp, overall_status, red_count}]'
```

---

## Environment Variables

### Core
| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `prod` | Environment name |
| `LOG_LEVEL` | `INFO` | Log level |
| `SCRAPE_INTERVAL_SECONDS` | `30` | How often to scrape all components |
| `REQUEST_TIMEOUT_SECONDS` | `5` | HTTP request timeout |
| `SQLITE_DB_PATH` | `/data/validator.db` | SQLite database path |

### Sensors
| Variable | Example | Description |
|---|---|---|
| `SENSOR_LIST` | `10.0.0.11,10.0.0.12` | Comma-separated sensor IPs |
| `EXPECTED_SENSOR_COUNT` | `3` | Alert if fewer sensors seen |
| `SENSOR_NAME_MAP_JSON` | `{"10.0.0.11":"s1"}` | Display name mapping |

### SSH / Zeek Direct Probing
| Variable | Default | Description |
|---|---|---|
| `ENABLE_SENSOR_SSH` | `false` | Enable SSH-based Zeek checks |
| `SENSOR_SSH_USER` | `vagrant` | SSH username |
| `SENSOR_SSH_PORT` | `22` | SSH port |
| `SENSOR_SSH_KEY_PATH` | `/run/secrets/sensor_ssh_key` | Private key path in container |
| `ZEEK_LOG_DIR` | `/opt/zeek/logs/current` | Zeek log directory on sensors |
| `ZEEK_SERVICE_NAME` | `zeek` | systemctl service name |

### Certificates
| Variable | Description |
|---|---|
| `CA_CERT_PATH` | Path to CA cert inside container (default: `/certs/ca/ca.crt`) |
| `DASHBOARDS_CA_CERT_PATH` | CA cert for Dashboards TLS (can be same) |
| `OPENSEARCH_CLIENT_CERT_PATH` | Optional mTLS client cert for OpenSearch |
| `DATAPREPPER_CLIENT_CERT_PATH` | Optional mTLS client cert for Data Prepper |

### Thresholds
| Variable | Default | Description |
|---|---|---|
| `STALE_DATA_THRESHOLD_SECONDS` | `120` | YELLOW freshness threshold |
| `CRITICAL_STALE_DATA_THRESHOLD_SECONDS` | `300` | RED freshness threshold |
| `MAX_VECTOR_TO_DP_DROP_PERCENT` | `5` | Max acceptable Vector→DP drop % |
| `MAX_DP_TO_OS_DROP_PERCENT` | `5` | Max acceptable DP→OS drop % |
| `MAX_DP_PIPELINE_LATENCY_SECONDS_WARN` | `5` | DP pipeline latency YELLOW |
| `MAX_DP_PIPELINE_LATENCY_SECONDS_CRIT` | `30` | DP pipeline latency RED |
| `HIGH_HEAP_THRESHOLD_PERCENT` | `85` | OpenSearch heap YELLOW threshold |
| `LOW_DISK_THRESHOLD_PERCENT` | `15` | Disk free % below which YELLOW |
| `ENABLE_DEBUG_INSECURE_SKIP_VERIFY` | `false` | **DANGER**: Disable TLS verification |

---

## Vector→DataPrepper Drop Rate and Intentional Filtering

### Why `VECTOR_DATAPREPPER_SINK_COMPONENTS` is required

Vector pipelines typically filter noisy logs before forwarding to Data Prepper:

```
zeek_raw → zeek_parse_json → zeek_filter → zeek_drop_azure_ips → … → dp_ingest
```

If the validator sums **all** Vector `sent_events` (sources + transforms + all sinks) and
compares it to Data Prepper `records_processed`, the drop rate will be massively inflated —
because transform components re-emit the same event multiple times through the pipeline.

Set `VECTOR_DATAPREPPER_SINK_COMPONENTS` to the `component_id` of the **final HTTP sink**
that delivers to Data Prepper:

```dotenv
# In your Vector config: [sinks.dp_ingest]
VECTOR_DATAPREPPER_SINK_COMPONENTS=dp_ingest
```

The validator then uses only `vector_component_sent_events_total{component_id="dp_ingest"}`
for the drop-rate numerator — which is the events that actually left Vector toward DP.

### Auto-detection (fallback)

If `VECTOR_DATAPREPPER_SINK_COMPONENTS` is not set, the validator tries to infer the sink:
- Finds all `component_kind="sink"` components
- Excludes `prometheus_exporter`, `prom_metrics`, and similar
- If **exactly one** HTTP sink remains → uses it automatically
- If **zero or multiple** → marks `corr.vector_dp.drop_rate` as **UNKNOWN** (not RED)

### Intentional filtering observability

Intentional discards from filter transforms are reported as a separate GREEN check
`corr.vector_dp.filtering` and are **never** counted as delivery loss:

```
vector_component_discarded_events_total{intentional="true",...}
```

This check shows the filtering reduction percentage so you can monitor filter effectiveness
without confusing it with a pipeline failure.

---

## Data Prepper Management Metrics

The validator scrapes Data Prepper's internal metrics (pipeline throughput, buffer usage,
latency, error counters) from the **management server**, which runs on a **separate port** from
the ingest endpoint.

### Port mapping

| Port | Purpose |
|------|---------|
| `2021` | Ingest (receives logs from Vector via HTTP/TLS) |
| `4900` | Management metrics (Prometheus scrape endpoint) |

> **Important**: Both ports must be exposed in your central-stack `docker-compose.yml`. The validator
> **cannot validate Data Prepper internals** if port 4900 is not reachable.

### Required central-stack docker-compose ports

```yaml
services:
  ndr-dataprepper:
    # ...
    ports:
      - "2021:2021"   # ingest
      - "4900:4900"   # management metrics
```

### Required data-prepper-config.yaml

```yaml
ssl: true
serverPort: 4900
metricRegistries:
  - Prometheus
authentication:
  http_basic:
    username: admin
    password: admin
```

### Validator .env settings

```dotenv
DATAPREPPER_HOST=<central-host>
DATAPREPPER_METRICS_SCHEME=https
DATAPREPPER_METRICS_PORT=4900
DATAPREPPER_METRICS_PATH=/metrics/sys
DATAPREPPER_USERNAME=admin
DATAPREPPER_PASSWORD=<password>

DATAPREPPER_INGEST_SCHEME=https
DATAPREPPER_INGEST_PORT=2021
DATAPREPPER_HEALTH_PATH=/health
DATAPREPPER_INGEST_USERNAME=<vector-user>
DATAPREPPER_INGEST_PASSWORD=<vector-password>
```

> **Health endpoint note**: If Data Prepper does not expose `/health` via `health_check_service`
> in the pipeline config, the validator will report the health check as YELLOW (not RED) and
> explain that the path is not exposed. Metrics and ingestion checks are unaffected.

---


Your CA cert must be mounted into the container at `/certs/ca/ca.crt`.

```yaml
# In docker-compose.yml (already configured):
volumes:
  - ./certs/ca:/certs/ca:ro
```

On the Docker host:
```bash
mkdir -p certs/ca
cp /your/ndr/ca.crt certs/ca/ca.crt
```

For optional client certificates (mTLS):
```bash
mkdir -p certs/client
cp /your/client.crt certs/client/client.crt
cp /your/client.key certs/client/client.key
# Then set in .env:
# OPENSEARCH_CLIENT_CERT_PATH=/certs/client/client.crt
# OPENSEARCH_CLIENT_KEY_PATH=/certs/client/client.key
```

---

## SSH Setup for Direct Zeek Checks

1. Generate or use an existing ED25519 key:
   ```bash
   ssh-keygen -t ed25519 -f secrets/sensor_ssh_key -N ""
   ```

2. Copy the public key to each sensor:
   ```bash
   ssh-copy-id -i secrets/sensor_ssh_key.pub vagrant@10.0.0.11
   ```

3. Enable SSH probing in `.env`:
   ```
   ENABLE_SENSOR_SSH=true
   SENSOR_SSH_USER=vagrant
   SSH_KEY_LOCAL_PATH=./secrets/sensor_ssh_key
   ```

4. The `docker-compose.yml` mounts the key at `/run/secrets/sensor_ssh_key` inside the container.

> **Security note**: The SSH key is mounted read-only. The validator user inside the container runs as a non-root user. Use a dedicated key with `command=` restrictions in `authorized_keys` if desired.

---

## Status Interpretation

| Status | Meaning |
|---|---|
| 🟢 **GREEN** | All checks passing within thresholds |
| 🟡 **YELLOW** | Degraded but functional — investigate promptly |
| 🔴 **RED** | Critical failure — likely silent data loss or service down |
| ⬜ **UNKNOWN** | No data yet or component unreachable |

### RED conditions include:
- Any sensor completely missing from recent OpenSearch data
- `overall_freshness_seconds > CRITICAL_STALE_DATA_THRESHOLD_SECONDS`
- TLS handshake failure delta > 0 with zero successful requests (protocol mismatch)
- Buffer write failures > 0
- Document errors > 0
- OpenSearch cluster status RED
- Zeek SSH probe failure

### YELLOW conditions include:
- One sensor significantly below peer throughput
- Buffer usage > 70%
- Freshness between STALE and CRITICAL thresholds
- Dashboards response > 1000ms

---

## Troubleshooting

### Validator shows UNKNOWN after startup
Wait 30–60 seconds for the first scrape cycle. Check `/readyz` to confirm DB and scheduler are ready.

### TLS verification failures
- Verify `CA_CERT_PATH` points to the correct CA cert
- Ensure the cert is mounted: `docker exec ndr-validator ls -la /certs/ca/`
- Check hostname matches the cert CN/SANs
- For debugging only: set `ENABLE_DEBUG_INSECURE_SKIP_VERIFY=true` temporarily

### Data Prepper auth failures
- Verify `DATAPREPPER_USERNAME` / `DATAPREPPER_PASSWORD` in `.env`
- Confirm the management server basic auth config in `data-prepper-config.yaml`

### Vector metrics not found
- Check that Vector is running on each sensor: `systemctl status vector`
- Verify the exporter port: `curl http://<sensor>:9598/metrics`
- The validator supports both current (`component_*`) and legacy (`events_*`) metric names

### OpenSearch freshness RED but cluster is GREEN
- Check Data Prepper buffer and document error metrics
- Look for rejected indexing requests in OpenSearch logs
- Verify index lifecycle policies are not blocking writes

### SSH probe timeout
- Verify sensor is reachable: `ssh -i secrets/sensor_ssh_key vagrant@<sensor>`
- Check `SENSOR_SSH_CONNECT_TIMEOUT_SECONDS` — increase if on high-latency links
- Ensure the sensor's firewall allows SSH from the validator container IP

---

## Assumptions

1. All TLS certificates are issued by the same internal CA mounted at `CA_CERT_PATH`
2. Vector exposes Prometheus metrics on port 9598 (configurable)
3. Data Prepper management server uses Basic Auth (no token auth)
4. OpenSearch uses HTTP Basic Auth (no SAML/OIDC for API access)
5. Zeek logs are JSON format (TSV format is not supported for parse checks)
6. The validator has network access to all pipeline components
7. SSH probing assumes the sensor user can run `zeekctl`, `systemctl`, `pgrep`, `df`, and `tail`

---

## Security Notes

- The validator stores no credentials in SQLite — only metric values and status snapshots
- TLS verification is **enabled by default** and cannot be disabled without an explicit env flag
- SSH keys are mounted read-only; the container runs as a non-root user
- Prometheus metrics at `/metrics` are unauthenticated — restrict access with a reverse proxy if needed
- Rotate credentials in `.env` and redeploy; no restart of the SQLite database is needed

---

## Future Improvements

- Alert routing (PagerDuty, Slack, webhook) via configurable notification channels
- Zeek local agent mode (no SSH required, sidecar container on each sensor)
- Multi-cluster OpenSearch support
- Historical trend graphs in the UI (Chart.js or similar)
- Per-index capacity forecasting
- Geo-IP enrichment validation
- Support for ISM policy health checks
- Optional Kafka/Kinesis intermediate stage support
- RBAC for the validator API
