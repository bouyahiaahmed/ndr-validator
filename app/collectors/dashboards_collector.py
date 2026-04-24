"""
OpenSearch Dashboards collector – layered probing with graceful fallbacks.
"""
from __future__ import annotations
import logging
import re
from typing import Dict, Optional
from app.config import settings
from app.utils.http import fetch_url, fetch_json

logger = logging.getLogger(__name__)

class DashboardsScrapeResult:
    def __init__(self):
        self.reachable = False
        self.tls_ok = False
        self.error: Optional[str] = None
        self.latency_ms = 0.0
        self.status_code = 0
        self.body_looks_like_dashboards = False
        self.redirect_loop = False
        self.has_5xx = False
        self.static_asset_ok = False
        self.status_api_available = False
        self.status_api_data: Optional[Dict] = None
        self.status_api_overall: Optional[str] = None
        self.auth_ok = False
        self.response_time_ms = 0.0

async def scrape_dashboards() -> DashboardsScrapeResult:
    result = DashboardsScrapeResult()
    base = settings.dashboards_base_url
    ca = settings.DASHBOARDS_CA_CERT_PATH

    # Layer 1: basic reachability
    code, body, lat, err = await fetch_url(base + "/", ca_path=ca)
    result.latency_ms = lat
    result.response_time_ms = lat
    result.status_code = code
    if err:
        result.error = err
        if "certificate" in str(err).lower() or "tls" in str(err).lower():
            result.reachable = True
        return result
    if code >= 500:
        result.reachable = True
        result.tls_ok = True
        result.has_5xx = True
        result.error = f"HTTP {code}"
        return result
    result.reachable = True
    result.tls_ok = True

    # Detect dashboards UI
    body_lower = body.lower() if body else ""
    result.body_looks_like_dashboards = any(
        kw in body_lower for kw in ["opensearch", "dashboards", "osd-app", "login", "kibana"]
    )

    # Detect redirect loop
    if body_lower.count("redirect") > 3 or body_lower.count("location:") > 3:
        result.redirect_loop = True

    # Layer 2: static asset sanity
    asset_url = _discover_asset(body, base)
    if asset_url:
        a_code, _, a_lat, a_err = await fetch_url(asset_url, ca_path=ca)
        result.static_asset_ok = a_code == 200 and not a_err

    # Layer 3: optional status API
    if settings.DASHBOARDS_ENABLE_STATUS_API_CHECK:
        status_url = base + settings.DASHBOARDS_STATUS_PATH
        auth = (settings.DASHBOARDS_USERNAME, settings.DASHBOARDS_PASSWORD)
        s_data, s_lat, s_err = await fetch_json(status_url, ca, auth)
        if s_data and not s_err:
            result.status_api_available = True
            result.status_api_data = s_data
            result.status_api_overall = s_data.get("status", {}).get("overall", {}).get("state", "unknown") if isinstance(s_data.get("status"), dict) else str(s_data.get("status", "unknown"))

    # Layer 4: authenticated check
    if settings.DASHBOARDS_USERNAME:
        auth = (settings.DASHBOARDS_USERNAME, settings.DASHBOARDS_PASSWORD)
        a_code, a_body, a_lat, a_err = await fetch_url(
            base + "/app/home", ca_path=ca, auth=auth
        )
        result.auth_ok = a_code in (200, 302) and not a_err

    return result

def _discover_asset(html: str, base_url: str) -> Optional[str]:
    if not html:
        return None
    m = re.search(r'(src|href)=["\']([^"\']+\.(js|css))', html)
    if m:
        path = m.group(2)
        if path.startswith("http"):
            return path
        return base_url.rstrip("/") + "/" + path.lstrip("/")
    return None
