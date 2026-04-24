"""
HTTP client utilities – shared httpx client factories with TLS support.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

import httpx

from app.config import settings
from app.utils.tls import get_httpx_verify, classify_tls_error

logger = logging.getLogger(__name__)


def _make_client(
    ca_path: Optional[str] = None,
    auth: Optional[Tuple[str, str]] = None,
    timeout: Optional[float] = None,
) -> httpx.AsyncClient:
    """Create a configured httpx.AsyncClient."""
    verify = get_httpx_verify(ca_path)
    t = timeout or settings.REQUEST_TIMEOUT_SECONDS
    kwargs: Dict[str, Any] = {
        "verify": verify,
        "timeout": httpx.Timeout(t, connect=t),
        "follow_redirects": True,
        "limits": httpx.Limits(max_connections=20, max_keepalive_connections=5),
    }
    if auth:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


async def fetch_url(
    url: str,
    ca_path: Optional[str] = None,
    auth: Optional[Tuple[str, str]] = None,
    timeout: Optional[float] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, float, Optional[str]]:
    """
    Fetch a URL and return (status_code, body, latency_ms, error_string).
    On connection or TLS errors, returns (0, '', latency_ms, error_classification).
    """
    start = time.monotonic()
    try:
        async with _make_client(ca_path, auth, timeout) as client:
            resp = await client.get(url, headers=headers or {})
            latency = (time.monotonic() - start) * 1000
            return resp.status_code, resp.text, latency, None
    except httpx.ConnectError as e:
        latency = (time.monotonic() - start) * 1000
        classification = classify_tls_error(e)
        logger.warning("Connection error fetching %s: %s (%s)", url, e, classification)
        return 0, "", latency, classification
    except httpx.TimeoutException as e:
        latency = (time.monotonic() - start) * 1000
        logger.warning("Timeout fetching %s: %s", url, e)
        return 0, "", latency, "connection_timeout"
    except Exception as e:
        latency = (time.monotonic() - start) * 1000
        classification = classify_tls_error(e)
        logger.warning("Error fetching %s: %s (%s)", url, e, classification)
        return 0, "", latency, str(e)


async def fetch_json(
    url: str,
    ca_path: Optional[str] = None,
    auth: Optional[Tuple[str, str]] = None,
    timeout: Optional[float] = None,
) -> Tuple[Optional[Dict[str, Any]], float, Optional[str]]:
    """
    Fetch a URL expecting JSON. Returns (parsed_json, latency_ms, error_string).
    """
    start = time.monotonic()
    try:
        async with _make_client(ca_path, auth, timeout) as client:
            resp = await client.get(url)
            latency = (time.monotonic() - start) * 1000
            if resp.status_code == 401:
                return None, latency, "auth_failure"
            if resp.status_code == 403:
                return None, latency, "auth_forbidden"
            if resp.status_code >= 400:
                return None, latency, f"http_{resp.status_code}"
            return resp.json(), latency, None
    except httpx.ConnectError as e:
        latency = (time.monotonic() - start) * 1000
        return None, latency, classify_tls_error(e)
    except httpx.TimeoutException:
        latency = (time.monotonic() - start) * 1000
        return None, latency, "connection_timeout"
    except Exception as e:
        latency = (time.monotonic() - start) * 1000
        return None, latency, str(e)


async def post_json(
    url: str,
    body: Any = None,
    ca_path: Optional[str] = None,
    auth: Optional[Tuple[str, str]] = None,
    timeout: Optional[float] = None,
) -> Tuple[Optional[Dict[str, Any]], float, Optional[str]]:
    """POST JSON to a URL. Returns (response_json, latency_ms, error)."""
    start = time.monotonic()
    try:
        async with _make_client(ca_path, auth, timeout) as client:
            resp = await client.post(url, json=body)
            latency = (time.monotonic() - start) * 1000
            if resp.status_code >= 400:
                return None, latency, f"http_{resp.status_code}"
            try:
                return resp.json(), latency, None
            except Exception:
                return None, latency, None
    except httpx.ConnectError as e:
        latency = (time.monotonic() - start) * 1000
        return None, latency, classify_tls_error(e)
    except httpx.TimeoutException:
        latency = (time.monotonic() - start) * 1000
        return None, latency, "connection_timeout"
    except Exception as e:
        latency = (time.monotonic() - start) * 1000
        return None, latency, str(e)
