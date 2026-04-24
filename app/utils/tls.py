"""
TLS/SSL utilities: build SSL contexts, verify certs, detect mismatches.
"""
from __future__ import annotations

import logging
import os
import ssl
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)


def build_ssl_context(
    ca_path: Optional[str] = None,
    client_cert_path: Optional[str] = None,
    client_key_path: Optional[str] = None,
    verify: bool = True,
) -> ssl.SSLContext:
    """Build an SSL context for HTTPS connections."""
    ctx = ssl.create_default_context()

    if not verify or settings.ENABLE_DEBUG_INSECURE_SKIP_VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning("TLS verification disabled – DEBUG mode only")
        return ctx

    ca = ca_path or settings.CA_CERT_PATH
    if ca and os.path.isfile(ca):
        ctx.load_verify_locations(ca)
        logger.debug("Loaded CA cert from %s", ca)
    else:
        logger.debug("No custom CA cert found at %s, using system defaults", ca)

    if client_cert_path and client_key_path:
        if os.path.isfile(client_cert_path) and os.path.isfile(client_key_path):
            ctx.load_cert_chain(client_cert_path, client_key_path)
            logger.debug("Loaded client cert from %s", client_cert_path)

    return ctx


def get_httpx_verify(
    ca_path: Optional[str] = None,
    skip_verify: bool = False,
) -> "str | bool":
    """Return the verify parameter for httpx clients."""
    if skip_verify or settings.ENABLE_DEBUG_INSECURE_SKIP_VERIFY:
        return False

    ca = ca_path or settings.CA_CERT_PATH
    if ca and os.path.isfile(ca):
        return ca
    return True


def classify_tls_error(error: Exception) -> str:
    """Classify a TLS error into a human-readable category."""
    msg = str(error).lower()
    if "certificate verify failed" in msg:
        return "certificate_trust_failure"
    if "hostname mismatch" in msg or "doesn't match" in msg:
        return "hostname_mismatch"
    if "ssl" in msg and ("eof" in msg or "alert" in msg):
        return "tls_handshake_failure"
    if "connection refused" in msg:
        return "endpoint_unreachable"
    if "timeout" in msg:
        return "connection_timeout"
    if "http" in msg and "https" in msg:
        return "plaintext_to_tls_port"
    return "unknown_tls_error"
