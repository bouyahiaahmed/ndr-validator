"""
SSH utilities for direct sensor probing (Zeek/Vector process and log checks).
Uses asyncssh for async SSH operations with timeout and error handling.
"""
from __future__ import annotations
import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Optional
from app.config import settings

logger = logging.getLogger(__name__)

try:
    import asyncssh
    HAS_ASYNCSSH = True
except ImportError:
    HAS_ASYNCSSH = False
    logger.info("asyncssh not installed; SSH sensor probing will be unavailable")


@dataclass
class SSHResult:
    """Result of an SSH command execution."""
    success: bool = False
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    error: str = ""
    duration_ms: float = 0.0


async def run_ssh_command(host: str, command: str, timeout: Optional[int] = None) -> SSHResult:
    """Run a single command over SSH on a sensor."""
    if not HAS_ASYNCSSH:
        return SSHResult(success=False, error="asyncssh not installed")
    if not settings.ENABLE_SENSOR_SSH:
        return SSHResult(success=False, error="SSH probing disabled")

    t = timeout or settings.SENSOR_SSH_CONNECT_TIMEOUT_SECONDS
    key_path = settings.SENSOR_SSH_KEY_PATH

    import time
    start = time.monotonic()

    try:
        conn_opts = {
            "host": host,
            "port": settings.SENSOR_SSH_PORT,
            "username": settings.SENSOR_SSH_USER,
            "known_hosts": None,  # Accept all host keys (internal network)
            "connect_timeout": t,
        }
        if key_path and os.path.isfile(key_path):
            conn_opts["client_keys"] = [key_path]

        async with asyncssh.connect(**conn_opts) as conn:
            result = await asyncio.wait_for(conn.run(command), timeout=t + 5)
            dur = (time.monotonic() - start) * 1000
            return SSHResult(
                success=result.exit_status == 0,
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                exit_code=result.exit_status or 0,
                duration_ms=dur,
            )
    except asyncio.TimeoutError:
        dur = (time.monotonic() - start) * 1000
        return SSHResult(success=False, error="SSH command timeout", duration_ms=dur)
    except Exception as e:
        dur = (time.monotonic() - start) * 1000
        logger.warning("SSH error on %s: %s", host, e)
        return SSHResult(success=False, error=str(e), duration_ms=dur)


async def check_service_status(host: str, service_name: str) -> SSHResult:
    """Check if a systemd service is active."""
    return await run_ssh_command(host, f"systemctl is-active {service_name} 2>/dev/null || echo inactive")


async def check_process_running(host: str, process_name: str) -> SSHResult:
    """Check if a process is running via pgrep."""
    return await run_ssh_command(host, f"pgrep -c {process_name} 2>/dev/null || echo 0")


async def check_zeekctl_status(host: str) -> SSHResult:
    """Run zeekctl status if available."""
    return await run_ssh_command(host, "command -v zeekctl >/dev/null 2>&1 && zeekctl status 2>&1 || echo 'zeekctl not found'")


async def check_log_freshness(host: str, log_dir: str, log_file: str) -> SSHResult:
    """Check mtime of a log file and return seconds since last modification."""
    cmd = f'stat -c %Y "{log_dir}/{log_file}" 2>/dev/null && date +%s'
    return await run_ssh_command(host, cmd)


async def tail_log_file(host: str, log_dir: str, log_file: str, lines: int = 3) -> SSHResult:
    """Tail the last N lines of a log file."""
    return await run_ssh_command(host, f'tail -n {lines} "{log_dir}/{log_file}" 2>/dev/null')


async def check_directory_exists(host: str, path: str) -> SSHResult:
    """Check if a directory exists."""
    return await run_ssh_command(host, f'test -d "{path}" && echo "exists" || echo "missing"')


async def check_disk_usage(host: str, path: str) -> SSHResult:
    """Get disk usage percentage for a given path."""
    return await run_ssh_command(host, f"df --output=pcent '{path}' 2>/dev/null | tail -1 | tr -d ' %'")


async def check_process_resources(host: str, process_name: str) -> SSHResult:
    """Get CPU and memory usage for a process."""
    return await run_ssh_command(host, f"ps aux | grep '[{process_name[0]}]{process_name[1:]}' | awk '{{print $3, $4, $6}}'")


async def list_log_files(host: str, log_dir: str) -> SSHResult:
    """List log files in the Zeek log directory."""
    return await run_ssh_command(host, f'ls -la "{log_dir}/"*.log 2>/dev/null | awk \'{{print $NF}}\'')


async def is_ssh_available() -> bool:
    """Check if SSH is configured and available."""
    return HAS_ASYNCSSH and settings.ENABLE_SENSOR_SSH
