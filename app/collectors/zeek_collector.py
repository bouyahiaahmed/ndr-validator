"""
Zeek direct collector – SSH-based probing of sensor Zeek instances.
"""
from __future__ import annotations
import json
import logging
from typing import Any, Dict, List, Optional
from app.config import settings
from app.utils.ssh import (
    check_zeekctl_status, check_service_status, check_process_running,
    check_directory_exists, check_log_freshness, tail_log_file,
    check_disk_usage, check_process_resources, list_log_files,
    is_ssh_available, SSHResult, run_ssh_command,
)

logger = logging.getLogger(__name__)
KEY_LOGS = ["conn.log", "dns.log", "http.log", "ssl.log", "files.log"]
OPTIONAL_LOGS = ["weird.log", "notice.log", "stats.log", "capture_loss.log"]

class ZeekSensorResult:
    def __init__(self, sensor_ip: str):
        self.sensor_ip = sensor_ip
        self.ssh_reachable = False
        self.ssh_error: Optional[str] = None
        self.zeek_running = False
        self.zeek_status_detail = ""
        self.zeekctl_available = False
        self.zeekctl_output = ""
        self.log_dir_exists = False
        self.existing_logs: List[str] = []
        self.missing_key_logs: List[str] = []
        self.log_freshness: Dict[str, float] = {}
        self.stale_logs: List[str] = []
        self.log_parse_ok: Dict[str, bool] = {}
        self.disk_used_percent: Optional[float] = None
        self.zeek_cpu: Optional[float] = None
        self.zeek_mem: Optional[float] = None
        self.vector_cpu: Optional[float] = None
        self.vector_mem: Optional[float] = None
        self.vector_running = False
        self.log_freeze_detected = False

async def probe_sensor(sensor_ip: str) -> ZeekSensorResult:
    result = ZeekSensorResult(sensor_ip)
    if not await is_ssh_available():
        result.ssh_error = "SSH not configured"
        return result

    # 1. SSH reachability via simple command
    r = await run_ssh_command(sensor_ip, "echo ok")
    if not r.success:
        result.ssh_error = r.error or "SSH unreachable"
        return result
    result.ssh_reachable = True

    # 2. Zeek service/process
    zctl = await check_zeekctl_status(sensor_ip)
    if "zeekctl not found" not in zctl.stdout:
        result.zeekctl_available = True
        result.zeekctl_output = zctl.stdout.strip()
        result.zeek_running = zctl.success and "running" in zctl.stdout.lower()
    else:
        svc = await check_service_status(sensor_ip, settings.ZEEK_SERVICE_NAME)
        result.zeek_status_detail = svc.stdout.strip()
        result.zeek_running = "active" in svc.stdout.lower()
        if not result.zeek_running:
            proc = await check_process_running(sensor_ip, "zeek")
            try:
                result.zeek_running = int(proc.stdout.strip()) > 0
            except ValueError:
                pass

    # 3. Log directory
    dcheck = await check_directory_exists(sensor_ip, settings.ZEEK_LOG_DIR)
    result.log_dir_exists = "exists" in dcheck.stdout

    if not result.log_dir_exists:
        return result

    # 4. List log files
    lfiles = await list_log_files(sensor_ip, settings.ZEEK_LOG_DIR)
    if lfiles.success:
        result.existing_logs = [l.split("/")[-1] for l in lfiles.stdout.strip().splitlines() if l.strip()]

    # 5. Key log existence and freshness
    for lf in KEY_LOGS:
        if lf not in result.existing_logs:
            result.missing_key_logs.append(lf)
            continue
        fr = await check_log_freshness(sensor_ip, settings.ZEEK_LOG_DIR, lf)
        if fr.success:
            lines = fr.stdout.strip().splitlines()
            if len(lines) >= 2:
                try:
                    mtime = int(lines[0])
                    now = int(lines[1])
                    age = now - mtime
                    result.log_freshness[lf] = float(age)
                    if age > settings.STALE_DATA_THRESHOLD_SECONDS:
                        result.stale_logs.append(lf)
                except (ValueError, IndexError):
                    pass

    # 6. JSON parse check for key logs
    for lf in KEY_LOGS:
        if lf in result.existing_logs:
            tail = await tail_log_file(sensor_ip, settings.ZEEK_LOG_DIR, lf, 2)
            if tail.success and tail.stdout.strip():
                last_line = tail.stdout.strip().splitlines()[-1]
                try:
                    json.loads(last_line)
                    result.log_parse_ok[lf] = True
                except (json.JSONDecodeError, ValueError):
                    result.log_parse_ok[lf] = False

    # 7. Optional logs freshness
    for lf in OPTIONAL_LOGS:
        if lf in result.existing_logs:
            fr = await check_log_freshness(sensor_ip, settings.ZEEK_LOG_DIR, lf)
            if fr.success:
                lines = fr.stdout.strip().splitlines()
                if len(lines) >= 2:
                    try:
                        result.log_freshness[lf] = float(int(lines[1]) - int(lines[0]))
                    except (ValueError, IndexError):
                        pass

    # 8. Disk usage
    du = await check_disk_usage(sensor_ip, settings.ZEEK_LOG_DIR)
    if du.success:
        try:
            result.disk_used_percent = float(du.stdout.strip())
        except ValueError:
            pass

    # 9. Process resources
    zres = await check_process_resources(sensor_ip, "zeek")
    if zres.success and zres.stdout.strip():
        parts = zres.stdout.strip().split()
        if len(parts) >= 2:
            try:
                result.zeek_cpu = float(parts[0])
                result.zeek_mem = float(parts[1])
            except ValueError:
                pass
    vres = await check_process_resources(sensor_ip, "vector")
    if vres.success and vres.stdout.strip():
        parts = vres.stdout.strip().split()
        if len(parts) >= 2:
            try:
                result.vector_cpu = float(parts[0])
                result.vector_mem = float(parts[1])
            except ValueError:
                pass
        result.vector_running = True

    # 10. Log freeze detection
    if result.zeek_running and result.stale_logs:
        result.log_freeze_detected = True

    return result

async def probe_all_sensors() -> List[ZeekSensorResult]:
    import asyncio
    if not await is_ssh_available():
        return []
    tasks = [probe_sensor(ip) for ip in settings.sensor_ips]
    return await asyncio.gather(*tasks) if tasks else []
