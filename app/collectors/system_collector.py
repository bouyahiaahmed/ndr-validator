"""
System collector – lightweight validator self-metrics (memory, uptime).
Does not probe external systems; used for validator health reporting.
"""
from __future__ import annotations
import os
import time
import logging

logger = logging.getLogger(__name__)
_start_time = time.monotonic()


def get_validator_uptime_seconds() -> float:
    return time.monotonic() - _start_time


def get_process_memory_mb() -> float:
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1]) / 1024
    except Exception:
        pass
    return 0.0
