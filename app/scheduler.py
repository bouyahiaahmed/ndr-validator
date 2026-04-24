"""
Scheduler – periodic scrape cycle with overlap prevention.
"""
from __future__ import annotations
import asyncio
import logging
from app.config import settings

logger = logging.getLogger(__name__)
_running = False


async def start_scheduler() -> None:
    """Start the background scheduler loop."""
    global _running
    from app.services.evaluator import run_scrape_cycle, mark_scheduler_ready
    _running = True
    mark_scheduler_ready()
    logger.info("Scheduler started, interval=%ds", settings.SCRAPE_INTERVAL_SECONDS)

    _lock = asyncio.Lock()

    async def _tick():
        if _lock.locked():
            logger.warning("Previous scrape still running, skipping cycle")
            return
        async with _lock:
            try:
                await run_scrape_cycle()
            except Exception as e:
                logger.error("Scrape cycle error: %s", e, exc_info=True)
                from app import metrics as prom
                prom.scrape_errors_total.inc()

    # Run first cycle immediately
    await _tick()

    while _running:
        await asyncio.sleep(settings.SCRAPE_INTERVAL_SECONDS)
        await _tick()


def stop_scheduler() -> None:
    global _running
    _running = False
