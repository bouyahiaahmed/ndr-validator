"""
FastAPI application entry point.
"""
from __future__ import annotations
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os

from app.logging_config import setup_logging
from app import db
from app.scheduler import start_scheduler, stop_scheduler
from app import metrics as prom
from app.api import routes_status, routes_checks, routes_history, routes_metrics

setup_logging()
logger = logging.getLogger(__name__)

_scheduler_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler_task
    # Startup
    logger.info("NDR Pipeline Validator starting")
    await db.init_db()
    prom.validator_info.info({"version": "1.0.0", "env": __import__("app.config", fromlist=["settings"]).settings.APP_ENV})
    _scheduler_task = asyncio.create_task(start_scheduler())
    yield
    # Shutdown
    logger.info("NDR Pipeline Validator shutting down")
    stop_scheduler()
    if _scheduler_task:
        _scheduler_task.cancel()
        try:
            await _scheduler_task
        except asyncio.CancelledError:
            pass
    await db.close_db()


app = FastAPI(
    title="NDR Pipeline Validator",
    description="Production-grade integrity validator for Zeek→Vector→DataPrepper→OpenSearch pipeline",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Static files and templates
_static_dir = os.path.join(os.path.dirname(__file__), "static")
_template_dir = os.path.join(os.path.dirname(__file__), "templates")
if os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

templates = Jinja2Templates(directory=_template_dir)

# Include routers
app.include_router(routes_status.router)
app.include_router(routes_checks.router)
app.include_router(routes_history.router)
app.include_router(routes_metrics.router)

# UI routes
from fastapi import Request
from fastapi.responses import HTMLResponse


@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def index(request: Request):
    from app.services.evaluator import get_latest_summary
    summary = get_latest_summary()
    return templates.TemplateResponse("index.html", {"request": request, "summary": summary})


@app.get("/components/{name}", response_class=HTMLResponse, tags=["UI"], include_in_schema=False)
async def component_page(request: Request, name: str):
    from app.services.evaluator import get_latest_summary
    from fastapi.responses import RedirectResponse
    summary = get_latest_summary()
    if summary is None:
        return RedirectResponse("/")
    comp = next((c for c in summary.components if c.name.value == name), None)
    if comp is None:
        return RedirectResponse("/")
    return templates.TemplateResponse("component.html", {"request": request, "comp": comp})


@app.get("/sensors/{sensor_id}", response_class=HTMLResponse, tags=["UI"], include_in_schema=False)
async def sensor_page(request: Request, sensor_id: str):
    from app.services.evaluator import get_latest_summary
    from fastapi.responses import RedirectResponse
    summary = get_latest_summary()
    if summary is None:
        return RedirectResponse("/")
    sen = next((s for s in summary.sensors if s.sensor_ip == sensor_id or s.display_name == sensor_id), None)
    if sen is None:
        return RedirectResponse("/")
    return templates.TemplateResponse("sensor.html", {"request": request, "sensor": sen})


@app.get("/history", response_class=HTMLResponse, tags=["UI"], include_in_schema=False)
async def history_page(request: Request):
    records = await db.get_history(limit=200)
    return templates.TemplateResponse("history.html", {"request": request, "records": records})


@app.get("/healthz", tags=["Health"])
async def healthz():
    return {"status": "ok"}


@app.get("/readyz", tags=["Health"])
async def readyz():
    from app.services.evaluator import is_scheduler_ready
    db_ok = await db.is_db_ready()
    sched_ok = is_scheduler_ready()
    ready = db_ok and sched_ok
    return {
        "ready": ready,
        "db": db_ok,
        "scheduler": sched_ok,
    }
