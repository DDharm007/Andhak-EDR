"""ANDHAK EDR FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Query

from app import __version__
from app.config import get_settings
from app.db import init_database
from app.routers.agent import router as agent_router
from app.services.ingest import list_endpoints, list_telemetry_events


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_database(get_settings())
    yield


app = FastAPI(
    title="ANDHAK EDR API",
    version=__version__,
    description=(
        "ANDHAK Endpoint Detection & Response backend "
        "(local SQLite primary, zero-AI deterministic engine)."
    ),
    lifespan=lifespan,
)
app.include_router(agent_router)


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    cfg = get_settings()
    return {
        "status": "ok",
        "service": "andhak-edr-backend",
        "version": __version__,
        "mode": "demo" if cfg.demo_mode else "live",
        "database_path": str(cfg.resolved_db_path),
    }


@app.get("/api/v1/endpoints")
def endpoints() -> dict[str, Any]:
    items = list_endpoints()
    return {"items": items, "total": len(items)}


@app.get("/api/v1/telemetry/events")
def telemetry_events(
    endpoint_id: str | None = None,
    category: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    items = list_telemetry_events(endpoint_id=endpoint_id, category=category, limit=limit)
    return {"items": items, "total": len(items)}
