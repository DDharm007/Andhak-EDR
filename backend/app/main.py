"""ANDHAK EDR FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import get_settings
from app.db import init_database
from app.routers.agent import router as agent_router
from app.routers.auth import router as auth_router
from app.routers.detections import router as detections_router
from app.routers.fleet import router as fleet_router
from app.routers.forensics import router as forensics_router
from app.routers.policies import router as policies_router
from app.routers.responses import router as responses_router
from app.routers.soc_bridge import router as soc_bridge_router
from app.routers.ws import router as ws_router
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(agent_router)
app.include_router(fleet_router)
app.include_router(detections_router)
app.include_router(forensics_router)
app.include_router(responses_router)
app.include_router(policies_router)
app.include_router(soc_bridge_router)
app.include_router(ws_router)


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
    severity: str | None = None,
    origin: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    items = list_telemetry_events(endpoint_id=endpoint_id, category=category, limit=limit)
    if severity:
        items = [i for i in items if i.get("severity") == severity]
    if origin:
        items = [i for i in items if i.get("telemetry_origin") == origin]
    return {"items": items, "total": len(items)}
