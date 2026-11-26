"""API routes for ANDHAK SOC integration bridge."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.soc_bridge.bridge import (
    get_soc_bridge_status,
    handle_soc_response_request,
    list_soc_normalized_events,
    sync_with_soc,
    verify_bridge_signature,
)

router = APIRouter(prefix="/api/v1/soc-bridge", tags=["soc-bridge"])


@router.get("/status")
def soc_bridge_status() -> dict[str, Any]:
    return get_soc_bridge_status(get_settings())


@router.get("/events")
def soc_bridge_events(limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
    items = list_soc_normalized_events(limit=limit, settings=get_settings())
    return {"items": items, "total": len(items)}


@router.post("/sync")
async def trigger_soc_sync() -> dict[str, Any]:
    cfg = get_settings()
    if cfg.demo_mode:
        raise HTTPException(status_code=403, detail="Sync disabled in public demo mode.")
    return await sync_with_soc(cfg)


@router.post("/responses/request")
async def soc_request_response(
    request: Request,
    x_andhak_timestamp: str | None = Header(default=None, alias="X-ANDHAK-Timestamp"),
    x_andhak_signature: str | None = Header(default=None, alias="X-ANDHAK-Signature"),
) -> Any:
    cfg = get_settings()
    if cfg.demo_mode:
        raise HTTPException(status_code=403, detail="Bridge mutations disabled in demo mode.")
    raw_body = await request.body()
    ok, err = verify_bridge_signature(
        cfg.soc_bridge_secret,
        x_andhak_timestamp,
        raw_body,
        x_andhak_signature,
    )
    if not ok:
        raise HTTPException(status_code=401, detail=err)

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Malformed JSON body: {exc}") from exc

    code, body = handle_soc_response_request(payload, settings=cfg)
    return JSONResponse(status_code=code, content=body)
