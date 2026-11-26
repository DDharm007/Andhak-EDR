"""Public read-only demonstration scenarios and WebSocket replay routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from app.config import get_settings
from app.demo.replay import list_demo_scenarios, seed_demo_scenario

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])


@router.get("/scenarios")
def get_demo_scenarios() -> dict[str, Any]:
    cfg = get_settings()
    items = list_demo_scenarios()
    return {
        "demo_mode": cfg.demo_mode,
        "items": items,
        "total": len(items),
    }


@router.post("/replay/{scenario_id}")
def replay_demo_scenario(scenario_id: str) -> dict[str, Any]:
    cfg = get_settings()
    try:
        return seed_demo_scenario(scenario_id=scenario_id, settings=cfg)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
