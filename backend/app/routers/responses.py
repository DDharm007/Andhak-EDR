"""Stage 05 API routes: controlled endpoint response, quarantine vault, and audit log."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.auth import require_role
from app.config import get_settings
from app.response.audit import list_audit_logs, verify_audit_chain
from app.response.engine import (
    ConflictActionError,
    ResourceNotFoundError,
    decide_response_action,
    initiate_rollback,
    list_quarantine_items,
    list_response_actions,
    propose_response_action,
)
from app.response.safety import ProtectedTargetError

router = APIRouter(prefix="/api/v1", tags=["response-audit"])


class ResponseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str = Field(min_length=4, max_length=64)
    incident_id: str | None = Field(default=None, max_length=64)
    action_type: Literal[
        "isolate_endpoint",
        "release_isolation",
        "terminate_process",
        "quarantine_file",
        "restore_file",
        "block_network_indicator",
        "push_policy",
    ]
    target_value: str = Field(min_length=1, max_length=1024)
    target_metadata: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=3, max_length=1000)


class ResponseDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=1000)


class ResponseRollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="Controlled analyst recovery", max_length=1000)


@router.get("/responses")
def get_responses(
    endpoint_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    _: dict[str, Any] = Depends(require_role("admin", "responder", "analyst", "readonly_demo")),
) -> dict[str, Any]:
    items = list_response_actions(
        endpoint_id=endpoint_id,
        status=status,
        limit=limit,
        settings=get_settings(),
    )
    return {"items": items, "total": len(items)}


@router.post("/responses", status_code=201)
def create_response_proposal(
    payload: ResponseCreateRequest,
    actor: dict[str, Any] = Depends(require_role("admin", "responder", "analyst")),
) -> Any:
    try:
        return propose_response_action(
            endpoint_id=payload.endpoint_id,
            action_type=payload.action_type,
            target_value=payload.target_value,
            reason=payload.reason,
            actor=actor,
            incident_id=payload.incident_id,
            target_metadata=payload.target_metadata,
            settings=get_settings(),
        )
    except ResourceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ProtectedTargetError as exc:
        return JSONResponse(status_code=422, content=exc.to_envelope())
    except ConflictActionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/responses/{action_id}/decision")
def decide_response(
    action_id: str,
    payload: ResponseDecisionRequest,
    actor: dict[str, Any] = Depends(require_role("admin", "responder")),
) -> dict[str, Any]:
    try:
        return decide_response_action(
            action_id=action_id,
            decision=payload.decision,
            actor=actor,
            note=payload.note,
            settings=get_settings(),
        )
    except ResourceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ConflictActionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/responses/{action_id}/rollback", status_code=201)
def rollback_response(
    action_id: str,
    payload: ResponseRollbackRequest | None = None,
    actor: dict[str, Any] = Depends(require_role("admin", "responder")),
) -> Any:
    reason = payload.reason if payload else "Controlled analyst recovery"
    try:
        return initiate_rollback(
            action_id=action_id,
            actor=actor,
            reason=reason,
            settings=get_settings(),
        )
    except ResourceNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ProtectedTargetError as exc:
        return JSONResponse(status_code=422, content=exc.to_envelope())
    except ConflictActionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/quarantine")
def get_quarantine(
    endpoint_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    _: dict[str, Any] = Depends(require_role("admin", "responder", "analyst", "readonly_demo")),
) -> dict[str, Any]:
    items = list_quarantine_items(
        endpoint_id=endpoint_id,
        status=status,
        limit=limit,
        settings=get_settings(),
    )
    return {"items": items, "total": len(items)}


@router.get("/audit")
def get_audit_logs(
    action: str | None = None,
    resource_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    verify_chain: bool = True,
    _: dict[str, Any] = Depends(require_role("admin", "responder", "analyst", "readonly_demo")),
) -> dict[str, Any]:
    cfg = get_settings()
    items = list_audit_logs(
        action=action,
        resource_type=resource_type,
        limit=limit,
        settings=cfg,
    )
    chain = verify_audit_chain(cfg) if verify_chain else None
    return {"items": items, "total": len(items), "chain_verification": chain}
