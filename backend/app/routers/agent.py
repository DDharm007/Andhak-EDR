"""Agent enrollment, heartbeat, policy, and telemetry ingestion routes."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import ValidationError

from app.schemas import (
    EnrollmentRequest,
    EnrollmentTokenCreate,
    HeartbeatRequest,
    TelemetryBatchRequest,
)
from app.services.ingest import (
    AuthError,
    ConflictError,
    enroll_agent,
    get_agent_policy,
    ingest_telemetry_batch,
    issue_enrollment_token,
    record_heartbeat,
    verify_agent_credential,
)

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


def _extract_bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer credential.")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer credential.")
    return token


async def require_agent_auth(
    authorization: str | None = Header(default=None),
    x_endpoint_id: str | None = Header(default=None, alias="X-Endpoint-ID"),
) -> str:
    if not x_endpoint_id:
        raise HTTPException(status_code=401, detail="Missing X-Endpoint-ID header.")
    token = _extract_bearer(authorization)
    try:
        verify_agent_credential(x_endpoint_id, token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    return x_endpoint_id


@router.post("/enrollment-tokens", status_code=201)
def create_enrollment_token(payload: EnrollmentTokenCreate) -> dict[str, str]:
    # Note: RBAC admin JWT enforcement is wired in Stage 06; Stage 02 exposes local provisioning.
    return issue_enrollment_token(description=payload.description, ttl_hours=payload.ttl_hours)


@router.post("/enroll", status_code=201)
def enroll(payload: EnrollmentRequest) -> dict[str, Any]:
    try:
        return enroll_agent(payload)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/heartbeat")
def heartbeat(
    payload: HeartbeatRequest,
    endpoint_id: str = Depends(require_agent_auth),
) -> dict[str, Any]:
    try:
        return record_heartbeat(endpoint_id, payload)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.get("/policy")
def fetch_policy(endpoint_id: str = Depends(require_agent_auth)) -> dict[str, Any]:
    return get_agent_policy(endpoint_id)


@router.post("/telemetry", status_code=202)
async def ingest_telemetry(
    request: Request,
    endpoint_id: str = Depends(require_agent_auth),
    x_payload_sha256: str | None = Header(default=None, alias="X-Payload-SHA256"),
) -> dict[str, Any]:
    raw_body = await request.body()
    if x_payload_sha256 is not None:
        actual = hashlib.sha256(raw_body).hexdigest()
        if not hmac.compare_digest(actual.lower(), x_payload_sha256.strip().lower()):
            raise HTTPException(status_code=400, detail="Payload SHA-256 integrity check failed.")

    try:
        parsed = json.loads(raw_body.decode("utf-8"))
        batch = TelemetryBatchRequest.model_validate(parsed)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}") from exc
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    try:
        return ingest_telemetry_batch(endpoint_id, batch)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
