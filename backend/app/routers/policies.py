"""Stage 05 API routes: endpoint policy management and data retention settings."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.auth import require_role
from app.config import get_settings
from app.db import DEFAULT_POLICY_ID, get_connection, utc_now_iso
from app.response.audit import append_audit_log

router = APIRouter(prefix="/api/v1", tags=["policies"])


class PolicyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fim_paths: list[str] | None = None
    exclusions: list[str] | None = None
    heartbeat_seconds: int | None = Field(default=None, ge=5, le=300)
    process_poll_ms: int | None = Field(default=None, ge=500, le=60000)
    network_poll_ms: int | None = Field(default=None, ge=1000, le=60000)
    system_poll_ms: int | None = Field(default=None, ge=1000, le=120000)
    batch_max_events: int | None = Field(default=None, ge=1, le=500)
    flush_interval_ms: int | None = Field(default=None, ge=500, le=60000)
    intel_external_enabled: bool | None = None
    allow_file_upload: bool | None = None
    retention_days: dict[str, int] | None = None


def _read_policies_payload() -> dict[str, Any]:
    cfg = get_settings()
    with get_connection(cfg) as conn:
        pol = conn.execute(
            "SELECT * FROM policies WHERE policy_id = ?",
            (DEFAULT_POLICY_ID,),
        ).fetchone()
        ret_rows = conn.execute(
            "SELECT domain, retention_days, updated_at FROM retention_policies ORDER BY domain ASC"
        ).fetchall()

    policy_obj = {
        "policy_id": pol["policy_id"],
        "name": pol["name"],
        "version": pol["version"],
        "fim_paths": json.loads(pol["fim_paths_json"]),
        "exclusions": json.loads(pol["exclusions_json"]),
        "collection_intervals": json.loads(pol["collection_intervals_json"]),
        "intel_external_enabled": bool(pol["intel_external_enabled"]),
        "allow_file_upload": bool(pol["allow_file_upload"]),
        "updated_by": pol["updated_by"],
        "updated_at": pol["updated_at"],
    }
    retention_obj = {r["domain"]: r["retention_days"] for r in ret_rows}
    return {"policy": policy_obj, "retention": retention_obj}


@router.get("/policies")
def get_policies(
    _: dict[str, Any] = Depends(require_role("admin", "responder", "analyst", "readonly_demo")),
) -> dict[str, Any]:
    return _read_policies_payload()


@router.put("/policies")
def update_policies(
    payload: PolicyUpdateRequest,
    actor: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    cfg = get_settings()
    now = utc_now_iso()
    with get_connection(cfg) as conn:
        pol = conn.execute(
            "SELECT * FROM policies WHERE policy_id = ?",
            (DEFAULT_POLICY_ID,),
        ).fetchone()
        fim_paths = (
            payload.fim_paths
            if payload.fim_paths is not None
            else json.loads(pol["fim_paths_json"])
        )
        exclusions = (
            payload.exclusions
            if payload.exclusions is not None
            else json.loads(pol["exclusions_json"])
        )
        intervals = json.loads(pol["collection_intervals_json"])
        for k in (
            "heartbeat_seconds",
            "process_poll_ms",
            "network_poll_ms",
            "system_poll_ms",
            "batch_max_events",
            "flush_interval_ms",
        ):
            val = getattr(payload, k)
            if val is not None:
                intervals[k] = val
        intel_ext = (
            int(payload.intel_external_enabled)
            if payload.intel_external_enabled is not None
            else pol["intel_external_enabled"]
        )
        allow_up = (
            int(payload.allow_file_upload)
            if payload.allow_file_upload is not None
            else pol["allow_file_upload"]
        )
        new_version = int(pol["version"]) + 1
        conn.execute(
            """
            UPDATE policies
            SET version = ?, fim_paths_json = ?, exclusions_json = ?,
                collection_intervals_json = ?, intel_external_enabled = ?,
                allow_file_upload = ?, updated_by = ?, updated_at = ?
            WHERE policy_id = ?
            """,
            (
                new_version,
                json.dumps(fim_paths),
                json.dumps(exclusions),
                json.dumps(intervals),
                intel_ext,
                allow_up,
                actor["user_id"],
                now,
                DEFAULT_POLICY_ID,
            ),
        )
        if payload.retention_days:
            for domain, days in payload.retention_days.items():
                if domain in {"telemetry", "alerts", "incidents", "audit"} and days >= 1:
                    conn.execute(
                        """
                        UPDATE retention_policies
                        SET retention_days = ?, updated_at = ?
                        WHERE domain = ?
                        """,
                        (days, now, domain),
                    )
        append_audit_log(
            conn,
            actor_id=actor["user_id"],
            actor_role=actor["role"],
            action="policy.updated",
            resource_type="policy",
            resource_id=DEFAULT_POLICY_ID,
            detail={"version": new_version, "intel_external_enabled": bool(intel_ext)},
        )
    return _read_policies_payload()
