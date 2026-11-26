"""Stage 04 API routes: incident correlation, attack graph, forensics, triage, and hunting."""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict

from app.auth import guard_demo_readonly
from app.config import get_settings
from app.db import get_connection
from app.forensics.bundler import collect_forensic_bundle, get_forensic_bundle
from app.forensics.correlator import _format_incident, list_incidents
from app.forensics.investigator import run_deterministic_investigation
from app.forensics.process_tree import build_incident_process_tree_and_graph
from app.forensics.timeline import build_attack_timeline, map_mitre_with_evidence

router = APIRouter(prefix="/api/v1", tags=["forensics-correlation"])


class IncidentStatusPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "contained", "resolved", "closed"]


class ForensicsCollectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    collected_by: str = "analyst"


def _format_alert_row(row: Any) -> dict[str, Any]:
    d = dict(row)
    d["evidence_event_ids"] = json.loads(d.pop("evidence_event_ids_json", "[]"))
    d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json", "[]"))
    d["mitre_techniques"] = json.loads(d.pop("mitre_techniques_json", "[]"))
    d["recommended_actions"] = json.loads(d.pop("recommended_actions_json", "[]"))
    return d


@router.get("/incidents")
def get_incidents(
    endpoint_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    items = list_incidents(
        endpoint_id=endpoint_id,
        status=status,
        limit=limit,
        settings=get_settings(),
    )
    return {"items": items, "total": len(items)}


@router.get("/incidents/{incident_id}")
def get_incident_detail(incident_id: str) -> dict[str, Any]:
    settings = get_settings()
    with get_connection(settings) as conn:
        inc_row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if inc_row is None:
            raise HTTPException(status_code=404, detail="Incident not found.")

        endpoint = conn.execute(
            "SELECT endpoint_id, hostname, os_version, status, isolation_state, "
            "telemetry_origin, last_heartbeat_at FROM endpoints WHERE endpoint_id = ?",
            (inc_row["endpoint_id"],),
        ).fetchone()
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at ASC",
            (incident_id,),
        ).fetchall()
        tree_graph = build_incident_process_tree_and_graph(conn, incident_id)
        timeline = build_attack_timeline(conn, incident_id)
        mitre_evidence = map_mitre_with_evidence(conn, incident_id)

        inv_row = conn.execute(
            """
            SELECT investigation_id, incident_id, engine_mode, summary_narrative,
                   false_positive_checks_json, recommended_runbook_json,
                   cited_evidence_ids_json, created_at
            FROM deterministic_investigations
            WHERE incident_id = ?
            ORDER BY created_at DESC LIMIT 1
            """,
            (incident_id,),
        ).fetchone()

        bundle_rows = conn.execute(
            """
            SELECT bundle_id, incident_id, endpoint_id, collected_by, manifest_sha256, collected_at
            FROM forensic_bundles
            WHERE incident_id = ?
            ORDER BY collected_at DESC
            """,
            (incident_id,),
        ).fetchall()

    latest_inv = None
    if inv_row is not None:
        latest_inv = {
            "investigation_id": inv_row["investigation_id"],
            "incident_id": inv_row["incident_id"],
            "engine_mode": inv_row["engine_mode"],
            "summary_narrative": inv_row["summary_narrative"],
            "false_positive_checks": json.loads(inv_row["false_positive_checks_json"] or "[]"),
            "recommended_runbook": json.loads(inv_row["recommended_runbook_json"] or "[]"),
            "cited_evidence_ids": json.loads(inv_row["cited_evidence_ids_json"] or "[]"),
            "created_at": inv_row["created_at"],
        }

    detail = _format_incident(inc_row)
    detail["endpoint"] = dict(endpoint) if endpoint else None
    detail["alerts"] = [_format_alert_row(a) for a in alerts]
    detail["process_tree"] = tree_graph["process_tree"]
    detail["process_count"] = tree_graph["process_count"]
    detail["graph"] = tree_graph["graph"]
    detail["timeline"] = timeline
    detail["mitre_evidence"] = mitre_evidence
    detail["latest_investigation"] = latest_inv
    detail["forensic_bundles"] = [dict(b) for b in bundle_rows]
    return detail


@router.patch("/incidents/{incident_id}", dependencies=[Depends(guard_demo_readonly)])
def patch_incident_status(incident_id: str, payload: IncidentStatusPatch) -> dict[str, Any]:
    with get_connection(get_settings()) as conn:
        cur = conn.execute(
            "UPDATE incidents SET status = ? WHERE incident_id = ?",
            (payload.status, incident_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Incident not found.")
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
    return _format_incident(row)


@router.get("/incidents/{incident_id}/graph")
def get_incident_graph(incident_id: str) -> dict[str, Any]:
    with get_connection(get_settings()) as conn:
        try:
            return build_incident_process_tree_and_graph(conn, incident_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/incidents/{incident_id}/investigate", dependencies=[Depends(guard_demo_readonly)])
def investigate_incident(incident_id: str) -> dict[str, Any]:
    try:
        return run_deterministic_investigation(incident_id, settings=get_settings())
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post(
    "/incidents/{incident_id}/forensics",
    status_code=201,
    dependencies=[Depends(guard_demo_readonly)],
)
def create_forensic_bundle(
    incident_id: str,
    payload: ForensicsCollectRequest | None = None,
) -> dict[str, Any]:
    actor = payload.collected_by if payload else "analyst"
    try:
        return collect_forensic_bundle(
            incident_id,
            collected_by=actor,
            settings=get_settings(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/forensics/{bundle_id}")
def fetch_forensic_bundle(bundle_id: str) -> dict[str, Any]:
    bundle = get_forensic_bundle(bundle_id, settings=get_settings())
    if bundle is None:
        raise HTTPException(status_code=404, detail="Forensic bundle not found.")
    return bundle


@router.get("/hunting/search")
def search_telemetry_hunting(
    endpoint_id: str | None = None,
    category: str | None = None,
    process: str | None = None,
    sha256: str | None = None,
    ip: str | None = None,
    severity: str | None = None,
    origin: str | None = None,
    q: str | None = None,
    from_ts: str | None = Query(default=None, alias="from"),
    to_ts: str | None = Query(default=None, alias="to"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []

    if endpoint_id:
        clauses.append("endpoint_id = ?")
        params.append(endpoint_id)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if process:
        clauses.append("LOWER(COALESCE(process_name, '')) LIKE ?")
        params.append(f"%{process.lower()}%")
    if sha256:
        clauses.append("LOWER(COALESCE(sha256, '')) = ?")
        params.append(sha256.lower())
    if ip:
        clauses.append("(dest_ip = ? OR source_ip = ?)")
        params.extend([ip, ip])
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if origin:
        clauses.append("telemetry_origin = ?")
        params.append(origin)
    if from_ts:
        clauses.append("occurred_at >= ?")
        params.append(from_ts)
    if to_ts:
        clauses.append("occurred_at <= ?")
        params.append(to_ts)
    if q:
        like_q = f"%{q.lower()}%"
        clauses.append(
            "("
            "LOWER(COALESCE(process_name, '')) LIKE ? OR "
            "LOWER(COALESCE(command_line, '')) LIKE ? OR "
            "LOWER(COALESCE(file_path, '')) LIKE ? OR "
            "LOWER(COALESCE(executable_path, '')) LIKE ? OR "
            "LOWER(COALESCE(dest_ip, '')) LIKE ? OR "
            "LOWER(COALESCE(sha256, '')) LIKE ?"
            ")"
        )
        params.extend([like_q, like_q, like_q, like_q, like_q, like_q])

    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_connection(get_settings()) as conn:
        total_row = conn.execute(
            f"SELECT COUNT(*) AS cnt FROM telemetry_events {where_sql}",
            params,
        ).fetchone()
        rows = conn.execute(
            f"SELECT * FROM telemetry_events {where_sql} "
            "ORDER BY occurred_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

    items: list[dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        item["raw_payload"] = json.loads(item.pop("raw_payload_json", "{}"))
        items.append(item)

    return {
        "items": items,
        "total": int(total_row["cnt"]) if total_row else len(items),
        "limit": limit,
        "offset": offset,
    }
