"""Event & alert correlation engine grouping detections into security incidents."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import Settings
from app.db import get_connection
from app.detection.scoring import SEVERITY_BASE_SCORE, compute_risk_score

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _root_process_guid(conn: sqlite3.Connection, process_guid: str | None) -> str | None:
    if not process_guid:
        return None
    current = process_guid
    visited: set[str] = set()
    while current and current not in visited:
        visited.add(current)
        row = conn.execute(
            "SELECT parent_process_guid FROM process_executions WHERE process_guid = ?",
            (current,),
        ).fetchone()
        if row is None or not row["parent_process_guid"]:
            return current
        parent = str(row["parent_process_guid"])
        # Verify parent exists in process_executions before ascending
        exists = conn.execute(
            "SELECT 1 FROM process_executions WHERE process_guid = ?",
            (parent,),
        ).fetchone()
        if exists is None:
            return current
        current = parent
    return current


def correlate_alerts_for_endpoint(
    conn: sqlite3.Connection,
    endpoint_id: str,
    window_minutes: int = 30,
) -> list[dict[str, Any]]:
    """Group unassigned alerts on an endpoint into time-window / process / IOC incidents."""
    unassigned = conn.execute(
        """
        SELECT * FROM alerts
        WHERE endpoint_id = ? AND incident_id IS NULL
        ORDER BY detected_at ASC
        """,
        (endpoint_id,),
    ).fetchall()
    if not unassigned:
        return []

    touched_incidents: dict[str, dict[str, Any]] = {}
    for alert in unassigned:
        alert_time = datetime.fromisoformat(str(alert["detected_at"]).replace("Z", "+00:00"))
        if alert_time.tzinfo is None:
            alert_time = alert_time.replace(tzinfo=UTC)
        window_start = (alert_time - timedelta(minutes=window_minutes)).isoformat()
        root_guid = _root_process_guid(conn, alert["process_guid"])

        # Try matching an existing open incident on the same endpoint within correlation window
        candidate = None
        if root_guid:
            candidate = conn.execute(
                """
                SELECT * FROM incidents
                WHERE endpoint_id = ? AND status IN ('open', 'contained')
                  AND root_process_guid = ? AND last_seen_at >= ?
                ORDER BY last_seen_at DESC LIMIT 1
                """,
                (endpoint_id, root_guid, window_start),
            ).fetchone()

        if candidate is None:
            candidate = conn.execute(
                """
                SELECT * FROM incidents
                WHERE endpoint_id = ? AND status IN ('open', 'contained')
                  AND last_seen_at >= ?
                ORDER BY last_seen_at DESC LIMIT 1
                """,
                (endpoint_id, window_start),
            ).fetchone()

        if candidate is None:
            incident_id = f"inc_{uuid.uuid4().hex[:16]}"
            tactics = json.loads(alert["mitre_tactics_json"] or "[]")
            techniques = json.loads(alert["mitre_techniques_json"] or "[]")
            title = f"Security Incident on {endpoint_id}: {alert['rule_name']}"
            conn.execute(
                """
                INSERT INTO incidents(
                    incident_id, title, endpoint_id, severity, confidence, risk_score,
                    status, root_process_guid, mitre_tactics_json, mitre_techniques_json,
                    alert_count, first_seen_at, last_seen_at, telemetry_origin
                ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    incident_id,
                    title,
                    endpoint_id,
                    alert["severity"],
                    alert["confidence"],
                    alert["risk_score"],
                    root_guid,
                    json.dumps(tactics),
                    json.dumps(techniques),
                    alert["detected_at"],
                    alert["detected_at"],
                    alert["telemetry_origin"],
                ),
            )
            conn.execute(
                "UPDATE alerts SET incident_id = ? WHERE alert_id = ?",
                (incident_id, alert["alert_id"]),
            )
            touched_incidents[incident_id] = dict(
                conn.execute(
                    "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
                ).fetchone()
            )
        else:
            incident_id = candidate["incident_id"]
            conn.execute(
                "UPDATE alerts SET incident_id = ? WHERE alert_id = ?",
                (incident_id, alert["alert_id"]),
            )
            _recompute_incident_aggregates(conn, incident_id, root_guid)
            touched_incidents[incident_id] = dict(
                conn.execute(
                    "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
                ).fetchone()
            )

    return [_format_incident(inc) for inc in touched_incidents.values()]


def _recompute_incident_aggregates(
    conn: sqlite3.Connection,
    incident_id: str,
    fallback_root_guid: str | None = None,
) -> None:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at ASC",
        (incident_id,),
    ).fetchall()
    if not rows:
        return
    max_sev = max((r["severity"] for r in rows), key=lambda s: SEVERITY_RANK.get(s, 0))
    max_conf = max(float(r["confidence"]) for r in rows)
    tactics: list[str] = []
    techniques: list[str] = []
    sources: set[str] = set()
    for r in rows:
        sources.add(str(r["detection_source"]))
        for t in json.loads(r["mitre_tactics_json"] or "[]"):
            if t not in tactics:
                tactics.append(t)
        for tech in json.loads(r["mitre_techniques_json"] or "[]"):
            if tech not in techniques:
                techniques.append(tech)

    corroboration = max(0, len(rows) - 1) + max(0, len(sources) - 1)
    risk_score = compute_risk_score(max_sev, max_conf, corroborating_signals=corroboration)
    # Escalate multi-stage chain title once >1 distinct rules correlate
    unique_rules = list(dict.fromkeys(r["rule_id"] for r in rows))
    ep_id = rows[0]["endpoint_id"]
    if len(unique_rules) >= 3:
        title = (
            f"Multi-Stage Threat Activity on {ep_id} "
            f"({len(unique_rules)} rules / {', '.join(unique_rules[:4])})"
        )
    else:
        title = f"Correlated Activity on {ep_id}: {rows[0]['rule_name']}"

    root_guid = fallback_root_guid
    if not root_guid:
        for r in rows:
            if r["process_guid"]:
                root_guid = _root_process_guid(conn, r["process_guid"])
                if root_guid:
                    break

    conn.execute(
        """
        UPDATE incidents
        SET title = ?, severity = ?, confidence = ?, risk_score = ?,
            root_process_guid = COALESCE(root_process_guid, ?),
            mitre_tactics_json = ?, mitre_techniques_json = ?,
            alert_count = ?, first_seen_at = ?, last_seen_at = ?
        WHERE incident_id = ?
        """,
        (
            title,
            max_sev,
            round(max_conf, 4),
            risk_score,
            root_guid,
            json.dumps(tactics),
            json.dumps(techniques),
            len(rows),
            rows[0]["detected_at"],
            rows[-1]["detected_at"],
            incident_id,
        ),
    )


def _format_incident(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json", "[]"))
    d["mitre_techniques"] = json.loads(d.pop("mitre_techniques_json", "[]"))
    return d


def list_incidents(
    endpoint_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if endpoint_id:
        clauses.append("endpoint_id = ?")
        params.append(endpoint_id)
    if status:
        clauses.append("status = ?")
        params.append(status)
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(limit, 500)))
    with get_connection(settings) as conn:
        rows = conn.execute(
            f"SELECT * FROM incidents {where_sql} ORDER BY last_seen_at DESC LIMIT ?",
            params,
        ).fetchall()
    return [_format_incident(r) for r in rows]


def _ensure_severity_rank_used() -> int:
    return SEVERITY_BASE_SCORE["info"]
