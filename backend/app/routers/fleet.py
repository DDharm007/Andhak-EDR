"""Fleet overview KPIs, endpoint inventory/details, and filtered telemetry stream."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.config import get_settings
from app.db import get_connection
from app.realtime.bus import event_bus

router = APIRouter(prefix="/api/v1", tags=["fleet"])


@router.get("/overview")
def get_overview() -> dict[str, Any]:
    cfg = get_settings()
    with get_connection(cfg) as conn:
        endpoints = conn.execute(
            "SELECT * FROM endpoints ORDER BY last_heartbeat_at DESC, enrolled_at DESC"
        ).fetchall()
        alerts = conn.execute("SELECT * FROM alerts ORDER BY detected_at DESC LIMIT 200").fetchall()
        incidents = conn.execute(
            "SELECT * FROM incidents ORDER BY last_seen_at DESC LIMIT 100"
        ).fetchall()
        pending_responses = conn.execute(
            "SELECT COUNT(*) AS cnt FROM response_actions WHERE status = 'pending_approval'"
        ).fetchone()
        quarantined_cnt = conn.execute(
            "SELECT COUNT(*) AS cnt FROM quarantine_vault WHERE status = 'quarantined'"
        ).fetchone()
        total_events = conn.execute("SELECT COUNT(*) AS cnt FROM telemetry_events").fetchone()

    ep_status_counts = Counter(r["status"] for r in endpoints)
    sev_counts = Counter(r["severity"] for r in alerts)
    src_counts = Counter(r["detection_source"] for r in alerts)
    origin_counts = Counter(r["telemetry_origin"] for r in endpoints)
    tech_counts: Counter[str] = Counter()
    for a in alerts:
        for t in json.loads(a["mitre_techniques_json"] or "[]"):
            tech_counts[t] += 1

    hour_buckets: Counter[str] = Counter()
    for a in alerts:
        ts = str(a["detected_at"])[:13] + ":00Z"
        hour_buckets[ts] += 1

    timeline_series = [
        {"bucket": k, "alerts": hour_buckets[k]} for k in sorted(hour_buckets.keys())[-12:]
    ]

    formatted_endpoints = []
    for e in endpoints[:20]:
        d = dict(e)
        d["last_metrics"] = json.loads(d.pop("last_metrics_json", "{}") or "{}")
        formatted_endpoints.append(d)

    formatted_alerts = []
    for a in alerts[:12]:
        d = dict(a)
        d["mitre_techniques"] = json.loads(d.pop("mitre_techniques_json", "[]") or "[]")
        d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json", "[]") or "[]")
        d["evidence_event_ids"] = json.loads(d.pop("evidence_event_ids_json", "[]") or "[]")
        d["recommended_actions"] = json.loads(d.pop("recommended_actions_json", "[]") or "[]")
        formatted_alerts.append(d)

    formatted_incidents = []
    for inc in incidents[:10]:
        d = dict(inc)
        d["mitre_tactics"] = json.loads(d.pop("mitre_tactics_json", "[]") or "[]")
        d["mitre_techniques"] = json.loads(d.pop("mitre_techniques_json", "[]") or "[]")
        formatted_incidents.append(d)

    return {
        "mode": "demo" if cfg.demo_mode else "live",
        "kpis": {
            "endpoints_total": len(endpoints),
            "endpoints_online": ep_status_counts.get("online", 0),
            "endpoints_isolated": ep_status_counts.get("isolated", 0),
            "endpoints_degraded": ep_status_counts.get("degraded", 0),
            "telemetry_events_total": int(total_events["cnt"]) if total_events else 0,
            "alerts_open": sum(1 for a in alerts if a["status"] in {"open", "investigating"}),
            "alerts_critical": sev_counts.get("critical", 0),
            "alerts_high": sev_counts.get("high", 0),
            "incidents_open": sum(1 for i in incidents if i["status"] in {"open", "contained"}),
            "pending_approvals": int(pending_responses["cnt"]) if pending_responses else 0,
            "quarantined_files": int(quarantined_cnt["cnt"]) if quarantined_cnt else 0,
        },
        "severity_breakdown": [
            {"severity": s, "count": sev_counts.get(s, 0)}
            for s in ("critical", "high", "medium", "low", "info")
        ],
        "source_breakdown": [
            {"source": s, "count": src_counts.get(s, 0)}
            for s in ("behavioral", "yara_x", "ember", "fim", "ioc", "sysmon")
        ],
        "top_mitre_techniques": [
            {"technique_id": k, "count": v} for k, v in tech_counts.most_common(8)
        ],
        "alert_timeline": timeline_series,
        "telemetry_origins": dict(origin_counts),
        "websocket_subscribers": event_bus.subscriber_counts(),
        "endpoints": formatted_endpoints,
        "recent_alerts": formatted_alerts,
        "recent_incidents": formatted_incidents,
    }


@router.get("/endpoints/{endpoint_id}")
def get_endpoint_detail(
    endpoint_id: str,
    limit: int = Query(default=60, ge=10, le=300),
) -> dict[str, Any]:
    with get_connection(get_settings()) as conn:
        ep = conn.execute(
            "SELECT * FROM endpoints WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
        if ep is None:
            raise HTTPException(status_code=404, detail="Endpoint not found.")

        procs = conn.execute(
            """
            SELECT * FROM process_executions
            WHERE endpoint_id = ?
            ORDER BY started_at DESC LIMIT ?
            """,
            (endpoint_id, limit),
        ).fetchall()
        sockets = conn.execute(
            """
            SELECT * FROM network_sockets
            WHERE endpoint_id = ?
            ORDER BY observed_at DESC LIMIT ?
            """,
            (endpoint_id, limit),
        ).fetchall()
        telemetry = conn.execute(
            """
            SELECT * FROM telemetry_events
            WHERE endpoint_id = ?
            ORDER BY occurred_at DESC LIMIT ?
            """,
            (endpoint_id, limit),
        ).fetchall()
        alerts = conn.execute(
            """
            SELECT * FROM alerts
            WHERE endpoint_id = ?
            ORDER BY detected_at DESC LIMIT ?
            """,
            (endpoint_id, limit),
        ).fetchall()
        fim_baselines = conn.execute(
            "SELECT * FROM fim_baselines WHERE endpoint_id = ? ORDER BY captured_at DESC",
            (endpoint_id,),
        ).fetchall()
        fim_events = conn.execute(
            "SELECT * FROM fim_events WHERE endpoint_id = ? ORDER BY detected_at DESC LIMIT ?",
            (endpoint_id, limit),
        ).fetchall()
        responses = conn.execute(
            "SELECT * FROM response_actions WHERE endpoint_id = ? ORDER BY requested_at DESC",
            (endpoint_id,),
        ).fetchall()
        quarantine = conn.execute(
            "SELECT * FROM quarantine_vault WHERE endpoint_id = ? ORDER BY quarantined_at DESC",
            (endpoint_id,),
        ).fetchall()

    ep_dict = dict(ep)
    ep_dict["last_metrics"] = json.loads(ep_dict.pop("last_metrics_json", "{}") or "{}")

    return {
        "endpoint": ep_dict,
        "processes": [dict(p) for p in procs],
        "network_sockets": [dict(s) for s in sockets],
        "telemetry_events": [
            {**dict(t), "raw_payload": json.loads(t["raw_payload_json"] or "{}")} for t in telemetry
        ],
        "alerts": [
            {
                **dict(a),
                "mitre_techniques": json.loads(a["mitre_techniques_json"] or "[]"),
                "mitre_tactics": json.loads(a["mitre_tactics_json"] or "[]"),
                "evidence_event_ids": json.loads(a["evidence_event_ids_json"] or "[]"),
                "recommended_actions": json.loads(a["recommended_actions_json"] or "[]"),
            }
            for a in alerts
        ],
        "fim_baselines": [dict(b) for b in fim_baselines],
        "fim_events": [dict(f) for f in fim_events],
        "responses": [
            {
                **dict(r),
                "target_metadata": json.loads(r["target_metadata_json"] or "{}"),
                "verification": json.loads(r["verification_json"] or "{}"),
            }
            for r in responses
        ],
        "quarantine": [dict(q) for q in quarantine],
    }
