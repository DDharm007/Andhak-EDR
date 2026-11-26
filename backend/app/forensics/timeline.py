"""Chronological attack timeline and evidence-backed MITRE ATT&CK mapper."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from app.detection.scoring import MITRE_CATALOG


def build_attack_timeline(conn: sqlite3.Connection, incident_id: str) -> list[dict[str, Any]]:
    incident = conn.execute(
        "SELECT * FROM incidents WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()
    if incident is None:
        raise ValueError(f"Incident not found: {incident_id}")

    alerts = conn.execute(
        "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at ASC",
        (incident_id,),
    ).fetchall()

    timeline: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()

    for a in alerts:
        ev_ids = json.loads(a["evidence_event_ids_json"] or "[]")
        for eid in ev_ids:
            seen_event_ids.add(str(eid))
        timeline.append(
            {
                "timestamp": a["detected_at"],
                "entry_type": "alert",
                "id": a["alert_id"],
                "severity": a["severity"],
                "source": a["detection_source"],
                "title": f"[{a['rule_id']}] {a['rule_name']}",
                "detail": a["evidence_summary"],
                "process_name": a["process_name"],
                "pid": a["pid"],
                "mitre_techniques": json.loads(a["mitre_techniques_json"] or "[]"),
            }
        )

    if seen_event_ids:
        placeholders = ",".join("?" for _ in seen_event_ids)
        ev_rows = conn.execute(
            f"SELECT * FROM telemetry_events WHERE event_id IN ({placeholders}) "
            "ORDER BY occurred_at ASC",
            tuple(seen_event_ids),
        ).fetchall()
        for e in ev_rows:
            timeline.append(
                {
                    "timestamp": e["occurred_at"],
                    "entry_type": "telemetry",
                    "id": e["event_id"],
                    "severity": e["severity"],
                    "source": e["category"],
                    "title": f"{e['category']}:{e['event_type']}",
                    "detail": (
                        e["command_line"]
                        or e["file_path"]
                        or (
                            f"{e['dest_ip']}:{e['dest_port']}"
                            if e["dest_ip"]
                            else e["process_name"]
                        )
                        or e["event_type"]
                    ),
                    "process_name": e["process_name"],
                    "pid": e["pid"],
                    "mitre_techniques": [],
                }
            )

    # Also include related FIM events within the incident time span
    fim_rows = conn.execute(
        """
        SELECT * FROM fim_events
        WHERE endpoint_id = ? AND detected_at BETWEEN ? AND ?
        ORDER BY detected_at ASC
        """,
        (incident["endpoint_id"], incident["first_seen_at"], incident["last_seen_at"]),
    ).fetchall()
    for f in fim_rows:
        timeline.append(
            {
                "timestamp": f["detected_at"],
                "entry_type": "fim",
                "id": f["fim_event_id"],
                "severity": f["severity"],
                "source": "fim",
                "title": f"FIM {f['change_type']}: {f['file_path']}",
                "detail": f"baseline={f['baseline_sha256']} observed={f['observed_sha256']}",
                "process_name": None,
                "pid": None,
                "mitre_techniques": ["T1565.001"],
            }
        )

    timeline.sort(key=lambda item: str(item["timestamp"]))
    return timeline


def map_mitre_with_evidence(conn: sqlite3.Connection, incident_id: str) -> list[dict[str, Any]]:
    """Map only observed detection rules with concrete supporting alerts & event IDs."""
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at ASC",
        (incident_id,),
    ).fetchall()

    by_tech: dict[str, dict[str, Any]] = {}
    for a in alerts:
        techs = json.loads(a["mitre_techniques_json"] or "[]")
        ev_ids = json.loads(a["evidence_event_ids_json"] or "[]")
        for tech in techs:
            if tech not in MITRE_CATALOG:
                continue
            tactic, name = MITRE_CATALOG[tech]
            bucket = by_tech.setdefault(
                tech,
                {
                    "technique_id": tech,
                    "tactic": tactic,
                    "technique_name": name,
                    "supporting_alert_ids": [],
                    "supporting_event_ids": [],
                    "supporting_rules": [],
                },
            )
            if a["alert_id"] not in bucket["supporting_alert_ids"]:
                bucket["supporting_alert_ids"].append(a["alert_id"])
            if a["rule_id"] not in bucket["supporting_rules"]:
                bucket["supporting_rules"].append(a["rule_id"])
            for eid in ev_ids:
                if eid not in bucket["supporting_event_ids"]:
                    bucket["supporting_event_ids"].append(eid)

    return list(by_tech.values())
