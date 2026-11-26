"""Forensic evidence collector and SHA-256 integrity-sealed bundle generator."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from app.config import Settings
from app.db import get_connection, utc_now_iso
from app.forensics.process_tree import build_incident_process_tree_and_graph
from app.forensics.timeline import build_attack_timeline, map_mitre_with_evidence


def collect_forensic_bundle(
    incident_id: str,
    collected_by: str = "analyst",
    settings: Settings | None = None,
) -> dict[str, Any]:
    now = utc_now_iso()
    with get_connection(settings) as conn:
        incident = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")

        endpoint_id = incident["endpoint_id"]
        endpoint = conn.execute(
            "SELECT * FROM endpoints WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at ASC",
            (incident_id,),
        ).fetchall()

        tree_data = build_incident_process_tree_and_graph(conn, incident_id)
        timeline = build_attack_timeline(conn, incident_id)
        mitre = map_mitre_with_evidence(conn, incident_id)

        evidence_ids: set[str] = set()
        sha256_hashes: set[str] = set()
        for a in alerts:
            for eid in json.loads(a["evidence_event_ids_json"] or "[]"):
                evidence_ids.add(str(eid))
            if a["file_sha256"]:
                sha256_hashes.add(str(a["file_sha256"]))

        events_data: list[dict[str, Any]] = []
        if evidence_ids:
            placeholders = ",".join("?" for _ in evidence_ids)
            ev_rows = conn.execute(
                f"SELECT * FROM telemetry_events WHERE event_id IN ({placeholders}) "
                "ORDER BY occurred_at ASC",
                tuple(evidence_ids),
            ).fetchall()
            events_data = [dict(r) for r in ev_rows]

        malware_rows: list[dict[str, Any]] = []
        if sha256_hashes:
            placeholders = ",".join("?" for _ in sha256_hashes)
            m_rows = conn.execute(
                f"SELECT * FROM malware_analyses WHERE sha256 IN ({placeholders})",
                tuple(sha256_hashes),
            ).fetchall()
            malware_rows = [dict(r) for r in m_rows]

        sockets = conn.execute(
            "SELECT * FROM network_sockets WHERE endpoint_id = ? "
            "ORDER BY observed_at DESC LIMIT 100",
            (endpoint_id,),
        ).fetchall()

        bundle_payload = {
            "provenance": {
                "collector": "andhak-edr-forensics-v1",
                "collected_by": collected_by,
                "collected_at": now,
                "telemetry_origin": incident["telemetry_origin"],
            },
            "incident": dict(incident),
            "endpoint": dict(endpoint) if endpoint else {},
            "alerts": [dict(a) for a in alerts],
            "process_tree": tree_data["process_tree"],
            "timeline": timeline,
            "mitre_attack": mitre,
            "telemetry_events": events_data,
            "network_sockets": [dict(s) for s in sockets],
            "malware_analyses": malware_rows,
        }
        canonical = json.dumps(bundle_payload, sort_keys=True, ensure_ascii=False)
        manifest_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        bundle_id = f"bnd_{uuid.uuid4().hex[:16]}"

        conn.execute(
            """
            INSERT INTO forensic_bundles(
                bundle_id, incident_id, endpoint_id, collected_by,
                manifest_sha256, bundle_json, collected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                bundle_id,
                incident_id,
                endpoint_id,
                collected_by,
                manifest_sha256,
                canonical,
                now,
            ),
        )

    return {
        "bundle_id": bundle_id,
        "incident_id": incident_id,
        "endpoint_id": endpoint_id,
        "collected_by": collected_by,
        "manifest_sha256": manifest_sha256,
        "collected_at": now,
        "bundle": bundle_payload,
    }


def get_forensic_bundle(bundle_id: str, settings: Settings | None = None) -> dict[str, Any] | None:
    with get_connection(settings) as conn:
        row = conn.execute(
            "SELECT * FROM forensic_bundles WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone()
    if row is None:
        return None
    bundle_obj = json.loads(row["bundle_json"])
    computed_hash = hashlib.sha256(row["bundle_json"].encode("utf-8")).hexdigest()
    return {
        "bundle_id": row["bundle_id"],
        "incident_id": row["incident_id"],
        "endpoint_id": row["endpoint_id"],
        "collected_by": row["collected_by"],
        "manifest_sha256": row["manifest_sha256"],
        "integrity_verified": computed_hash == row["manifest_sha256"],
        "collected_at": row["collected_at"],
        "bundle": bundle_obj,
    }
