"""Deterministic, evidence-cited Incident Investigation & Triage Engine (Zero-AI per ADR-002)."""

from __future__ import annotations

import json
import uuid
from typing import Any

from app.config import Settings
from app.db import get_connection, utc_now_iso
from app.forensics.process_tree import build_incident_process_tree_and_graph
from app.forensics.timeline import build_attack_timeline, map_mitre_with_evidence


def run_deterministic_investigation(
    incident_id: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Produce structured triage report solely from verified DB evidence and deterministic rules."""
    now = utc_now_iso()
    with get_connection(settings) as conn:
        incident = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            raise ValueError(f"Incident not found: {incident_id}")

        endpoint = conn.execute(
            "SELECT * FROM endpoints WHERE endpoint_id = ?",
            (incident["endpoint_id"],),
        ).fetchone()
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at ASC",
            (incident_id,),
        ).fetchall()

        tree_data = build_incident_process_tree_and_graph(conn, incident_id)
        timeline = build_attack_timeline(conn, incident_id)
        mitre = map_mitre_with_evidence(conn, incident_id)

        cited_ids: list[str] = []
        rules_seen: list[str] = []
        sources_seen: set[str] = set()
        unsigned_or_temp_processes: list[str] = []
        valid_signed_processes: list[str] = []

        for a in alerts:
            cited_ids.append(a["alert_id"])
            if a["rule_id"] not in rules_seen:
                rules_seen.append(a["rule_id"])
            sources_seen.add(a["detection_source"])
            for eid in json.loads(a["evidence_event_ids_json"] or "[]"):
                if eid not in cited_ids:
                    cited_ids.append(eid)

        # Evaluate process signature posture deterministically for false-positive analysis
        proc_rows = conn.execute(
            "SELECT process_name, pid, executable_path, signature_status, signer_subject "
            "FROM process_executions WHERE endpoint_id = ?",
            (incident["endpoint_id"],),
        ).fetchall()
        alert_guids = {a["process_guid"] for a in alerts if a["process_guid"]}
        involved_procs = conn.execute(
            "SELECT * FROM process_executions WHERE endpoint_id = ?",
            (incident["endpoint_id"],),
        ).fetchall()
        for p in involved_procs:
            if p["process_guid"] in alert_guids:
                label = f"{p['process_name']} (PID {p['pid']})"
                if p["signature_status"] == "valid":
                    valid_signed_processes.append(f"{label} [{p['signer_subject'] or 'Signed'}]")
                else:
                    unsigned_or_temp_processes.append(
                        f"{label} [{p['signature_status']}] @ {p['executable_path']}"
                    )
        _ = proc_rows

        fp_checks: list[dict[str, str]] = []
        if len(alerts) == 1 and float(alerts[0]["confidence"]) < 0.75:
            fp_checks.append(
                {
                    "check": "single_signal_confidence",
                    "status": "review_required",
                    "detail": (
                        "Incident rests on a single moderate-confidence signal; "
                        "corroborate before destructive containment."
                    ),
                }
            )
        else:
            fp_checks.append(
                {
                    "check": "multi_signal_corroboration",
                    "status": "corroborated",
                    "detail": (
                        f"{len(alerts)} alerts across {len(sources_seen)} detection engine(s) "
                        f"support non-incidental activity."
                    ),
                }
            )

        if valid_signed_processes and not unsigned_or_temp_processes:
            fp_checks.append(
                {
                    "check": "authenticode_posture",
                    "status": "living_off_the_land_review",
                    "detail": (
                        "Involved processes carry valid signatures "
                        f"({', '.join(valid_signed_processes[:3])}); verify whether "
                        "administrative scripting or LOLBin abuse occurred."
                    ),
                }
            )
        elif unsigned_or_temp_processes:
            fp_checks.append(
                {
                    "check": "authenticode_posture",
                    "status": "elevated_suspicion",
                    "detail": (
                        "Unsigned or staging-path binary involved: "
                        f"{', '.join(unsigned_or_temp_processes[:3])}"
                    ),
                }
            )

        # Deterministic recommended runbook actions (no autonomous execution)
        runbook: list[dict[str, Any]] = []
        if any(
            r in {"BEH-007", "BEH-006", "IOC-IP", "ANDHAK_Credential_Access_Command_Markers"}
            for r in rules_seen
        ):
            runbook.append(
                {
                    "priority": 1,
                    "action_type": "isolate_endpoint",
                    "target": incident["endpoint_id"],
                    "rationale": (
                        "High-severity credential access, rapid write burst, or C2 IOC match."
                    ),
                    "requires_approval": True,
                }
            )
        for a in alerts:
            if a["pid"] and a["process_name"] and a["severity"] in {"critical", "high"}:
                runbook.append(
                    {
                        "priority": 2,
                        "action_type": "terminate_process",
                        "target": str(a["pid"]),
                        "process_name": a["process_name"],
                        "rationale": f"Triggered {a['rule_id']} ({a['rule_name']}).",
                        "requires_approval": True,
                    }
                )
            if a["file_sha256"]:
                runbook.append(
                    {
                        "priority": 3,
                        "action_type": "quarantine_file",
                        "target": a["file_sha256"],
                        "rationale": f"Associated file hash observed in {a['rule_id']}.",
                        "requires_approval": True,
                    }
                )

        # Deduplicate runbook recommendations
        dedup_runbook: list[dict[str, Any]] = []
        seen_rb: set[tuple[str, str]] = set()
        for rb in runbook:
            key = (rb["action_type"], rb["target"])
            if key not in seen_rb:
                seen_rb.add(key)
                dedup_runbook.append(rb)

        hostname = endpoint["hostname"] if endpoint else incident["endpoint_id"]
        tactic_list = json.loads(incident["mitre_tactics_json"] or "[]")
        narrative = (
            f"Deterministic Triage Summary for Incident {incident_id} on endpoint {hostname}: "
            f"{len(alerts)} correlated alert(s) spanning rules [{', '.join(rules_seen)}] "
            f"between {incident['first_seen_at']} and {incident['last_seen_at']}. "
            f"Overall severity is {incident['severity'].upper()} "
            f"(confidence {incident['confidence']:.2f}, risk score {incident['risk_score']}/100). "
            f"Observed MITRE ATT&CK tactics: {', '.join(tactic_list) or 'none mapped'}. "
            "All findings cite recorded telemetry and never execute containment automatically."
        )

        investigation_id = f"inv_{uuid.uuid4().hex[:16]}"
        conn.execute(
            """
            INSERT INTO deterministic_investigations(
                investigation_id, incident_id, engine_mode, summary_narrative,
                timeline_json, process_tree_json, mitre_evidence_json,
                false_positive_checks_json, recommended_runbook_json,
                cited_evidence_ids_json, created_at
            ) VALUES (?, ?, 'deterministic_rules_v1', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                incident_id,
                narrative,
                json.dumps(timeline),
                json.dumps(tree_data["process_tree"]),
                json.dumps(mitre),
                json.dumps(fp_checks),
                json.dumps(dedup_runbook),
                json.dumps(cited_ids),
                now,
            ),
        )

    return {
        "investigation_id": investigation_id,
        "incident_id": incident_id,
        "engine_mode": "deterministic_rules_v1",
        "summary_narrative": narrative,
        "timeline": timeline,
        "process_tree": tree_data["process_tree"],
        "mitre_evidence": mitre,
        "false_positive_checks": fp_checks,
        "recommended_runbook": dedup_runbook,
        "cited_evidence_ids": cited_ids,
        "created_at": now,
    }
