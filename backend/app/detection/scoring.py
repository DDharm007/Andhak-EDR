"""Transparent detection risk scoring, deduplication, and alert persistence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.config import Settings
from app.db import get_connection, utc_now_iso

SEVERITY_BASE_SCORE = {
    "critical": 90,
    "high": 72,
    "medium": 50,
    "low": 25,
    "info": 10,
}

MITRE_CATALOG: dict[str, tuple[str, str]] = {
    "T1059.001": ("Execution", "Command and Scripting Interpreter: PowerShell"),
    "T1059.003": ("Execution", "Command and Scripting Interpreter: Windows Command Shell"),
    "T1055": ("Defense Evasion / Privilege Escalation", "Process Injection"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1204.002": ("Execution", "User Execution: Malicious File"),
    "T1547.001": ("Persistence", "Boot or Logon Autostart Execution: Registry Run Keys / Startup"),
    "T1053.005": ("Persistence / Execution", "Scheduled Task/Job: Scheduled Task"),
    "T1543.003": ("Persistence", "Create or Modify System Process: Windows Service"),
    "T1071.001": ("Command and Control", "Application Layer Protocol: Web Protocols"),
    "T1003.001": ("Credential Access", "OS Credential Dumping: LSASS Memory"),
    "T1486": ("Impact", "Data Encrypted for Impact"),
    "T1565.001": ("Impact", "Data Manipulation: Stored Data Manipulation"),
    "T1070.004": ("Defense Evasion", "Indicator Removal: File Deletion"),
}


def compute_risk_score(
    severity: str,
    confidence: float,
    corroborating_signals: int = 0,
) -> int:
    """Compute transparent 0..100 risk score while keeping severity & confidence distinct."""
    clamped_conf = max(0.0, min(1.0, confidence))
    base = SEVERITY_BASE_SCORE.get(severity, 10)
    weighted = base * (0.45 + 0.55 * clamped_conf) + min(15, corroborating_signals * 5)
    return max(0, min(100, round(weighted)))


@dataclass
class AlertCandidate:
    endpoint_id: str
    rule_id: str
    rule_name: str
    detection_source: str
    severity: str
    confidence: float
    evidence_summary: str
    evidence_event_ids: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    process_guid: str | None = None
    pid: int | None = None
    process_name: str | None = None
    file_sha256: str | None = None
    corroborating_signals: int = 0
    telemetry_origin: str = "real_endpoint"
    dedup_scope: str = ""
    detected_at: str | None = None

    def to_record(self) -> dict[str, Any]:
        detected = self.detected_at or utc_now_iso()
        tactics: list[str] = []
        for tech in self.mitre_techniques:
            if tech in MITRE_CATALOG:
                tactic = MITRE_CATALOG[tech][0]
                if tactic not in tactics:
                    tactics.append(tactic)
        confidence = round(max(0.0, min(1.0, self.confidence)), 4)
        risk_score = compute_risk_score(self.severity, confidence, self.corroborating_signals)
        dedup_seed = "|".join(
            [
                self.endpoint_id,
                self.rule_id,
                self.dedup_scope or self.process_guid or self.file_sha256 or self.evidence_summary,
                detected[:13],  # hourly suppression bucket
            ]
        )
        dedup_key = hashlib.sha256(dedup_seed.encode("utf-8")).hexdigest()[:32]
        return {
            "alert_id": f"alt_{uuid.uuid4().hex[:16]}",
            "endpoint_id": self.endpoint_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "detection_source": self.detection_source,
            "severity": self.severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "process_guid": self.process_guid,
            "pid": self.pid,
            "process_name": self.process_name,
            "file_sha256": self.file_sha256,
            "evidence_event_ids_json": json.dumps(self.evidence_event_ids),
            "evidence_summary": self.evidence_summary,
            "mitre_tactics_json": json.dumps(tactics),
            "mitre_techniques_json": json.dumps(self.mitre_techniques),
            "recommended_actions_json": json.dumps(self.recommended_actions),
            "status": "open",
            "dedup_key": dedup_key,
            "detected_at": detected,
            "telemetry_origin": self.telemetry_origin,
        }


def persist_alert_conn(
    conn: sqlite3.Connection, candidate: AlertCandidate
) -> dict[str, Any] | None:
    rec = candidate.to_record()
    existing = conn.execute(
        "SELECT alert_id FROM alerts WHERE dedup_key = ?",
        (rec["dedup_key"],),
    ).fetchone()
    if existing is not None:
        return None
    conn.execute(
        """
        INSERT INTO alerts(
            alert_id, endpoint_id, rule_id, rule_name, detection_source,
            severity, confidence, risk_score, process_guid, pid, process_name,
            file_sha256, evidence_event_ids_json, evidence_summary,
            mitre_tactics_json, mitre_techniques_json, recommended_actions_json,
            status, dedup_key, detected_at, telemetry_origin
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            rec["alert_id"],
            rec["endpoint_id"],
            rec["rule_id"],
            rec["rule_name"],
            rec["detection_source"],
            rec["severity"],
            rec["confidence"],
            rec["risk_score"],
            rec["process_guid"],
            rec["pid"],
            rec["process_name"],
            rec["file_sha256"],
            rec["evidence_event_ids_json"],
            rec["evidence_summary"],
            rec["mitre_tactics_json"],
            rec["mitre_techniques_json"],
            rec["recommended_actions_json"],
            rec["status"],
            rec["dedup_key"],
            rec["detected_at"],
            rec["telemetry_origin"],
        ),
    )
    return rec


def persist_alert(
    candidate: AlertCandidate, settings: Settings | None = None
) -> dict[str, Any] | None:
    with get_connection(settings) as conn:
        return persist_alert_conn(conn, candidate)


def list_alerts(
    endpoint_id: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    status: str | None = None,
    limit: int = 100,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if endpoint_id:
        clauses.append("endpoint_id = ?")
        params.append(endpoint_id)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if source:
        clauses.append("detection_source = ?")
        params.append(source)
    if status:
        clauses.append("status = ?")
        params.append(status)
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(limit, 500)))
    with get_connection(settings) as conn:
        rows = conn.execute(
            f"SELECT * FROM alerts {where_sql} ORDER BY detected_at DESC LIMIT ?",
            params,
        ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["evidence_event_ids"] = json.loads(item.pop("evidence_event_ids_json", "[]"))
        item["mitre_tactics"] = json.loads(item.pop("mitre_tactics_json", "[]"))
        item["mitre_techniques"] = json.loads(item.pop("mitre_techniques_json", "[]"))
        item["recommended_actions"] = json.loads(item.pop("recommended_actions_json", "[]"))
        out.append(item)
    return out
