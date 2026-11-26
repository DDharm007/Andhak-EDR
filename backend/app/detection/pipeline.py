"""Unified Stage 03 detection orchestration across YARA-X, EMBER, FIM, Behavioral, and IOC."""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from app.config import Settings
from app.db import get_connection, utc_now_iso
from app.detection.behavioral_engine import BEHAVIORAL_RULES, evaluate_behavioral_event
from app.detection.ember_classifier import (
    DATASET_PROVENANCE,
    MODEL_VERSION,
    classify_pe_bytes,
)
from app.detection.fim_engine import evaluate_fim_change
from app.detection.intel_service import enrich_indicator_reputation, match_telemetry_iocs
from app.detection.scoring import AlertCandidate, persist_alert_conn
from app.detection.yara_scanner import RULES_DIR, scan_bytes_yara
from app.forensics.correlator import correlate_alerts_for_endpoint
from app.schemas import TelemetryEventIn

_FS_EVENT_TO_CHANGE = {
    "file_created": "created",
    "file_modified": "modified",
    "file_deleted": "deleted",
    "file_renamed": "renamed",
}


def sync_detection_rules(conn: sqlite3.Connection) -> None:
    now = utc_now_iso()
    records: list[tuple[str, str, str, str, str, str, str, str, str]] = []
    for rule in BEHAVIORAL_RULES:
        records.append(
            (
                rule["rule_id"],
                rule["name"],
                "behavioral",
                rule["severity"],
                rule["description"],
                json.dumps(rule["mitre"]),
                "MIT",
                "ANDHAK EDR Behavioral Engine",
                now,
            )
        )
    records.append(
        (
            "EMBER-PE-STATIC",
            "EMBER Structural PE Malware Classifier",
            "ember",
            "high",
            "Probabilistic static Windows PE scoring model (advisory signal).",
            json.dumps(["T1204.002"]),
            "MIT",
            DATASET_PROVENANCE,
            now,
        )
    )
    records.append(
        (
            "FIM-DRIFT",
            "File Integrity Baseline & Signature Drift",
            "fim",
            "high",
            "Monitors critical directories for unauthorized hash or Authenticode drift.",
            json.dumps(["T1565.001", "T1070.004"]),
            "MIT",
            "ANDHAK EDR FIM Engine",
            now,
        )
    )
    records.append(
        (
            "IOC-WATCHLIST",
            "Threat Intelligence Indicator Match",
            "ioc",
            "high",
            "Matches hashes, IPs, domains, and URLs against local/policy-gated feeds.",
            json.dumps(["T1071.001"]),
            "MIT",
            "ANDHAK EDR Intel Engine",
            now,
        )
    )
    # Seed YARA rule names from local rule file
    yar_file = RULES_DIR / "andhak_edr_rules.yar"
    if yar_file.is_file():
        for line in yar_file.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("rule ") and stripped.endswith("{"):
                rule_name = stripped[5:-1].strip()
                records.append(
                    (
                        rule_name,
                        rule_name.replace("_", " "),
                        "yara_x",
                        "high" if "EICAR" not in rule_name else "info",
                        f"YARA-X local rule loaded from {yar_file.name}",
                        json.dumps([]),
                        "MIT / BSD-3-Clause (YARA-X)",
                        "ANDHAK EDR Security Engineering",
                        now,
                    )
                )

    for rec in records:
        conn.execute(
            """
            INSERT INTO detection_rules(
                rule_id, name, source, severity, description,
                mitre_techniques_json, license, attribution, enabled, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                name = excluded.name,
                severity = excluded.severity,
                description = excluded.description,
                mitre_techniques_json = excluded.mitre_techniques_json,
                updated_at = excluded.updated_at
            """,
            rec,
        )


def evaluate_ingested_event(
    conn: sqlite3.Connection,
    endpoint_id: str,
    evt: TelemetryEventIn,
) -> list[dict[str, Any]]:
    """Run real-time IOC, FIM, and behavioral rules over newly persisted telemetry."""
    emitted: list[dict[str, Any]] = []
    candidates: list[AlertCandidate] = []
    candidates.extend(match_telemetry_iocs(conn, endpoint_id, evt))
    candidates.extend(evaluate_behavioral_event(conn, endpoint_id, evt))

    for cand in candidates:
        rec = persist_alert_conn(conn, cand)
        if rec is not None:
            emitted.append(rec)

    if evt.category == "filesystem" and evt.filesystem is not None:
        change = _FS_EVENT_TO_CHANGE.get(evt.event_type)
        if change:
            fim_res = evaluate_fim_change(
                conn=conn,
                endpoint_id=endpoint_id,
                file_path=evt.filesystem.file_path,
                change_type=change,
                observed_sha256=evt.filesystem.sha256,
                observed_signature=evt.filesystem.signature_status,
                source_event_id=evt.event_id,
                telemetry_origin=evt.telemetry_origin,
            )
            if fim_res and fim_res.get("alert"):
                emitted.append(fim_res["alert"])

    return emitted


async def analyze_file_bytes(
    file_name: str,
    content: bytes,
    endpoint_id: str | None = None,
    file_path: str | None = None,
    signature_status: str = "unknown",
    signer_subject: str | None = None,
    telemetry_origin: str = "real_endpoint",
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Run combined YARA-X, EMBER PE classification, and IOC lookup on file bytes in memory."""
    yara_res = scan_bytes_yara(file_name, content)
    ember_res = classify_pe_bytes(file_name, content, settings=settings)
    ioc_rep = await enrich_indicator_reputation(yara_res["sha256"], settings=settings)

    has_yara = bool(yara_res["matches"])
    ember_score = ember_res.get("ember_score")
    has_ioc = bool(ioc_rep.get("local_matches"))

    # Verdict and confidence strictly distinguish deterministic signatures vs probabilistic EMBER.
    if has_ioc or any(m["severity"] in {"critical", "high"} for m in yara_res["matches"]):
        verdict = "malicious"
        confidence = 0.92 if has_ioc else max(m["confidence"] for m in yara_res["matches"])
    elif has_yara or (ember_score is not None and ember_score >= 0.65):
        verdict = "suspicious"
        yara_conf = max((m["confidence"] for m in yara_res["matches"]), default=0.0)
        confidence = max(yara_conf, float(ember_score or 0.0))
    else:
        verdict = "clean"
        confidence = 0.85 if ember_score is not None and ember_score < 0.35 else 0.70

    analysis_id = f"mal_{uuid.uuid4().hex[:16]}"
    now = utc_now_iso()
    file_type = "pe" if ember_res.get("is_pe") else "non_pe"

    with get_connection(settings) as conn:
        conn.execute(
            """
            INSERT INTO malware_analyses(
                analysis_id, endpoint_id, file_name, file_path, sha256, size_bytes,
                file_type, yara_matches_json, ember_score, ember_model_version,
                ember_provenance, signature_status, signer_subject,
                ioc_reputation_json, verdict, confidence, analyzed_at, telemetry_origin
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                endpoint_id,
                yara_res["file_name"],
                file_path,
                yara_res["sha256"],
                yara_res["size_bytes"],
                file_type,
                json.dumps(yara_res["matches"]),
                ember_score,
                ember_res.get("model_version", MODEL_VERSION),
                ember_res.get("provenance", DATASET_PROVENANCE),
                signature_status,
                signer_subject,
                json.dumps(ioc_rep),
                verdict,
                round(confidence, 4),
                now,
                telemetry_origin,
            ),
        )

        created_alerts: list[dict[str, Any]] = []
        if endpoint_id and has_yara:
            for m in yara_res["matches"]:
                alert = persist_alert_conn(
                    conn,
                    AlertCandidate(
                        endpoint_id=endpoint_id,
                        rule_id=m["rule_id"],
                        rule_name=f"YARA-X match: {m['rule_id']}",
                        detection_source="yara_x",
                        severity=m["severity"],
                        confidence=m["confidence"],
                        file_sha256=yara_res["sha256"],
                        evidence_summary=f"{m['description']} (file={yara_res['file_name']})",
                        mitre_techniques=m.get("mitre_techniques", []),
                        recommended_actions=[
                            "Inspect file origin and process execution history",
                            "Quarantine file if unauthorized",
                        ],
                        telemetry_origin=telemetry_origin,
                        dedup_scope=f"{yara_res['sha256']}:{m['rule_id']}",
                    ),
                )
                if alert:
                    created_alerts.append(alert)

        if endpoint_id and ember_score is not None and ember_score >= 0.78:
            highlights = ", ".join(ember_res["pe_summary"].get("feature_highlights", []))
            alert = persist_alert_conn(
                conn,
                AlertCandidate(
                    endpoint_id=endpoint_id,
                    rule_id="EMBER-PE-STATIC",
                    rule_name="High EMBER Static PE Suspicion Score",
                    detection_source="ember",
                    severity="medium",
                    confidence=ember_score,
                    file_sha256=yara_res["sha256"],
                    evidence_summary=(
                        f"EMBER advisory score {ember_score:.2f} for {yara_res['file_name']} "
                        f"({highlights or 'structural indicators'})"
                    ),
                    mitre_techniques=["T1204.002"],
                    recommended_actions=[
                        "Verify Authenticode signature and publisher",
                        "Do not quarantine solely on probabilistic score without corroboration",
                    ],
                    telemetry_origin=telemetry_origin,
                    dedup_scope=f"ember:{yara_res['sha256']}",
                ),
            )
            if alert:
                created_alerts.append(alert)

        if endpoint_id and created_alerts:
            correlate_alerts_for_endpoint(conn, endpoint_id)

    return {
        "analysis_id": analysis_id,
        "file_name": yara_res["file_name"],
        "sha256": yara_res["sha256"],
        "size_bytes": yara_res["size_bytes"],
        "file_type": file_type,
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "yara": yara_res,
        "ember": ember_res,
        "ioc_reputation": ioc_rep,
        "signature_status": signature_status,
        "signer_subject": signer_subject,
        "alerts_created": created_alerts,
        "analyzed_at": now,
    }
