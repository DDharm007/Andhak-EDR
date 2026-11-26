"""Independent File Integrity Monitoring (FIM) baseline and drift engine."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any

from app.config import Settings
from app.db import DEFAULT_POLICY_ID, get_connection, utc_now_iso
from app.detection.scoring import AlertCandidate, persist_alert_conn

MAX_FIM_HASH_BYTES = 25 * 1024 * 1024


def _file_sha256(path: Path) -> str | None:
    if not path.is_file() or path.stat().st_size > MAX_FIM_HASH_BYTES:
        return None
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


def capture_directory_baseline(
    endpoint_id: str,
    directory: Path,
    policy_id: str = DEFAULT_POLICY_ID,
    recursive: bool = True,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Scan local critical directory and store SHA-256 baseline rows."""
    if not directory.exists() or not directory.is_dir():
        raise ValueError(f"Baseline directory does not exist: {directory}")

    now = utc_now_iso()
    iterator = directory.rglob("*") if recursive else directory.glob("*")
    files_captured = 0

    with get_connection(settings) as conn:
        for item in iterator:
            if not item.is_file():
                continue
            digest = _file_sha256(item)
            if digest is None:
                continue
            stat = item.stat()
            baseline_id = f"fim_{uuid.uuid4().hex[:16]}"
            conn.execute(
                """
                INSERT INTO fim_baselines(
                    baseline_id, endpoint_id, policy_id, file_path, sha256,
                    size_bytes, signature_status, signer_subject, modified_at, captured_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'unknown', NULL, ?, ?)
                ON CONFLICT(endpoint_id, file_path) DO UPDATE SET
                    sha256 = excluded.sha256,
                    size_bytes = excluded.size_bytes,
                    modified_at = excluded.modified_at,
                    captured_at = excluded.captured_at
                """,
                (
                    baseline_id,
                    endpoint_id,
                    policy_id,
                    str(item.resolve()),
                    digest,
                    int(stat.st_size),
                    utc_now_iso(),
                    now,
                ),
            )
            files_captured += 1

    return {
        "endpoint_id": endpoint_id,
        "directory": str(directory.resolve()),
        "files_captured": files_captured,
        "captured_at": now,
    }


def upsert_baseline_entry(
    endpoint_id: str,
    file_path: str,
    sha256: str,
    size_bytes: int,
    signature_status: str = "unknown",
    signer_subject: str | None = None,
    policy_id: str = DEFAULT_POLICY_ID,
    settings: Settings | None = None,
) -> dict[str, Any]:
    now = utc_now_iso()
    baseline_id = f"fim_{uuid.uuid4().hex[:16]}"
    with get_connection(settings) as conn:
        conn.execute(
            """
            INSERT INTO fim_baselines(
                baseline_id, endpoint_id, policy_id, file_path, sha256,
                size_bytes, signature_status, signer_subject, modified_at, captured_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(endpoint_id, file_path) DO UPDATE SET
                sha256 = excluded.sha256,
                size_bytes = excluded.size_bytes,
                signature_status = excluded.signature_status,
                signer_subject = excluded.signer_subject,
                modified_at = excluded.modified_at,
                captured_at = excluded.captured_at
            """,
            (
                baseline_id,
                endpoint_id,
                policy_id,
                file_path,
                sha256,
                size_bytes,
                signature_status,
                signer_subject,
                now,
                now,
            ),
        )
    return {"baseline_id": baseline_id, "file_path": file_path, "sha256": sha256}


def evaluate_fim_change(
    conn: Any,
    endpoint_id: str,
    file_path: str,
    change_type: str,
    observed_sha256: str | None,
    observed_signature: str = "unknown",
    source_event_id: str | None = None,
    telemetry_origin: str = "real_endpoint",
) -> dict[str, Any] | None:
    """Compare incoming filesystem observation against FIM baseline and emit alerts on drift."""
    baseline = conn.execute(
        "SELECT * FROM fim_baselines WHERE endpoint_id = ? AND file_path = ?",
        (endpoint_id, file_path),
    ).fetchone()

    # Check if path belongs to any monitored baseline root for this endpoint
    if baseline is None:
        roots = conn.execute(
            "SELECT DISTINCT file_path FROM fim_baselines WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchall()
        monitored_parents = {str(Path(r["file_path"]).parent).lower() for r in roots}
        if str(Path(file_path).parent).lower() not in monitored_parents:
            return None

    baseline_sha = baseline["sha256"] if baseline else None
    baseline_sig = baseline["signature_status"] if baseline else None

    if change_type == "modified" and baseline_sha and observed_sha256 == baseline_sha:
        if baseline_sig == observed_signature:
            return None

    if baseline_sig == "valid" and observed_signature in {"unsigned", "invalid"}:
        effective_change = "signature_changed"
        severity = "critical"
        confidence = 0.95
    elif change_type == "deleted" and baseline is not None:
        effective_change = "deleted"
        severity = "high"
        confidence = 0.90
    elif change_type == "modified" and baseline is not None:
        effective_change = "modified"
        severity = "high" if observed_signature != "valid" else "medium"
        confidence = 0.92 if observed_sha256 != baseline_sha else 0.70
    elif change_type == "renamed":
        effective_change = "renamed"
        severity = "high"
        confidence = 0.85
    else:
        effective_change = "created"
        severity = "medium" if observed_signature != "valid" else "low"
        confidence = 0.80

    now = utc_now_iso()
    fim_event_id = f"fimevt_{uuid.uuid4().hex[:16]}"
    conn.execute(
        """
        INSERT INTO fim_events(
            fim_event_id, endpoint_id, file_path, change_type,
            baseline_sha256, observed_sha256, baseline_signature,
            observed_signature, authorized, severity, detected_at, telemetry_origin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        """,
        (
            fim_event_id,
            endpoint_id,
            file_path,
            effective_change,
            baseline_sha,
            observed_sha256,
            baseline_sig,
            observed_signature,
            severity,
            now,
            telemetry_origin,
        ),
    )

    alert = persist_alert_conn(
        conn,
        AlertCandidate(
            endpoint_id=endpoint_id,
            rule_id=f"FIM-{effective_change.upper()}",
            rule_name=f"Unauthorized FIM {effective_change.replace('_', ' ')}",
            detection_source="fim",
            severity=severity,
            confidence=confidence,
            evidence_event_ids=[source_event_id] if source_event_id else [],
            evidence_summary=(
                f"Monitored file {file_path} ({effective_change}): "
                f"baseline={baseline_sha or 'none'} observed={observed_sha256 or 'deleted'} "
                f"sig={observed_signature}"
            ),
            file_sha256=observed_sha256,
            mitre_techniques=["T1565.001"] if effective_change != "deleted" else ["T1070.004"],
            recommended_actions=[
                "Compare file diff against authorized change tickets",
                "Inspect creating/modifying process tree",
                "Quarantine file and restore trusted baseline if unauthorized",
            ],
            telemetry_origin=telemetry_origin,
            dedup_scope=f"{file_path}:{effective_change}:{observed_sha256 or 'del'}",
        ),
    )
    return {
        "fim_event_id": fim_event_id,
        "change_type": effective_change,
        "alert": alert,
    }


def list_fim_status(
    endpoint_id: str | None = None, settings: Settings | None = None
) -> dict[str, Any]:
    with get_connection(settings) as conn:
        if endpoint_id:
            baselines = conn.execute(
                "SELECT * FROM fim_baselines WHERE endpoint_id = ? ORDER BY file_path",
                (endpoint_id,),
            ).fetchall()
            events = conn.execute(
                "SELECT * FROM fim_events WHERE endpoint_id = ? "
                "ORDER BY detected_at DESC LIMIT 100",
                (endpoint_id,),
            ).fetchall()
        else:
            baselines = conn.execute("SELECT * FROM fim_baselines ORDER BY file_path").fetchall()
            events = conn.execute(
                "SELECT * FROM fim_events ORDER BY detected_at DESC LIMIT 100"
            ).fetchall()
    return {
        "baseline_count": len(baselines),
        "baselines": [dict(r) for r in baselines],
        "events": [dict(r) for r in events],
    }
