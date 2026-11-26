"""Agent enrollment, authentication, heartbeat, and telemetry persistence."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.config import Settings, get_settings
from app.db import DEFAULT_POLICY_ID, get_connection, hash_secret, utc_now_iso
from app.detection.pipeline import evaluate_ingested_event
from app.forensics.correlator import correlate_alerts_for_endpoint
from app.schemas import (
    EnrollmentRequest,
    HeartbeatRequest,
    TelemetryBatchRequest,
    TelemetryEventIn,
)

_SECRET_PATTERNS = (
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*[^\s,;]+"
        ),
        r"\1=***",
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer ***"),
)


class AuthError(RuntimeError):
    pass


class ConflictError(RuntimeError):
    pass


def redact_secrets(text: str) -> str:
    result = text
    for pattern, repl in _SECRET_PATTERNS:
        result = pattern.sub(repl, result)
    return result


def issue_enrollment_token(
    description: str = "Workstation enrollment",
    ttl_hours: int = 24,
    created_by: str = "usr_system_admin",
    settings: Settings | None = None,
) -> dict[str, str]:
    raw_token = f"andhak_bs_{secrets.token_urlsafe(32)}"
    token_id = f"tok_{uuid.uuid4().hex[:16]}"
    expires_at = (datetime.now(UTC) + timedelta(hours=ttl_hours)).isoformat()
    with get_connection(settings) as conn:
        conn.execute(
            """
            INSERT INTO enrollment_tokens(token_id, token_hash, description, created_by, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (token_id, hash_secret(raw_token), description, created_by, expires_at),
        )
    return {
        "token_id": token_id,
        "bootstrap_token": raw_token,
        "expires_at": expires_at,
    }


def _policy_payload(conn: sqlite3.Connection, policy_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM policies WHERE policy_id = ?", (policy_id,)).fetchone()
    if row is None:
        return {
            "policy_id": DEFAULT_POLICY_ID,
            "version": 1,
            "heartbeat_seconds": 15,
            "batch_max_events": 100,
            "flush_interval_ms": 2000,
            "fim_paths": [],
            "exclusions": [],
        }
    intervals = json.loads(row["collection_intervals_json"])
    return {
        "policy_id": row["policy_id"],
        "version": row["version"],
        "heartbeat_seconds": int(intervals.get("heartbeat_seconds", 15)),
        "process_poll_ms": int(intervals.get("process_poll_ms", 2000)),
        "network_poll_ms": int(intervals.get("network_poll_ms", 5000)),
        "system_poll_ms": int(intervals.get("system_poll_ms", 5000)),
        "batch_max_events": int(intervals.get("batch_max_events", 100)),
        "flush_interval_ms": int(intervals.get("flush_interval_ms", 2000)),
        "fim_paths": json.loads(row["fim_paths_json"]),
        "exclusions": json.loads(row["exclusions_json"]),
    }


def enroll_agent(payload: EnrollmentRequest, settings: Settings | None = None) -> dict[str, Any]:
    now = utc_now_iso()
    token_digest = hash_secret(payload.bootstrap_token)
    with get_connection(settings) as conn:
        row = conn.execute(
            "SELECT * FROM enrollment_tokens WHERE token_hash = ?",
            (token_digest,),
        ).fetchone()
        if row is None:
            raise AuthError("Invalid bootstrap enrollment token.")
        if row["used_at"] is not None:
            raise AuthError("Bootstrap enrollment token has already been consumed.")
        if row["expires_at"] < now:
            raise AuthError("Bootstrap enrollment token has expired.")

        endpoint_id = f"ep_{uuid.uuid4().hex[:16]}"
        credential_id = f"cred_{uuid.uuid4().hex[:16]}"
        agent_token = f"andhak_ag_{secrets.token_urlsafe(36)}"

        conn.execute(
            """
            INSERT INTO endpoints(
                endpoint_id, hostname, fqdn, os_family, os_version, architecture,
                agent_version, primary_ip, mac_address, status, isolation_state,
                posture_score, policy_id, policy_version, sysmon_available,
                elevated_sensor, telemetry_origin, enrolled_at, last_heartbeat_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', 'none', 100,
                ?, 1, ?, ?, 'real_endpoint', ?, ?
            )
            """,
            (
                endpoint_id,
                payload.hostname,
                payload.fqdn,
                payload.os_family,
                payload.os_version,
                payload.architecture,
                payload.agent_version,
                payload.primary_ip,
                payload.mac_address,
                DEFAULT_POLICY_ID,
                int(payload.sysmon_available),
                int(payload.elevated_sensor),
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO agent_credentials(
                credential_id, endpoint_id, token_hash, key_version, revoked, issued_at
            ) VALUES (?, ?, ?, 1, 0, ?)
            """,
            (credential_id, endpoint_id, hash_secret(agent_token), now),
        )
        updated = conn.execute(
            """
            UPDATE enrollment_tokens
            SET used_at = ?, used_by_endpoint_id = ?
            WHERE token_id = ? AND used_at IS NULL
            """,
            (now, endpoint_id, row["token_id"]),
        )
        if updated.rowcount != 1:
            raise ConflictError("Enrollment token race detected.")

        policy = _policy_payload(conn, DEFAULT_POLICY_ID)

    return {
        "endpoint_id": endpoint_id,
        "agent_token": agent_token,
        "credential_id": credential_id,
        "policy": policy,
    }


def verify_agent_credential(
    endpoint_id: str,
    bearer_token: str,
    settings: Settings | None = None,
) -> sqlite3.Row:
    presented_hash = hash_secret(bearer_token)
    with get_connection(settings) as conn:
        rows = conn.execute(
            """
            SELECT ac.credential_id, ac.token_hash, ep.endpoint_id, ep.policy_id, ep.policy_version
            FROM agent_credentials ac
            JOIN endpoints ep ON ep.endpoint_id = ac.endpoint_id
            WHERE ac.endpoint_id = ? AND ac.revoked = 0
            """,
            (endpoint_id,),
        ).fetchall()
    for row in rows:
        if hmac.compare_digest(row["token_hash"], presented_hash):
            return row
    raise AuthError("Invalid or revoked agent credential.")


def record_heartbeat(
    endpoint_id: str,
    payload: HeartbeatRequest,
    settings: Settings | None = None,
) -> dict[str, Any]:
    if payload.endpoint_id != endpoint_id:
        raise AuthError("Endpoint ID mismatch between header and payload.")
    now = utc_now_iso()
    metrics = payload.model_dump(mode="json")
    sensor_values = set(metrics["sensors"].values())
    status = "online" if "ready" in sensor_values else "degraded"
    sysmon_ready = int(payload.sensors.sysmon == "ready")

    with get_connection(settings) as conn:
        row = conn.execute(
            "SELECT policy_id, policy_version FROM endpoints WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
        if row is None:
            raise AuthError("Unknown endpoint.")

        conn.execute(
            """
            UPDATE endpoints
            SET agent_version = ?,
                status = CASE WHEN isolation_state = 'isolated' THEN 'isolated' ELSE ? END,
                sysmon_available = ?,
                last_heartbeat_at = ?,
                last_metrics_json = ?
            WHERE endpoint_id = ?
            """,
            (
                payload.agent_version,
                status,
                sysmon_ready,
                now,
                json.dumps(metrics),
                endpoint_id,
            ),
        )
        pending = conn.execute(
            """
            SELECT action_id, action_type, target_value,
                   target_metadata_json, approved_by, decided_at
            FROM response_actions
            WHERE endpoint_id = ? AND status = 'approved'
            ORDER BY requested_at ASC
            """,
            (endpoint_id,),
        ).fetchall()
        commands = []
        for cmd in pending:
            commands.append(
                {
                    "action_id": cmd["action_id"],
                    "action_type": cmd["action_type"],
                    "target_value": cmd["target_value"],
                    "target_metadata": json.loads(cmd["target_metadata_json"]),
                    "issued_at": cmd["decided_at"] or now,
                }
            )
        policy = _policy_payload(conn, row["policy_id"] or DEFAULT_POLICY_ID)

    return {
        "server_time": now,
        "policy_update_available": policy["version"] > payload.policy_version,
        "pending_commands": commands,
    }


def get_agent_policy(endpoint_id: str, settings: Settings | None = None) -> dict[str, Any]:
    with get_connection(settings) as conn:
        row = conn.execute(
            "SELECT policy_id FROM endpoints WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
        policy_id = row["policy_id"] if row and row["policy_id"] else DEFAULT_POLICY_ID
        return _policy_payload(conn, policy_id)


def ingest_telemetry_batch(
    endpoint_id: str,
    batch: TelemetryBatchRequest,
    settings: Settings | None = None,
) -> dict[str, Any]:
    if batch.endpoint_id != endpoint_id:
        raise AuthError("Endpoint ID mismatch between header and telemetry batch.")
    cfg = settings or get_settings()
    if len(batch.events) > cfg.max_batch_events:
        raise ValueError(f"Batch exceeds maximum allowed {cfg.max_batch_events} events.")

    ingested_at = utc_now_iso()
    accepted = 0
    duplicate_skipped = 0
    alerts_emitted = 0

    with get_connection(cfg) as conn:
        for evt in batch.events:
            inserted = _insert_telemetry_event(conn, endpoint_id, evt, ingested_at)
            if inserted:
                accepted += 1
                alerts_emitted += len(evaluate_ingested_event(conn, endpoint_id, evt))
            else:
                duplicate_skipped += 1
        if alerts_emitted > 0:
            correlate_alerts_for_endpoint(conn, endpoint_id)
        conn.execute(
            "UPDATE endpoints SET last_heartbeat_at = ? WHERE endpoint_id = ?",
            (ingested_at, endpoint_id),
        )

    return {
        "batch_id": batch.batch_id,
        "accepted": accepted,
        "duplicate_skipped": duplicate_skipped,
        "alerts_emitted": alerts_emitted,
        "ingested_at": ingested_at,
    }


def _insert_telemetry_event(
    conn: sqlite3.Connection,
    endpoint_id: str,
    evt: TelemetryEventIn,
    ingested_at: str,
) -> bool:
    proc = evt.process
    net = evt.network
    fs = evt.filesystem

    cmd_line = redact_secrets(proc.command_line) if proc else None
    raw_dump = json.dumps(evt.model_dump(mode="json", exclude_none=True), ensure_ascii=False)
    raw_dump = redact_secrets(raw_dump)

    sha256_val = (proc.sha256 if proc else None) or (fs.sha256 if fs else None)
    sig_status = (proc.signature_status if proc else None) or (fs.signature_status if fs else None)
    process_guid = (proc.process_guid if proc else None) or (net.process_guid if net else None)
    pid = (proc.pid if proc else None) or (net.pid if net else None)
    process_name = (proc.name if proc else None) or (net.process_name if net else None)

    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO telemetry_events(
            event_id, endpoint_id, telemetry_origin, category, event_type, severity,
            occurred_at, ingested_at, process_guid, pid, ppid, process_name,
            executable_path, sha256, command_line, user_context, signature_status,
            source_ip, source_port, dest_ip, dest_port, protocol, file_path,
            dedup_hash, raw_payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evt.event_id,
            endpoint_id,
            evt.telemetry_origin,
            evt.category,
            evt.event_type,
            evt.severity,
            evt.occurred_at,
            ingested_at,
            process_guid,
            pid,
            proc.ppid if proc else None,
            process_name,
            proc.executable_path if proc else None,
            sha256_val,
            cmd_line,
            proc.user_context if proc else None,
            sig_status,
            net.local_addr if net else None,
            net.local_port if net else None,
            net.remote_addr if net else None,
            net.remote_port if net else None,
            net.protocol if net else None,
            fs.file_path if fs else None,
            evt.dedup_hash,
            raw_dump,
        ),
    )
    if cursor.rowcount == 0:
        return False

    if proc is not None:
        if evt.event_type == "process_exit":
            conn.execute(
                "UPDATE process_executions SET ended_at = ? WHERE process_guid = ?",
                (evt.occurred_at, proc.process_guid),
            )
        else:
            conn.execute(
                """
                INSERT OR IGNORE INTO process_executions(
                    process_guid, endpoint_id, parent_process_guid, pid, ppid,
                    process_name, executable_path, command_line, user_context,
                    sha256, signature_status, signer_subject, started_at, telemetry_origin
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proc.process_guid,
                    endpoint_id,
                    proc.parent_process_guid,
                    proc.pid,
                    proc.ppid,
                    proc.name,
                    proc.executable_path,
                    cmd_line or "",
                    proc.user_context,
                    proc.sha256,
                    proc.signature_status,
                    proc.signer_subject,
                    proc.started_at,
                    evt.telemetry_origin,
                ),
            )

    if net is not None:
        socket_id = hashlib.sha256(
            f"{endpoint_id}:{net.protocol}:{net.local_addr}:{net.local_port}:{net.remote_addr}:{net.remote_port}:{net.pid}".encode()
        ).hexdigest()[:24]
        conn.execute(
            """
            INSERT OR REPLACE INTO network_sockets(
                socket_id, endpoint_id, process_guid, pid, process_name, protocol,
                local_addr, local_port, remote_addr, remote_port, state,
                observed_at, telemetry_origin
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                socket_id,
                endpoint_id,
                net.process_guid,
                net.pid,
                net.process_name,
                net.protocol,
                net.local_addr,
                net.local_port,
                net.remote_addr,
                net.remote_port,
                net.state,
                evt.occurred_at,
                evt.telemetry_origin,
            ),
        )

    return True


def list_endpoints(settings: Settings | None = None) -> list[dict[str, Any]]:
    with get_connection(settings) as conn:
        rows = conn.execute(
            "SELECT * FROM endpoints ORDER BY last_heartbeat_at DESC, enrolled_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def list_telemetry_events(
    endpoint_id: str | None = None,
    category: str | None = None,
    limit: int = 100,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if endpoint_id:
        clauses.append("endpoint_id = ?")
        params.append(endpoint_id)
    if category:
        clauses.append("category = ?")
        params.append(category)
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(limit, 500)))
    with get_connection(settings) as conn:
        rows = conn.execute(
            f"SELECT * FROM telemetry_events {where_sql} ORDER BY occurred_at DESC LIMIT ?",
            params,
        ).fetchall()
    return [dict(row) for row in rows]
