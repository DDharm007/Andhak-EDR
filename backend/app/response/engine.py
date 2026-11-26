"""Controlled response orchestrator: approvals, quarantine vault, isolation, and acks."""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from app.config import Settings
from app.db import get_connection, utc_now_iso
from app.response.audit import append_audit_log
from app.response.safety import ProtectedTargetError, validate_response_target


class ResourceNotFoundError(LookupError):
    pass


class ConflictActionError(RuntimeError):
    pass


def _format_action(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    d = dict(row)
    d["target_metadata"] = json.loads(d.pop("target_metadata_json", "{}") or "{}")
    d["verification"] = json.loads(d.pop("verification_json", "{}") or "{}")
    return d


def propose_response_action(
    endpoint_id: str,
    action_type: str,
    target_value: str,
    reason: str,
    actor: dict[str, Any],
    incident_id: str | None = None,
    target_metadata: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    now = utc_now_iso()
    meta = dict(target_metadata or {})
    with get_connection(settings) as conn:
        ep = conn.execute(
            "SELECT endpoint_id, isolation_state FROM endpoints WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
        if ep is None:
            raise ResourceNotFoundError(f"Endpoint not found: {endpoint_id}")

        if incident_id:
            inc = conn.execute(
                "SELECT incident_id FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            if inc is None:
                raise ResourceNotFoundError(f"Incident not found: {incident_id}")

        validate_response_target(conn, endpoint_id, action_type, target_value, meta)

        if action_type == "isolate_endpoint" and ep["isolation_state"] in {
            "isolating",
            "isolated",
        }:
            raise ConflictActionError(
                f"Endpoint {endpoint_id} is already in '{ep['isolation_state']}' state."
            )

        action_id = f"act_{uuid.uuid4().hex[:16]}"
        conn.execute(
            """
            INSERT INTO response_actions(
                action_id, endpoint_id, incident_id, action_type, target_value,
                target_metadata_json, reason, status, requested_by, requested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?)
            """,
            (
                action_id,
                endpoint_id,
                incident_id,
                action_type,
                target_value.strip(),
                json.dumps(meta),
                reason.strip(),
                actor["user_id"],
                now,
            ),
        )
        append_audit_log(
            conn,
            actor_id=actor["user_id"],
            actor_role=actor["role"],
            action="response.proposed",
            resource_type="response_action",
            resource_id=action_id,
            detail={
                "endpoint_id": endpoint_id,
                "incident_id": incident_id,
                "action_type": action_type,
                "target_value": target_value.strip(),
                "reason": reason.strip(),
            },
        )
        row = conn.execute(
            "SELECT * FROM response_actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
    return _format_action(row)


def decide_response_action(
    action_id: str,
    decision: str,
    actor: dict[str, Any],
    note: str = "",
    soc_approval_id: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    if decision not in {"approve", "reject"}:
        raise ValueError("Decision must be 'approve' or 'reject'.")
    now = utc_now_iso()
    new_status = "approved" if decision == "approve" else "rejected"
    with get_connection(settings) as conn:
        row = conn.execute(
            "SELECT * FROM response_actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None:
            raise ResourceNotFoundError(f"Response action not found: {action_id}")
        if row["status"] != "pending_approval":
            raise ConflictActionError(
                f"Response action {action_id} cannot be decided from status '{row['status']}'."
            )

        conn.execute(
            """
            UPDATE response_actions
            SET status = ?, approved_by = ?, decided_at = ?, decision_note = ?, soc_approval_id = ?
            WHERE action_id = ?
            """,
            (new_status, actor["user_id"], now, note.strip(), soc_approval_id, action_id),
        )
        if decision == "approve" and row["action_type"] == "isolate_endpoint":
            conn.execute(
                "UPDATE endpoints SET isolation_state = 'isolating' WHERE endpoint_id = ?",
                (row["endpoint_id"],),
            )

        append_audit_log(
            conn,
            actor_id=actor["user_id"],
            actor_role=actor["role"],
            action=f"response.{new_status}",
            resource_type="response_action",
            resource_id=action_id,
            detail={
                "endpoint_id": row["endpoint_id"],
                "action_type": row["action_type"],
                "target_value": row["target_value"],
                "decision_note": note.strip(),
                "soc_approval_id": soc_approval_id,
            },
        )
        updated = conn.execute(
            "SELECT * FROM response_actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
    return _format_action(updated)


def initiate_rollback(
    action_id: str,
    actor: dict[str, Any],
    reason: str = "Controlled analyst recovery",
    settings: Settings | None = None,
) -> dict[str, Any]:
    now = utc_now_iso()
    with get_connection(settings) as conn:
        orig = conn.execute(
            "SELECT * FROM response_actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if orig is None:
            raise ResourceNotFoundError(f"Response action not found: {action_id}")
        if orig["status"] != "executed":
            raise ConflictActionError(
                f"Only executed actions can be rolled back (current status: '{orig['status']}')."
            )
        if orig["rollback_action_id"]:
            raise ConflictActionError(
                f"Rollback already initiated under action {orig['rollback_action_id']}."
            )

        rb_id = f"act_{uuid.uuid4().hex[:16]}"
        endpoint_id = orig["endpoint_id"]
        if orig["action_type"] == "isolate_endpoint":
            rb_type = "release_isolation"
            rb_target = endpoint_id
            rb_meta: dict[str, Any] = {"original_action_id": action_id}
            conn.execute(
                "UPDATE endpoints SET isolation_state = 'releasing' WHERE endpoint_id = ?",
                (endpoint_id,),
            )
        elif orig["action_type"] == "quarantine_file":
            qrow = conn.execute(
                "SELECT * FROM quarantine_vault WHERE action_id = ? AND status = 'quarantined'",
                (action_id,),
            ).fetchone()
            if qrow is None:
                raise ConflictActionError(
                    f"No active quarantined item found for action {action_id}."
                )
            rb_type = "restore_file"
            rb_target = qrow["vault_path"]
            rb_meta = {
                "original_action_id": action_id,
                "quarantine_id": qrow["quarantine_id"],
                "original_path": qrow["original_path"],
                "vault_path": qrow["vault_path"],
                "sha256_before": qrow["sha256_before"],
            }
        else:
            raise ProtectedTargetError(
                "ROLLBACK_UNSUPPORTED",
                f"Action type '{orig['action_type']}' is not automatically reversible.",
                {"action_id": action_id, "action_type": orig["action_type"]},
            )

        conn.execute(
            """
            INSERT INTO response_actions(
                action_id, endpoint_id, incident_id, action_type, target_value,
                target_metadata_json, reason, status, requested_by, requested_at,
                approved_by, decided_at, decision_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?)
            """,
            (
                rb_id,
                endpoint_id,
                orig["incident_id"],
                rb_type,
                rb_target,
                json.dumps(rb_meta),
                reason.strip(),
                actor["user_id"],
                now,
                actor["user_id"],
                now,
                f"Rollback of {action_id}",
            ),
        )
        conn.execute(
            "UPDATE response_actions SET rollback_action_id = ? WHERE action_id = ?",
            (rb_id, action_id),
        )
        append_audit_log(
            conn,
            actor_id=actor["user_id"],
            actor_role=actor["role"],
            action="response.rollback_initiated",
            resource_type="response_action",
            resource_id=rb_id,
            detail={
                "original_action_id": action_id,
                "endpoint_id": endpoint_id,
                "rollback_type": rb_type,
                "reason": reason.strip(),
            },
        )
        rb_row = conn.execute(
            "SELECT * FROM response_actions WHERE action_id = ?",
            (rb_id,),
        ).fetchone()
    return _format_action(rb_row)


def ack_agent_command(
    endpoint_id: str,
    action_id: str,
    success: bool,
    verification: dict[str, Any],
    executed_at: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    now = executed_at or utc_now_iso()
    with get_connection(settings) as conn:
        row = conn.execute(
            "SELECT * FROM response_actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if row is None or row["endpoint_id"] != endpoint_id:
            raise ResourceNotFoundError(f"Command action {action_id} not found for endpoint.")
        if row["status"] not in {"approved", "dispatched"}:
            raise ConflictActionError(
                f"Command {action_id} is in terminal/invalid status '{row['status']}'."
            )

        final_status = "executed" if success else "failed"
        conn.execute(
            """
            UPDATE response_actions
            SET status = ?, executed_at = ?, verification_json = ?
            WHERE action_id = ?
            """,
            (final_status, now, json.dumps(verification), action_id),
        )

        action_type = row["action_type"]
        if success:
            if action_type == "isolate_endpoint":
                conn.execute(
                    """
                    UPDATE endpoints
                    SET status = 'isolated', isolation_state = 'isolated'
                    WHERE endpoint_id = ?
                    """,
                    (endpoint_id,),
                )
            elif action_type == "release_isolation":
                conn.execute(
                    """
                    UPDATE endpoints
                    SET isolation_state = 'none', status = 'online'
                    WHERE endpoint_id = ?
                    """,
                    (endpoint_id,),
                )
                meta = json.loads(row["target_metadata_json"] or "{}")
                orig_id = meta.get("original_action_id")
                if orig_id:
                    conn.execute(
                        "UPDATE response_actions SET status = 'rolled_back' WHERE action_id = ?",
                        (orig_id,),
                    )
            elif action_type == "quarantine_file":
                q_id = str(verification.get("quarantine_id") or f"qtn_{uuid.uuid4().hex[:14]}")
                orig_path = str(verification.get("original_path") or row["target_value"])
                vault_path = str(verification.get("vault_path") or "")
                sha_before = str(verification.get("sha256_before") or "")
                sha_after = str(verification.get("sha256_after") or sha_before)
                size_bytes = int(verification.get("size_bytes") or 0)
                conn.execute(
                    """
                    INSERT INTO quarantine_vault(
                        quarantine_id, endpoint_id, action_id, original_path, vault_path,
                        sha256_before, sha256_after, size_bytes, status, quarantined_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'quarantined', ?)
                    """,
                    (
                        q_id,
                        endpoint_id,
                        action_id,
                        orig_path,
                        vault_path,
                        sha_before,
                        sha_after,
                        size_bytes,
                        now,
                    ),
                )
            elif action_type == "restore_file":
                meta = json.loads(row["target_metadata_json"] or "{}")
                q_id = str(verification.get("quarantine_id") or meta.get("quarantine_id") or "")
                if q_id:
                    conn.execute(
                        """
                        UPDATE quarantine_vault
                        SET status = 'restored', restored_at = ?
                        WHERE quarantine_id = ?
                        """,
                        (now, q_id),
                    )
                orig_id = meta.get("original_action_id")
                if orig_id:
                    conn.execute(
                        "UPDATE response_actions SET status = 'rolled_back' WHERE action_id = ?",
                        (orig_id,),
                    )

            if row["incident_id"] and action_type in {
                "isolate_endpoint",
                "quarantine_file",
                "terminate_process",
            }:
                conn.execute(
                    """
                    UPDATE incidents SET status = 'contained'
                    WHERE incident_id = ? AND status = 'open'
                    """,
                    (row["incident_id"],),
                )
        elif action_type == "isolate_endpoint":
            conn.execute(
                "UPDATE endpoints SET isolation_state = 'none' WHERE endpoint_id = ?",
                (endpoint_id,),
            )

        append_audit_log(
            conn,
            actor_id=endpoint_id,
            actor_role="agent",
            action=f"response.{final_status}",
            resource_type="response_action",
            resource_id=action_id,
            detail={
                "action_type": action_type,
                "target_value": row["target_value"],
                "verification": verification,
            },
        )
        updated = conn.execute(
            "SELECT * FROM response_actions WHERE action_id = ?",
            (action_id,),
        ).fetchone()
    return _format_action(updated)


def list_response_actions(
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
            f"SELECT * FROM response_actions {where_sql} ORDER BY requested_at DESC LIMIT ?",
            params,
        ).fetchall()
    return [_format_action(r) for r in rows]


def list_quarantine_items(
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
            f"SELECT * FROM quarantine_vault {where_sql} ORDER BY quarantined_at DESC LIMIT ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]
