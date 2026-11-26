"""Tamper-evident append-only SHA-256 hash-chained audit logging."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from typing import Any

from app.config import Settings
from app.db import get_connection, utc_now_iso

GENESIS_HASH = "0" * 64


def _compute_entry_hash(
    prev_hash: str,
    audit_id: str,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    detail_json: str,
    created_at: str,
) -> str:
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "audit_id": audit_id,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "detail_json": detail_json,
            "created_at": created_at,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_audit_log(
    conn: sqlite3.Connection,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    last_row = conn.execute(
        "SELECT entry_hash FROM audit_logs ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    prev_hash = str(last_row["entry_hash"]) if last_row else GENESIS_HASH

    audit_id = f"aud_{uuid.uuid4().hex[:16]}"
    now = utc_now_iso()
    detail_obj = detail or {}
    detail_json = json.dumps(detail_obj, sort_keys=True, ensure_ascii=False)
    entry_hash = _compute_entry_hash(
        prev_hash,
        audit_id,
        actor_id,
        actor_role,
        action,
        resource_type,
        resource_id,
        detail_json,
        now,
    )
    cur = conn.execute(
        """
        INSERT INTO audit_logs(
            audit_id, actor_id, actor_role, action, resource_type,
            resource_id, detail_json, prev_hash, entry_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            audit_id,
            actor_id,
            actor_role,
            action,
            resource_type,
            resource_id,
            detail_json,
            prev_hash,
            entry_hash,
            now,
        ),
    )
    return {
        "seq": cur.lastrowid,
        "audit_id": audit_id,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": detail_obj,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
        "created_at": now,
    }


def list_audit_logs(
    action: str | None = None,
    resource_type: str | None = None,
    limit: int = 100,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if action:
        clauses.append("action = ?")
        params.append(action)
    if resource_type:
        clauses.append("resource_type = ?")
        params.append(resource_type)
    where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(max(1, min(limit, 500)))
    with get_connection(settings) as conn:
        rows = conn.execute(
            f"SELECT * FROM audit_logs {where_sql} ORDER BY seq DESC LIMIT ?",
            params,
        ).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        item["detail"] = json.loads(item.pop("detail_json", "{}"))
        items.append(item)
    return items


def verify_audit_chain(settings: Settings | None = None) -> dict[str, Any]:
    """Verify full SHA-256 prev_hash -> entry_hash chain continuity."""
    with get_connection(settings) as conn:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY seq ASC").fetchall()

    expected_prev = GENESIS_HASH
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "total_entries": len(rows),
                "broken_seq": r["seq"],
                "reason": "prev_hash_mismatch",
            }
        recomputed = _compute_entry_hash(
            r["prev_hash"],
            r["audit_id"],
            r["actor_id"],
            r["actor_role"],
            r["action"],
            r["resource_type"],
            r["resource_id"],
            r["detail_json"],
            r["created_at"],
        )
        if recomputed != r["entry_hash"]:
            return {
                "valid": False,
                "total_entries": len(rows),
                "broken_seq": r["seq"],
                "reason": "entry_hash_tampered",
            }
        expected_prev = r["entry_hash"]

    return {
        "valid": True,
        "total_entries": len(rows),
        "broken_seq": None,
        "head_hash": expected_prev,
    }
