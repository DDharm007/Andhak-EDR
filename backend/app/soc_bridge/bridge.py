"""ANDHAK SOC HMAC-authenticated bridge implementing SOC_INTEGRATION_CONTRACT.md."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import sqlite3
import time
import uuid
from typing import Any

import httpx

from app.config import Settings, get_settings
from app.db import get_connection, utc_now_iso
from app.detection.intel_service import classify_ioc
from app.response.audit import append_audit_log
from app.response.engine import propose_response_action
from app.response.safety import ProtectedTargetError

SUPPORTED_SOC_ACTIONS = frozenset(
    {
        "isolate_endpoint",
        "release_isolation",
        "terminate_process",
        "quarantine_file",
        "block_network_indicator",
    }
)


_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_public_ip(val: str | None) -> bool:
    if not val:
        return False
    try:
        ip = ipaddress.ip_address(val)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return False
        return not any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def sign_bridge_payload(shared_secret: str, timestamp: str, raw_body: bytes) -> str:
    msg = timestamp.encode("utf-8") + b"." + raw_body
    return hmac.new(shared_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_bridge_signature(
    shared_secret: str,
    timestamp: str | None,
    raw_body: bytes,
    provided_signature: str | None,
    max_skew_seconds: int = 300,
) -> tuple[bool, str]:
    if not timestamp or not provided_signature:
        return False, "Missing X-ANDHAK-Timestamp or X-ANDHAK-Signature header."
    try:
        ts_val = int(timestamp)
    except ValueError:
        return False, "X-ANDHAK-Timestamp must be Unix epoch seconds."
    if abs(int(time.time()) - ts_val) > max_skew_seconds:
        return False, "HMAC bridge timestamp outside allowed replay window."
    expected = sign_bridge_payload(shared_secret, timestamp, raw_body)
    sig_clean = provided_signature.removeprefix("sha256=").strip().lower()
    if not hmac.compare_digest(expected.lower(), sig_clean):
        return False, "Invalid HMAC-SHA256 bridge signature."
    return True, "ok"


def transform_alert_to_soc_event(
    conn: sqlite3.Connection,
    alert_row: sqlite3.Row | dict[str, Any],
) -> dict[str, Any]:
    ep = conn.execute(
        "SELECT hostname FROM endpoints WHERE endpoint_id = ?",
        (alert_row["endpoint_id"],),
    ).fetchone()
    hostname = ep["hostname"] if ep else alert_row["endpoint_id"]

    ev_ids = json.loads(alert_row["evidence_event_ids_json"] or "[]")
    remote_ip: str | None = None
    if ev_ids:
        placeholders = ",".join("?" for _ in ev_ids)
        net_ev = conn.execute(
            f"SELECT dest_ip FROM telemetry_events WHERE event_id IN ({placeholders}) "
            "AND dest_ip IS NOT NULL LIMIT 1",
            tuple(ev_ids),
        ).fetchone()
        if net_ev and _is_public_ip(net_ev["dest_ip"]):
            remote_ip = str(net_ev["dest_ip"])

    proc = alert_row["process_name"] or "host"
    pid_part = f"PID {alert_row['pid']}" if alert_row["pid"] else "host"
    sha_part = str(alert_row["file_sha256"] or "")[:12] or "no-hash"
    techs = json.loads(alert_row["mitre_techniques_json"] or "[]")
    mitre_str = ", ".join(t.lower() for t in techs) or "unmapped"

    return {
        "event_id": f"edr-{alert_row['alert_id']}",
        "timestamp": alert_row["detected_at"],
        "source_system": f"ANDHAK EDR · {alert_row['detection_source']}",
        "event_type": alert_row["rule_id"],
        "severity": alert_row["severity"],
        "summary": f"{alert_row['rule_name']} ({hostname})",
        "endpoint": hostname,
        "evidence_reference": f"{proc} · {pid_part} · {sha_part}",
        "details": (
            f"{alert_row['evidence_summary']} | "
            f"Confidence: {float(alert_row['confidence']):.2f} | "
            f"ATT&CK: {mitre_str} | Origin: {alert_row['telemetry_origin']}"
        ),
        "source_ip": remote_ip,
    }


def list_soc_normalized_events(
    limit: int = 100,
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    cfg = settings or get_settings()
    with get_connection(cfg) as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY detected_at DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        ).fetchall()
        return [transform_alert_to_soc_event(conn, r) for r in rows]


def _log_sync(
    conn: sqlite3.Connection,
    direction: str,
    entity_type: str,
    entity_id: str,
    soc_reference_id: str | None,
    status: str,
    detail: str,
) -> None:
    conn.execute(
        """
        INSERT INTO soc_bridge_sync_log(
            sync_id, direction, entity_type, entity_id,
            soc_reference_id, status, detail, synced_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            f"syn_{uuid.uuid4().hex[:16]}",
            direction,
            entity_type,
            entity_id,
            soc_reference_id,
            status,
            detail[:500],
            utc_now_iso(),
        ),
    )


async def sync_with_soc(
    settings: Settings | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Synchronize normalized EDR alerts & bidirectional IOCs with ANDHAK SOC safely."""
    cfg = settings or get_settings()
    now = utc_now_iso()
    if not cfg.soc_enabled:
        return {
            "soc_enabled": False,
            "soc_reachable": False,
            "alerts_queued": 0,
            "iocs_pulled": 0,
            "iocs_pushed": 0,
            "detail": "ANDHAK_SOC_ENABLED=false",
        }

    with get_connection(cfg) as conn:
        pending_alerts = conn.execute(
            """
            SELECT a.* FROM alerts a
            WHERE NOT EXISTS (
                SELECT 1 FROM soc_bridge_sync_log s
                WHERE s.entity_type = 'alert' AND s.entity_id = a.alert_id AND s.status = 'synced'
            )
            ORDER BY a.detected_at DESC LIMIT 100
            """
        ).fetchall()
        edr_events = [transform_alert_to_soc_event(conn, a) for a in pending_alerts]
        local_iocs = conn.execute(
            "SELECT * FROM iocs ORDER BY created_at DESC LIMIT 200"
        ).fetchall()

    soc_reachable = False
    soc_health: dict[str, Any] = {}
    iocs_pulled = 0
    iocs_pushed = 0
    bridge_error: str | None = None

    async def _run(client: httpx.AsyncClient) -> None:
        nonlocal soc_reachable, soc_health, iocs_pulled, iocs_pushed, bridge_error
        base = cfg.soc_base_url.rstrip("/")
        try:
            h_res = await client.get(f"{base}/api/v1/health")
            if h_res.status_code == 200:
                soc_reachable = True
                soc_health = h_res.json()
        except httpx.RequestError as exc:
            bridge_error = str(exc)
            return

        # 1. Pull SOC indicators into local EDR watchlist
        try:
            ind_res = await client.get(f"{base}/api/v1/intelligence/indicators")
            if ind_res.status_code == 200:
                soc_inds = ind_res.json()
                with get_connection(cfg) as conn:
                    for item in soc_inds:
                        val = str(item.get("value", "")).strip()
                        if not val:
                            continue
                        try:
                            kind, norm_val = classify_ioc(val)
                        except ValueError:
                            continue
                        sev = item.get("severity", "medium")
                        desc = str(item.get("description", "Synced from ANDHAK SOC"))
                        cur = conn.execute(
                            """
                            INSERT OR IGNORE INTO iocs(
                                ioc_id, value, kind, severity, source, description,
                                mitre_tags_json, created_at
                            ) VALUES (?, ?, ?, ?, 'soc_watchlist', ?, '[]', ?)
                            """,
                            (f"ioc_{uuid.uuid4().hex[:14]}", norm_val, kind, sev, desc, now),
                        )
                        if cur.rowcount > 0:
                            iocs_pulled += 1
                            _log_sync(
                                conn,
                                "soc_to_edr",
                                "ioc",
                                norm_val,
                                str(item.get("id", norm_val)),
                                "synced",
                                f"Imported SOC {kind} indicator",
                            )
        except httpx.RequestError as exc:
            bridge_error = str(exc)

        # 2. Push EDR IOCs (non-internal values only) to ANDHAK SOC
        for row in local_iocs:
            if row["source"] == "soc_watchlist":
                continue
            val = str(row["value"]).strip()
            if val.lower() in {"127.0.0.1", "localhost", "::1"}:
                continue
            try:
                p_res = await client.post(
                    f"{base}/api/v1/intelligence/indicators",
                    json={
                        "value": val,
                        "severity": row["severity"],
                        "description": f"[ANDHAK EDR] {row['description'] or row['kind']}",
                    },
                )
                if p_res.status_code in {200, 201}:
                    iocs_pushed += 1
                    with get_connection(cfg) as conn:
                        _log_sync(
                            conn,
                            "edr_to_soc",
                            "ioc",
                            row["ioc_id"],
                            val,
                            "synced",
                            "Pushed EDR indicator to ANDHAK SOC",
                        )
            except httpx.RequestError:
                break

    if http_client is not None:
        await _run(http_client)
    else:
        async with httpx.AsyncClient(timeout=2.5) as c:
            await _run(c)

    # Record normalized event availability in sync log
    with get_connection(cfg) as conn:
        for ev in edr_events:
            alert_id = ev["event_id"].removeprefix("edr-")
            _log_sync(
                conn,
                "edr_to_soc",
                "alert",
                alert_id,
                ev["event_id"],
                "synced" if soc_reachable else "pending",
                "Prepared normalized SOC event envelope"
                + (" (SOC reachable)" if soc_reachable else " (SOC offline; queued locally)"),
            )

    return {
        "soc_enabled": True,
        "soc_base_url": cfg.soc_base_url,
        "soc_reachable": soc_reachable,
        "soc_service": soc_health.get("service"),
        "events_normalized": len(edr_events),
        "iocs_pulled": iocs_pulled,
        "iocs_pushed": iocs_pushed,
        "detail": bridge_error
        or ("Synchronized with ANDHAK SOC" if soc_reachable else "SOC offline"),
    }


def handle_soc_response_request(
    payload: dict[str, Any],
    settings: Settings | None = None,
) -> tuple[int, dict[str, Any]]:
    cfg = settings or get_settings()
    action_type = str(payload.get("action_type", "")).strip()
    if action_type == "revoke_session":
        return (
            501,
            {
                "error": "no identity connector",
                "detail": "Identity session revocation is unsupported without an external IdP.",
            },
        )
    if action_type not in SUPPORTED_SOC_ACTIONS:
        return (
            422,
            {"error": "UNSUPPORTED_SOC_ACTION", "detail": f"Unsupported action '{action_type}'."},
        )

    ep_host = str(payload.get("endpoint_hostname", "")).strip()
    target_val = str(payload.get("target_value", "")).strip()
    reason = str(payload.get("reason", "Triggered via ANDHAK SOC bridge")).strip()
    soc_approval_id = str(payload.get("soc_approval_id", "")).strip() or None
    soc_actor = str(payload.get("soc_actor", "soc_operator")).strip()

    with get_connection(cfg) as conn:
        ep = conn.execute(
            """
            SELECT endpoint_id, hostname FROM endpoints
            WHERE endpoint_id = ? OR LOWER(hostname) = LOWER(?)
            ORDER BY last_heartbeat_at DESC LIMIT 1
            """,
            (ep_host, ep_host),
        ).fetchone()
        if ep is None:
            return (
                404,
                {"detail": f"No enrolled EDR endpoint matching '{ep_host}'."},
            )
        endpoint_id = ep["endpoint_id"]

    # Route through standard EDR response engine (enforces ProtectedTargetError & pending_approval)
    actor = {"user_id": f"soc:{soc_actor}", "role": "analyst"}
    actual_target = (
        endpoint_id if action_type in {"isolate_endpoint", "release_isolation"} else target_val
    )
    try:
        action = propose_response_action(
            endpoint_id=endpoint_id,
            action_type=action_type,
            target_value=actual_target,
            reason=f"[SOC Bridge {soc_approval_id or 'unlinked'}] {reason}",
            actor=actor,
            target_metadata=payload.get("target_metadata") or {},
            settings=cfg,
        )
    except ProtectedTargetError as exc:
        return 422, exc.to_envelope()

    with get_connection(cfg) as conn:
        if soc_approval_id:
            conn.execute(
                "UPDATE response_actions SET soc_approval_id = ? WHERE action_id = ?",
                (soc_approval_id, action["action_id"]),
            )
            action["soc_approval_id"] = soc_approval_id
        _log_sync(
            conn,
            "soc_to_edr",
            "response",
            action["action_id"],
            soc_approval_id,
            "synced",
            f"Queued SOC {action_type} proposal awaiting EDR responder RBAC approval",
        )
        append_audit_log(
            conn,
            actor_id=f"soc:{soc_actor}",
            actor_role="soc_bridge",
            action="soc_bridge.response_queued",
            resource_type="response_action",
            resource_id=action["action_id"],
            detail={"soc_approval_id": soc_approval_id, "endpoint_id": endpoint_id},
        )
    return 202, {
        "bridge_status": "queued_for_edr_approval",
        "action": action,
    }


def get_soc_bridge_status(settings: Settings | None = None) -> dict[str, Any]:
    cfg = settings or get_settings()
    with get_connection(cfg) as conn:
        logs = conn.execute(
            "SELECT * FROM soc_bridge_sync_log ORDER BY synced_at DESC LIMIT 40"
        ).fetchall()
        counts = conn.execute(
            "SELECT status, COUNT(*) AS cnt FROM soc_bridge_sync_log GROUP BY status"
        ).fetchall()
    return {
        "soc_enabled": cfg.soc_enabled,
        "soc_base_url": cfg.soc_base_url,
        "summary_counts": {r["status"]: r["cnt"] for r in counts},
        "recent_sync_logs": [dict(r) for r in logs],
    }
