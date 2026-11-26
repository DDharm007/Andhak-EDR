"""Sanitized recorded demonstration scenarios clearly badged 'recorded_demo'."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from app.config import Settings, get_settings
from app.db import get_connection, hash_secret, init_database, utc_now_iso
from app.detection.pipeline import evaluate_ingested_event
from app.forensics.bundler import collect_forensic_bundle
from app.forensics.correlator import correlate_alerts_for_endpoint
from app.forensics.investigator import run_deterministic_investigation
from app.realtime.bus import event_bus
from app.response.audit import append_audit_log
from app.schemas import TelemetryEventIn

DEMO_SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "scenario_id": "staged-office-powershell-c2",
        "title": "Staged Macro -> Encoded PowerShell -> Temp Dropper -> C2 Beacon & hosts Tamper",
        "description": (
            "Sanitized recorded attack sequence demonstrating multi-stage correlation, "
            "process tree reconstruction, ATT&CK evidence mapping, and deterministic triage."
        ),
        "origin": "recorded_demo",
        "endpoint_hostname": "WS-FINANCE-04",
    },
    {
        "scenario_id": "ransomware-velocity-burst",
        "title": "High-Velocity Temp File Encryption Burst & Containment Runbook",
        "description": (
            "Demonstrates BEH-007 sliding-window burst detection and safe endpoint isolation "
            "proposal awaiting responder approval."
        ),
        "origin": "recorded_demo",
        "endpoint_hostname": "WS-OPS-09",
    },
)


def list_demo_scenarios() -> list[dict[str, Any]]:
    return [dict(s) for s in DEMO_SCENARIOS]


def seed_demo_scenario(
    scenario_id: str = "staged-office-powershell-c2",
    settings: Settings | None = None,
) -> dict[str, Any]:
    cfg = settings or get_settings()
    init_database(cfg)
    now = utc_now_iso()

    matched = [s for s in DEMO_SCENARIOS if s["scenario_id"] == scenario_id]
    if not matched:
        raise ValueError(f"Unknown demo scenario '{scenario_id}'.")

    ep_id = "ep_demo_ws_finance_04"
    g_word = f"{ep_id}-1400-1"
    g_ps = f"{ep_id}-2840-2"
    g_drop = f"{ep_id}-4120-3"
    drop_path = "C:\\Users\\analyst.demo\\AppData\\Local\\Temp\\updater_stage.exe"
    drop_sha = hashlib.sha256(b"recorded-demo-dropper-sample").hexdigest()
    hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts"

    with get_connection(cfg) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO endpoints(
                endpoint_id, hostname, fqdn, os_family, os_version, architecture,
                agent_version, primary_ip, status, isolation_state, posture_score,
                policy_id, policy_version, sysmon_available, elevated_sensor,
                telemetry_origin, enrolled_at, last_heartbeat_at, last_metrics_json
            ) VALUES (?, ?, ?, 'windows', 'Windows 11 Pro 24H2', 'x86_64', '0.6.0',
                '10.20.4.18', 'online', 'none', 64, 'pol_default_windows', 1, 0, 0,
                'recorded_demo', ?, ?, ?)
            """,
            (
                ep_id,
                "WS-FINANCE-04",
                "WS-FINANCE-04.demo.local",
                now,
                now,
                json.dumps(
                    {
                        "cpu_percent": 34.2,
                        "memory_used_mb": 6420,
                        "memory_total_mb": 16384,
                        "disk_used_percent": 61.5,
                        "agent_rss_mb": 18.4,
                        "spool_queue_depth": 0,
                        "sensors": {
                            "process": "ready",
                            "network": "ready",
                            "filesystem": "ready",
                            "system": "ready",
                            "sysmon": "unavailable",
                        },
                    }
                ),
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO iocs(
                ioc_id, value, kind, severity, source, description, mitre_tags_json, created_at
            ) VALUES (?, '203.0.113.55', 'ip', 'critical', 'soc_watchlist',
                      'Recorded demo C2 endpoint', '["T1071.001"]', ?)
            """,
            (f"ioc_{hashlib.md5(b'203.0.113.55').hexdigest()[:12]}", now),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO fim_baselines(
                baseline_id, endpoint_id, policy_id, file_path, sha256,
                size_bytes, signature_status, modified_at, captured_at
            ) VALUES (?, ?, 'pol_default_windows', ?, ?, 824, 'unsigned', ?, ?)
            """,
            (
                f"bas_demo_{ep_id}",
                ep_id,
                hosts_path,
                hashlib.sha256(b"baseline-hosts-demo").hexdigest(),
                now,
                now,
            ),
        )

        raw_events = [
            TelemetryEventIn(
                event_id="evt_demo_01",
                telemetry_origin="recorded_demo",
                category="process",
                event_type="process_start",
                severity="info",
                occurred_at="2026-11-26T18:00:00Z",
                dedup_hash=hashlib.sha256(b"demo_01").hexdigest(),
                process={
                    "process_guid": g_word,
                    "pid": 1400,
                    "ppid": 4,
                    "name": "winword.exe",
                    "executable_path": "C:\\Program Files\\Microsoft Office\\winword.exe",
                    "command_line": "winword.exe Q4_Statement.docm",
                    "user_context": "DEMO\\j.doe",
                    "signature_status": "valid",
                    "signer_subject": "CN=Microsoft Corporation",
                    "started_at": "2026-11-26T18:00:00Z",
                },
            ),
            TelemetryEventIn(
                event_id="evt_demo_02",
                telemetry_origin="recorded_demo",
                category="process",
                event_type="process_start",
                severity="high",
                occurred_at="2026-11-26T18:00:04Z",
                dedup_hash=hashlib.sha256(b"demo_02").hexdigest(),
                process={
                    "process_guid": g_ps,
                    "parent_process_guid": g_word,
                    "pid": 2840,
                    "ppid": 1400,
                    "name": "powershell.exe",
                    "executable_path": (
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    ),
                    "command_line": (
                        "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA "
                        "&& schtasks /create /tn AndhakUpdate /tr updater_stage.exe"
                    ),
                    "user_context": "DEMO\\j.doe",
                    "signature_status": "valid",
                    "signer_subject": "CN=Microsoft Windows",
                    "started_at": "2026-11-26T18:00:04Z",
                },
            ),
            TelemetryEventIn(
                event_id="evt_demo_03",
                telemetry_origin="recorded_demo",
                category="filesystem",
                event_type="file_created",
                severity="medium",
                occurred_at="2026-11-26T18:00:09Z",
                dedup_hash=hashlib.sha256(b"demo_03").hexdigest(),
                filesystem={
                    "file_path": drop_path,
                    "sha256": drop_sha,
                    "size_bytes": 18432,
                    "signature_status": "unsigned",
                },
            ),
            TelemetryEventIn(
                event_id="evt_demo_04",
                telemetry_origin="recorded_demo",
                category="process",
                event_type="process_start",
                severity="high",
                occurred_at="2026-11-26T18:00:13Z",
                dedup_hash=hashlib.sha256(b"demo_04").hexdigest(),
                process={
                    "process_guid": g_drop,
                    "parent_process_guid": g_ps,
                    "pid": 4120,
                    "ppid": 2840,
                    "name": "updater_stage.exe",
                    "executable_path": drop_path,
                    "command_line": drop_path,
                    "user_context": "DEMO\\j.doe",
                    "sha256": drop_sha,
                    "signature_status": "unsigned",
                    "started_at": "2026-11-26T18:00:13Z",
                },
            ),
            TelemetryEventIn(
                event_id="evt_demo_05",
                telemetry_origin="recorded_demo",
                category="network",
                event_type="socket_observed",
                severity="high",
                occurred_at="2026-11-26T18:00:18Z",
                dedup_hash=hashlib.sha256(b"demo_05").hexdigest(),
                network={
                    "protocol": "tcp",
                    "local_addr": "10.20.4.18",
                    "local_port": 52410,
                    "remote_addr": "203.0.113.55",
                    "remote_port": 4444,
                    "state": "ESTABLISHED",
                    "pid": 4120,
                    "process_name": "updater_stage.exe",
                    "process_guid": g_drop,
                },
            ),
            TelemetryEventIn(
                event_id="evt_demo_06",
                telemetry_origin="recorded_demo",
                category="filesystem",
                event_type="file_modified",
                severity="high",
                occurred_at="2026-11-26T18:00:24Z",
                dedup_hash=hashlib.sha256(b"demo_06").hexdigest(),
                filesystem={
                    "file_path": hosts_path,
                    "sha256": hashlib.sha256(b"tampered-hosts-demo").hexdigest(),
                    "size_bytes": 960,
                    "signature_status": "unsigned",
                },
            ),
        ]

        from app.services.ingest import _insert_telemetry_event

        for evt in raw_events:
            inserted = _insert_telemetry_event(conn, ep_id, evt, now)
            if inserted:
                evaluate_ingested_event(conn, ep_id, evt)

        incidents = correlate_alerts_for_endpoint(conn, ep_id)
        if not incidents:
            existing_inc = conn.execute(
                "SELECT incident_id FROM incidents WHERE endpoint_id = ? LIMIT 1",
                (ep_id,),
            ).fetchone()
            inc_id = existing_inc["incident_id"] if existing_inc else None
        else:
            inc_id = incidents[0]["incident_id"]

        # Seed a pending containment proposal & audit trail if none exist yet
        has_act = conn.execute(
            "SELECT 1 FROM response_actions WHERE endpoint_id = ? LIMIT 1",
            (ep_id,),
        ).fetchone()
        if has_act is None:
            act_id = f"act_demo_{hash_secret(ep_id)[:10]}"
            conn.execute(
                """
                INSERT INTO response_actions(
                    action_id, endpoint_id, incident_id, action_type, target_value,
                    target_metadata_json, reason, status, requested_by, requested_at
                ) VALUES (?, ?, ?, 'isolate_endpoint', ?, '{}', ?, 'pending_approval',
                          'usr_system_admin', ?)
                """,
                (act_id, ep_id, inc_id, ep_id, "Recorded demo containment proposal", now),
            )
            append_audit_log(
                conn,
                actor_id="usr_system_admin",
                actor_role="analyst",
                action="demo.scenario_seeded",
                resource_type="endpoint",
                resource_id=ep_id,
                detail={"scenario_id": scenario_id, "telemetry_origin": "recorded_demo"},
            )

    if inc_id:
        run_deterministic_investigation(inc_id, settings=cfg)
        collect_forensic_bundle(inc_id, collected_by="demo_recorder", settings=cfg)

    for evt in raw_events:
        event_bus.publish_sync(
            "telemetry",
            {
                "type": "telemetry.event",
                "origin": "recorded_demo",
                "endpoint_id": ep_id,
                "data": evt.model_dump(mode="json", exclude_none=True),
            },
        )

    return {
        "scenario_id": scenario_id,
        "origin": "recorded_demo",
        "endpoint_id": ep_id,
        "incident_id": inc_id,
        "replay_events": len(raw_events),
        "replay_token": uuid.uuid4().hex[:10],
    }
