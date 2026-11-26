"""Stage 04 tests: incident correlation, process tree, timeline, forensics, and hunting."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.db import get_connection, init_database
from app.main import app
from app.services.ingest import issue_enrollment_token


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    db_file = tmp_path / "stage04-test.sqlite3"
    monkeypatch.setenv("ANDHAK_EDR_DB_PATH", str(db_file))
    monkeypatch.setenv("ANDHAK_INTEL_EXTERNAL_ENABLED", "false")
    get_settings.cache_clear()
    init_database(Settings(db_path=db_file))
    with TestClient(app) as tc:
        yield tc
    get_settings.cache_clear()


def _enroll(client: TestClient, hostname: str = "CORR-HOST") -> tuple[str, str]:
    tok = issue_enrollment_token(description=hostname)["bootstrap_token"]
    res = client.post(
        "/api/v1/agent/enroll",
        json={
            "bootstrap_token": tok,
            "hostname": hostname,
            "os_family": "windows",
            "os_version": "Windows 11",
            "architecture": "x86_64",
            "agent_version": "0.4.0",
        },
    )
    assert res.status_code == 201
    data = res.json()
    return data["endpoint_id"], data["agent_token"]


def _post_events(client: TestClient, endpoint_id: str, token: str, events: list[dict]) -> dict:
    batch = {
        "batch_id": f"b_{hashlib.sha256(json.dumps(events).encode()).hexdigest()[:12]}",
        "endpoint_id": endpoint_id,
        "sent_at": "2026-11-26T18:05:00Z",
        "events": events,
    }
    raw = json.dumps(batch).encode("utf-8")
    res = client.post(
        "/api/v1/agent/telemetry",
        content=raw,
        headers={
            "Authorization": f"Bearer {token}",
            "X-Endpoint-ID": endpoint_id,
            "X-Payload-SHA256": hashlib.sha256(raw).hexdigest(),
            "Content-Type": "application/json",
        },
    )
    assert res.status_code == 202, res.text
    return res.json()


def test_multi_stage_correlation_forensics_triage_and_hunting(
    client: TestClient, tmp_path: Path
) -> None:
    ep_id, tok = _enroll(client, "ATTACK-CHAIN-WS01")

    # Prepare a real baseline file for hosts-like FIM tamper verification
    etc_dir = tmp_path / "System32" / "drivers" / "etc"
    etc_dir.mkdir(parents=True)
    hosts_file = etc_dir / "hosts"
    hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    base_res = client.post(
        "/api/v1/fim/baselines",
        json={"endpoint_id": ep_id, "directory": str(etc_dir), "recursive": False},
    )
    assert base_res.status_code == 201

    # Seed IOC matching C2 IP
    ioc_res = client.post(
        "/api/v1/intel/iocs",
        json={"value": "203.0.113.55", "severity": "critical", "description": "C2 Node"},
    )
    assert ioc_res.status_code == 201

    g_word = f"{ep_id}-100-1"
    g_ps = f"{ep_id}-200-2"
    g_drop = f"{ep_id}-300-3"
    drop_path = "C:\\Users\\Analyst\\AppData\\Local\\Temp\\payload.exe"
    drop_sha = "c" * 64

    events = [
        # 1. winword.exe parent process
        {
            "event_id": "evt_chain_01",
            "telemetry_origin": "test_fixture",
            "category": "process",
            "event_type": "process_start",
            "occurred_at": "2026-11-26T18:00:00Z",
            "dedup_hash": hashlib.sha256(b"chain_01").hexdigest(),
            "process": {
                "process_guid": g_word,
                "pid": 100,
                "ppid": 4,
                "name": "winword.exe",
                "executable_path": "C:\\Program Files\\Microsoft Office\\winword.exe",
                "command_line": "winword.exe report.docm",
                "user_context": "CORP\\User",
                "signature_status": "valid",
                "signer_subject": "CN=Microsoft Corporation",
                "started_at": "2026-11-26T18:00:00Z",
            },
        },
        # 2. winword -> powershell -EncodedCommand + schtasks persistence
        {
            "event_id": "evt_chain_02",
            "telemetry_origin": "test_fixture",
            "category": "process",
            "event_type": "process_start",
            "occurred_at": "2026-11-26T18:00:05Z",
            "dedup_hash": hashlib.sha256(b"chain_02").hexdigest(),
            "process": {
                "process_guid": g_ps,
                "parent_process_guid": g_word,
                "pid": 200,
                "ppid": 100,
                "name": "powershell.exe",
                "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": (
                    "powershell.exe -EncodedCommand SQBFAFgA && schtasks /create /tn Upd /tr x"
                ),
                "user_context": "CORP\\User",
                "signature_status": "valid",
                "signer_subject": "CN=Microsoft Windows",
                "started_at": "2026-11-26T18:00:05Z",
            },
        },
        # 3. Drop unsigned payload.exe into Temp
        {
            "event_id": "evt_chain_03",
            "telemetry_origin": "test_fixture",
            "category": "filesystem",
            "event_type": "file_created",
            "occurred_at": "2026-11-26T18:00:10Z",
            "dedup_hash": hashlib.sha256(b"chain_03").hexdigest(),
            "filesystem": {
                "file_path": drop_path,
                "sha256": drop_sha,
                "size_bytes": 4096,
                "signature_status": "unsigned",
            },
        },
        # 4. Execute unsigned payload.exe as child of powershell.exe
        {
            "event_id": "evt_chain_04",
            "telemetry_origin": "test_fixture",
            "category": "process",
            "event_type": "process_start",
            "occurred_at": "2026-11-26T18:00:15Z",
            "dedup_hash": hashlib.sha256(b"chain_04").hexdigest(),
            "process": {
                "process_guid": g_drop,
                "parent_process_guid": g_ps,
                "pid": 300,
                "ppid": 200,
                "name": "payload.exe",
                "executable_path": drop_path,
                "command_line": drop_path,
                "user_context": "CORP\\User",
                "sha256": drop_sha,
                "signature_status": "unsigned",
                "started_at": "2026-11-26T18:00:15Z",
            },
        },
        # 5. Outbound C2 socket to 203.0.113.55:4444
        {
            "event_id": "evt_chain_05",
            "telemetry_origin": "test_fixture",
            "category": "network",
            "event_type": "socket_observed",
            "occurred_at": "2026-11-26T18:00:20Z",
            "dedup_hash": hashlib.sha256(b"chain_05").hexdigest(),
            "network": {
                "protocol": "tcp",
                "local_addr": "10.0.0.45",
                "local_port": 51200,
                "remote_addr": "203.0.113.55",
                "remote_port": 4444,
                "state": "ESTABLISHED",
                "pid": 300,
                "process_name": "payload.exe",
                "process_guid": g_drop,
            },
        },
        # 6. Modify baselined hosts file -> FIM drift + BEH-006
        {
            "event_id": "evt_chain_06",
            "telemetry_origin": "test_fixture",
            "category": "filesystem",
            "event_type": "file_modified",
            "occurred_at": "2026-11-26T18:00:25Z",
            "dedup_hash": hashlib.sha256(b"chain_06").hexdigest(),
            "filesystem": {
                "file_path": str(hosts_file),
                "sha256": "d" * 64,
                "size_bytes": 128,
                "signature_status": "unsigned",
            },
        },
    ]

    ingest_res = _post_events(client, ep_id, tok, events)
    assert ingest_res["accepted"] == 6
    assert ingest_res["alerts_emitted"] >= 6

    # All alerts within the window must correlate into ONE incident
    inc_list = client.get("/api/v1/incidents", params={"endpoint_id": ep_id}).json()
    assert inc_list["total"] == 1
    incident_id = inc_list["items"][0]["incident_id"]
    assert inc_list["items"][0]["alert_count"] >= 6
    assert inc_list["items"][0]["risk_score"] >= 70
    assert inc_list["items"][0]["root_process_guid"] == g_word

    # Verify full incident detail: process tree, React Flow graph, timeline, ATT&CK evidence
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["process_count"] == 3
    root = detail["process_tree"][0]
    assert root["process_name"] == "winword.exe"
    assert root["children"][0]["process_name"] == "powershell.exe"
    assert root["children"][0]["children"][0]["process_name"] == "payload.exe"

    graph_res = client.get(f"/api/v1/incidents/{incident_id}/graph").json()
    node_types = {n["data"]["kind"] for n in graph_res["graph"]["nodes"]}
    assert {"endpoint", "process", "alert", "network", "file"}.issubset(node_types)
    assert len(graph_res["graph"]["edges"]) >= 6

    timeline_ts = [entry["timestamp"] for entry in detail["timeline"]]
    assert timeline_ts == sorted(timeline_ts)
    entry_types = {entry["entry_type"] for entry in detail["timeline"]}
    assert {"alert", "telemetry", "fim"}.issubset(entry_types)

    mitre_ids = {m["technique_id"] for m in detail["mitre_evidence"]}
    assert {"T1059.001", "T1053.005", "T1105", "T1071.001", "T1565.001"}.issubset(mitre_ids)
    # T1486 (ransomware burst) was not triggered, so it must NOT appear
    assert "T1486" not in mitre_ids
    for item in detail["mitre_evidence"]:
        assert item["supporting_alert_ids"]
        assert item["supporting_event_ids"]

    # Deterministic investigation report (Zero-AI)
    inv_res = client.post(f"/api/v1/incidents/{incident_id}/investigate")
    assert inv_res.status_code == 200
    inv = inv_res.json()
    assert inv["engine_mode"] == "deterministic_rules_v1"
    assert "evt_chain_02" in inv["cited_evidence_ids"]
    assert "evt_chain_05" in inv["cited_evidence_ids"]
    check_names = {c["check"]: c["status"] for c in inv["false_positive_checks"]}
    assert check_names["multi_signal_corroboration"] == "corroborated"
    assert check_names["authenticode_posture"] == "elevated_suspicion"
    assert len(inv["recommended_runbook"]) >= 2
    assert all(step["requires_approval"] is True for step in inv["recommended_runbook"])

    # Forensic bundle generation + SHA-256 verification + tamper detection
    bnd_create = client.post(
        f"/api/v1/incidents/{incident_id}/forensics",
        json={"collected_by": "analyst_priya"},
    )
    assert bnd_create.status_code == 201
    bundle_id = bnd_create.json()["bundle_id"]

    bnd_fetch = client.get(f"/api/v1/forensics/{bundle_id}")
    assert bnd_fetch.status_code == 200
    assert bnd_fetch.json()["integrity_verified"] is True
    assert bnd_fetch.json()["bundle"]["provenance"]["telemetry_origin"] == "test_fixture"

    # Mutate stored bundle_json directly and confirm integrity check catches tampering
    with get_connection() as conn:
        conn.execute(
            "UPDATE forensic_bundles SET bundle_json = ? WHERE bundle_id = ?",
            ('{"tampered": true}', bundle_id),
        )
    tampered = client.get(f"/api/v1/forensics/{bundle_id}").json()
    assert tampered["integrity_verified"] is False

    # Threat hunting filters
    hunt_proc = client.get("/api/v1/hunting/search", params={"process": "payload"}).json()
    assert hunt_proc["total"] >= 2
    assert all("payload.exe" in (item["process_name"] or "").lower() for item in hunt_proc["items"])

    hunt_ip = client.get("/api/v1/hunting/search", params={"ip": "203.0.113.55"}).json()
    assert hunt_ip["total"] == 1
    assert hunt_ip["items"][0]["event_id"] == "evt_chain_05"

    hunt_q = client.get(
        "/api/v1/hunting/search",
        params={"q": "EncodedCommand", "origin": "test_fixture"},
    ).json()
    assert hunt_q["total"] == 1
    assert hunt_q["items"][0]["event_id"] == "evt_chain_02"

    # Status update & 404 guards
    patch_res = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "contained"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "contained"
    assert client.get("/api/v1/incidents/inc_missing").status_code == 404
    assert client.get("/api/v1/forensics/bnd_missing").status_code == 404
