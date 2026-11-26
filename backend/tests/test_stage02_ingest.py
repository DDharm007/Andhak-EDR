"""Stage 02 tests: agent enrollment, credential auth, heartbeat, batch dedup, and persistence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import init_database
from app.main import app
from app.services.ingest import issue_enrollment_token


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    db_file = tmp_path / "test-edr.sqlite3"
    monkeypatch.setenv("ANDHAK_EDR_DB_PATH", str(db_file))
    from app.config import get_settings

    get_settings.cache_clear()
    settings = Settings(db_path=db_file)
    init_database(settings)
    with TestClient(app) as tc:
        yield tc
    get_settings.cache_clear()


def test_health_and_enrollment_lifecycle(client: TestClient) -> None:
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    tok_res = client.post("/api/v1/agent/enrollment-tokens", json={"description": "lab"})
    assert tok_res.status_code == 201
    bootstrap = tok_res.json()["bootstrap_token"]

    enroll_body = {
        "bootstrap_token": bootstrap,
        "hostname": "TEST-WIN-01",
        "os_family": "windows",
        "os_version": "Windows 11",
        "architecture": "x86_64",
        "agent_version": "0.1.0",
        "primary_ip": "127.0.0.1",
        "elevated_sensor": False,
        "sysmon_available": False,
    }
    enroll = client.post("/api/v1/agent/enroll", json=enroll_body)
    assert enroll.status_code == 201
    creds = enroll.json()
    endpoint_id = creds["endpoint_id"]
    agent_token = creds["agent_token"]

    # Bootstrap token must be strictly single-use
    replay = client.post("/api/v1/agent/enroll", json=enroll_body)
    assert replay.status_code == 401

    # Heartbeat requires valid X-Endpoint-ID + Bearer token
    bad_hb = client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": "Bearer wrong", "X-Endpoint-ID": endpoint_id},
        json={
            "endpoint_id": endpoint_id,
            "agent_version": "0.1.0",
            "uptime_seconds": 10,
            "cpu_percent": 5.0,
            "memory_used_mb": 1000,
            "memory_total_mb": 4000,
            "disk_used_percent": 40.0,
            "agent_rss_mb": 12.0,
            "spool_queue_depth": 0,
            "policy_version": 1,
            "sensors": {
                "process": "ready",
                "network": "ready",
                "filesystem": "ready",
                "system": "ready",
                "sysmon": "unavailable",
            },
        },
    )
    assert bad_hb.status_code == 401

    good_hb = client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent_token}", "X-Endpoint-ID": endpoint_id},
        json={
            "endpoint_id": endpoint_id,
            "agent_version": "0.1.0",
            "uptime_seconds": 10,
            "cpu_percent": 12.5,
            "memory_used_mb": 2048,
            "memory_total_mb": 8192,
            "disk_used_percent": 55.0,
            "agent_rss_mb": 16.4,
            "spool_queue_depth": 0,
            "policy_version": 1,
            "sensors": {
                "process": "ready",
                "network": "ready",
                "filesystem": "ready",
                "system": "ready",
                "sysmon": "unavailable",
            },
        },
    )
    assert good_hb.status_code == 200
    assert good_hb.json()["pending_commands"] == []


def test_telemetry_batch_integrity_and_deduplication(client: TestClient) -> None:
    tok = issue_enrollment_token(description="ingest-test")
    enroll = client.post(
        "/api/v1/agent/enroll",
        json={
            "bootstrap_token": tok["bootstrap_token"],
            "hostname": "TEST-WIN-02",
            "os_family": "windows",
            "os_version": "Windows 11",
            "architecture": "x86_64",
            "agent_version": "0.1.0",
        },
    ).json()
    endpoint_id = enroll["endpoint_id"]
    token = enroll["agent_token"]

    batch = {
        "batch_id": "batch_001",
        "endpoint_id": endpoint_id,
        "sent_at": "2026-11-26T17:15:00Z",
        "events": [
            {
                "event_id": "evt_proc_1",
                "telemetry_origin": "test_fixture",
                "category": "process",
                "event_type": "process_start",
                "severity": "info",
                "occurred_at": "2026-11-26T17:14:59Z",
                "dedup_hash": "0123456789abcdef0123456789abcdef",
                "process": {
                    "process_guid": f"{endpoint_id}-100-1",
                    "parent_process_guid": f"{endpoint_id}-4-0",
                    "pid": 100,
                    "ppid": 4,
                    "name": "notepad.exe",
                    "executable_path": "C:\\Windows\\System32\\notepad.exe",
                    "command_line": "notepad.exe --token=secretvalue123",
                    "user_context": "TEST-WIN-02\\User",
                    "sha256": "a" * 64,
                    "signature_status": "valid",
                    "signer_subject": "Microsoft Windows",
                    "started_at": "2026-11-26T17:14:59Z",
                },
            }
        ],
    }
    raw = json.dumps(batch).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()

    # Corrupted SHA-256 header rejected
    bad_sig = client.post(
        "/api/v1/agent/telemetry",
        content=raw,
        headers={
            "Authorization": f"Bearer {token}",
            "X-Endpoint-ID": endpoint_id,
            "X-Payload-SHA256": "0" * 64,
            "Content-Type": "application/json",
        },
    )
    assert bad_sig.status_code == 400

    ok_res = client.post(
        "/api/v1/agent/telemetry",
        content=raw,
        headers={
            "Authorization": f"Bearer {token}",
            "X-Endpoint-ID": endpoint_id,
            "X-Payload-SHA256": digest,
            "Content-Type": "application/json",
        },
    )
    assert ok_res.status_code == 202
    assert ok_res.json()["accepted"] == 1
    assert ok_res.json()["duplicate_skipped"] == 0

    # Duplicate batch skipped cleanly
    dup_res = client.post(
        "/api/v1/agent/telemetry",
        content=raw,
        headers={
            "Authorization": f"Bearer {token}",
            "X-Endpoint-ID": endpoint_id,
            "X-Payload-SHA256": digest,
            "Content-Type": "application/json",
        },
    )
    assert dup_res.status_code == 202
    assert dup_res.json()["accepted"] == 0
    assert dup_res.json()["duplicate_skipped"] == 1

    # Verify secret redaction + persistence
    events = client.get(f"/api/v1/telemetry/events?endpoint_id={endpoint_id}").json()
    assert events["total"] == 1
    assert "secretvalue123" not in events["items"][0]["command_line"]
    assert "token=***" in events["items"][0]["command_line"]
