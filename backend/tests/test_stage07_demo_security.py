"""Stage 07 tests: public read-only demo mode, mutation lockdown, and secret hygiene."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import create_user
from app.config import Settings, get_settings
from app.db import init_database
from app.demo.replay import seed_demo_scenario
from app.main import app
from app.services.ingest import issue_enrollment_token


@pytest.fixture()
def demo_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    db_file = tmp_path / "stage07-demo.sqlite3"
    monkeypatch.setenv("ANDHAK_EDR_DB_PATH", str(db_file))
    monkeypatch.setenv("ANDHAK_EDR_JWT_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("ANDHAK_DEMO_MODE", "true")
    get_settings.cache_clear()
    cfg = Settings(
        db_path=db_file,
        jwt_secret=os.environ["ANDHAK_EDR_JWT_SECRET"],
        demo_mode=True,
    )
    init_database(cfg)
    pw = f"DemoAdm!{secrets.token_hex(8)}"
    create_user("demo_adm", "Demo Admin", "admin", pw, settings=cfg)
    seed_demo_scenario("staged-office-powershell-c2", settings=cfg)

    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "demo_adm", "password": pw})
        token = login.json()["access_token"]
        yield {"client": client, "token": token}
    get_settings.cache_clear()


def test_public_demo_mode_serves_recorded_data_and_blocks_all_mutations(demo_client: dict) -> None:
    client: TestClient = demo_client["client"]
    hdr = {"Authorization": f"Bearer {demo_client['token']}"}

    # Public read-only demo endpoints succeed cleanly
    health = client.get("/api/v1/health").json()
    assert health["mode"] == "demo"

    scenarios = client.get("/api/v1/demo/scenarios").json()
    assert scenarios["demo_mode"] is True
    assert scenarios["total"] == 2

    overview = client.get("/api/v1/overview").json()
    assert overview["mode"] == "demo"
    assert overview["kpis"]["endpoints_total"] >= 1
    assert "recorded_demo" in overview["telemetry_origins"]
    assert overview["kpis"]["incidents_open"] >= 1

    # Unauthenticated GET in demo mode downgrades safely to readonly_demo & reads seeded demo data
    assert client.get("/api/v1/responses").status_code == 200
    assert client.get("/api/v1/audit").status_code == 200
    assert client.get("/api/v1/incidents").json()["total"] >= 1

    # ALL mutation routes hard-block with 403 Forbidden even when sending an admin JWT
    assert (
        client.post(
            "/api/v1/agent/enrollment-tokens",
            headers=hdr,
            json={"description": "blocked"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/intel/iocs",
            headers=hdr,
            json={"value": "198.51.100.1", "severity": "high"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/responses",
            headers=hdr,
            json={
                "endpoint_id": "ep_demo_ws_finance_04",
                "action_type": "isolate_endpoint",
                "target_value": "ep_demo_ws_finance_04",
                "reason": "Blocked demo mutation",
            },
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/api/v1/policies",
            headers=hdr,
            json={"heartbeat_seconds": 30},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/soc-bridge/sync",
            headers=hdr,
        ).status_code
        == 403
    )

    # Replay route resets/replays recorded demo events cleanly without error
    replay = client.post("/api/v1/demo/replay/staged-office-powershell-c2")
    assert replay.status_code == 200
    assert replay.json()["origin"] == "recorded_demo"


def test_secret_redaction_on_telemetry_ingestion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "stage07-redact.sqlite3"
    monkeypatch.setenv("ANDHAK_EDR_DB_PATH", str(db_file))
    monkeypatch.setenv("ANDHAK_DEMO_MODE", "false")
    get_settings.cache_clear()
    init_database(Settings(db_path=db_file))

    with TestClient(app) as client:
        boot = issue_enrollment_token("Redaction host")["bootstrap_token"]
        ep = client.post(
            "/api/v1/agent/enroll",
            json={
                "bootstrap_token": boot,
                "hostname": "REDACT-WS01",
                "os_family": "windows",
                "os_version": "Windows 11",
                "architecture": "x86_64",
                "agent_version": "0.7.0",
            },
        ).json()
        batch = {
            "batch_id": "b_red_1",
            "endpoint_id": ep["endpoint_id"],
            "sent_at": "2026-11-26T18:30:00Z",
            "events": [
                {
                    "event_id": "evt_red_01",
                    "telemetry_origin": "test_fixture",
                    "category": "process",
                    "event_type": "process_start",
                    "occurred_at": "2026-11-26T18:30:00Z",
                    "dedup_hash": hashlib.sha256(b"red_01").hexdigest(),
                    "process": {
                        "process_guid": f"{ep['endpoint_id']}-700-1",
                        "pid": 700,
                        "ppid": 4,
                        "name": "curl.exe",
                        "executable_path": "C:\\Windows\\System32\\curl.exe",
                        "command_line": (
                            "curl.exe -H 'Authorization: Bearer TopSecretTokenValue123456' "
                            "--password=MyPassword99 https://example.com"
                        ),
                        "user_context": "LAB\\User",
                        "signature_status": "valid",
                        "started_at": "2026-11-26T18:30:00Z",
                    },
                }
            ],
        }
        raw = json.dumps(batch).encode("utf-8")
        res = client.post(
            "/api/v1/agent/telemetry",
            content=raw,
            headers={
                "Authorization": f"Bearer {ep['agent_token']}",
                "X-Endpoint-ID": ep["endpoint_id"],
                "X-Payload-SHA256": hashlib.sha256(raw).hexdigest(),
                "Content-Type": "application/json",
            },
        )
        assert res.status_code == 202

        stored = client.get(
            "/api/v1/hunting/search", params={"endpoint_id": ep["endpoint_id"]}
        ).json()["items"][0]
        assert "TopSecretTokenValue123456" not in stored["command_line"]
        assert "MyPassword99" not in stored["command_line"]
        assert "Bearer ***" in stored["command_line"]
        assert "password=***" in stored["command_line"]
    get_settings.cache_clear()
