"""Stage 06 backend tests: WebSocket streaming, fleet overview, and ANDHAK SOC bridge."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth import create_user
from app.config import Settings, get_settings
from app.db import init_database
from app.main import app
from app.services.ingest import issue_enrollment_token
from app.soc_bridge.bridge import sign_bridge_payload, sync_with_soc

SOC_SHARED_SECRET = "test-soc-bridge-hmac-secret-stage06"


@pytest.fixture()
def ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    db_file = tmp_path / "stage06-test.sqlite3"
    monkeypatch.setenv("ANDHAK_EDR_DB_PATH", str(db_file))
    monkeypatch.setenv("ANDHAK_EDR_JWT_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("ANDHAK_DEMO_MODE", "false")
    monkeypatch.setenv("ANDHAK_SOC_ENABLED", "true")
    monkeypatch.setenv("ANDHAK_SOC_BRIDGE_SHARED_SECRET", SOC_SHARED_SECRET)
    get_settings.cache_clear()
    cfg = Settings(
        db_path=db_file,
        jwt_secret=os.environ["ANDHAK_EDR_JWT_SECRET"],
        soc_bridge_secret=SOC_SHARED_SECRET,
    )
    init_database(cfg)
    pw = f"Soc!{secrets.token_hex(8)}"
    create_user("soc_resp", "SOC Responder", "responder", pw, settings=cfg)
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "soc_resp", "password": pw})
        token = login.json()["access_token"]
        yield {"client": client, "token": token, "settings": cfg}
    get_settings.cache_clear()


def _enroll(client: TestClient, hostname: str) -> tuple[str, str]:
    boot = issue_enrollment_token(description=hostname)["bootstrap_token"]
    res = client.post(
        "/api/v1/agent/enroll",
        json={
            "bootstrap_token": boot,
            "hostname": hostname,
            "os_family": "windows",
            "os_version": "Windows 11",
            "architecture": "x86_64",
            "agent_version": "0.6.0",
        },
    )
    assert res.status_code == 201
    return res.json()["endpoint_id"], res.json()["agent_token"]


def test_websockets_fleet_overview_and_endpoint_details(ctx: dict) -> None:
    client: TestClient = ctx["client"]
    hdr = {"Authorization": f"Bearer {ctx['token']}"}
    ep_id, ag_tok = _enroll(client, "WS-SOC-HOST01")

    with (
        client.websocket_connect(f"/ws/telemetry?endpoint_id={ep_id}") as ws_tel,
        client.websocket_connect(f"/ws/alerts?endpoint_id={ep_id}") as ws_alt,
        client.websocket_connect(f"/ws/responses?endpoint_id={ep_id}") as ws_rsp,
    ):
        assert ws_tel.receive_json()["type"] == "ws.connected"
        assert ws_alt.receive_json()["type"] == "ws.connected"
        assert ws_rsp.receive_json()["type"] == "ws.connected"

        ws_tel.send_text("ping")
        assert ws_tel.receive_json()["type"] == "pong"

        batch = {
            "batch_id": "b_ws_1",
            "endpoint_id": ep_id,
            "sent_at": "2026-11-26T18:20:00Z",
            "events": [
                {
                    "event_id": "evt_ws_ps",
                    "telemetry_origin": "test_fixture",
                    "category": "process",
                    "event_type": "process_start",
                    "occurred_at": "2026-11-26T18:20:00Z",
                    "dedup_hash": hashlib.sha256(b"ws_ps").hexdigest(),
                    "process": {
                        "process_guid": f"{ep_id}-501-1",
                        "pid": 501,
                        "ppid": 100,
                        "name": "powershell.exe",
                        "executable_path": (
                            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                        ),
                        "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
                        "user_context": "CORP\\User",
                        "signature_status": "valid",
                        "started_at": "2026-11-26T18:20:00Z",
                    },
                }
            ],
        }
        raw = json.dumps(batch).encode("utf-8")
        res = client.post(
            "/api/v1/agent/telemetry",
            content=raw,
            headers={
                "Authorization": f"Bearer {ag_tok}",
                "X-Endpoint-ID": ep_id,
                "X-Payload-SHA256": hashlib.sha256(raw).hexdigest(),
                "Content-Type": "application/json",
            },
        )
        assert res.status_code == 202

        tel_msg = ws_tel.receive_json()
        assert tel_msg["type"] == "telemetry.event"
        assert tel_msg["data"]["event_id"] == "evt_ws_ps"

        alt_msg = ws_alt.receive_json()
        assert alt_msg["type"] == "alert.created"
        assert alt_msg["data"]["rule_id"] == "BEH-001"

        inc_msg = ws_alt.receive_json()
        assert inc_msg["type"] == "incident.updated"

        prop = client.post(
            "/api/v1/responses",
            headers=hdr,
            json={
                "endpoint_id": ep_id,
                "action_type": "isolate_endpoint",
                "target_value": ep_id,
                "reason": "WS response test",
            },
        )
        assert prop.status_code == 201
        rsp_msg = ws_rsp.receive_json()
        assert rsp_msg["type"] == "response.pending"
        assert rsp_msg["data"]["action_id"] == prop.json()["action_id"]

    overview = client.get("/api/v1/overview").json()
    assert overview["kpis"]["endpoints_total"] == 1
    assert overview["kpis"]["alerts_high"] >= 1
    assert overview["kpis"]["pending_approvals"] == 1

    ep_detail = client.get(f"/api/v1/endpoints/{ep_id}").json()
    assert ep_detail["endpoint"]["hostname"] == "WS-SOC-HOST01"
    assert len(ep_detail["processes"]) >= 1
    assert len(ep_detail["alerts"]) >= 1


@pytest.mark.asyncio
async def test_soc_bridge_event_contract_ioc_sync_and_hmac_responses(ctx: dict) -> None:
    client: TestClient = ctx["client"]
    cfg: Settings = ctx["settings"]
    ep_id, ag_tok = _enroll(client, "TUF-DHARM007")

    # Trigger an alert + add a local IOC
    assert (
        client.post(
            "/api/v1/intel/iocs",
            json={"value": "198.51.100.44", "severity": "critical", "description": "C2 peer"},
        ).status_code
        == 201
    )
    batch = {
        "batch_id": "b_soc_1",
        "endpoint_id": ep_id,
        "sent_at": "2026-11-26T18:22:00Z",
        "events": [
            {
                "event_id": "evt_soc_c2",
                "telemetry_origin": "test_fixture",
                "category": "network",
                "event_type": "socket_observed",
                "occurred_at": "2026-11-26T18:22:00Z",
                "dedup_hash": hashlib.sha256(b"soc_c2").hexdigest(),
                "network": {
                    "protocol": "tcp",
                    "local_addr": "10.0.0.10",
                    "local_port": 51111,
                    "remote_addr": "198.51.100.44",
                    "remote_port": 4444,
                    "state": "ESTABLISHED",
                    "pid": 888,
                    "process_name": "beacon.exe",
                },
            }
        ],
    }
    raw_b = json.dumps(batch).encode("utf-8")
    assert (
        client.post(
            "/api/v1/agent/telemetry",
            content=raw_b,
            headers={
                "Authorization": f"Bearer {ag_tok}",
                "X-Endpoint-ID": ep_id,
                "X-Payload-SHA256": hashlib.sha256(raw_b).hexdigest(),
                "Content-Type": "application/json",
            },
        ).status_code
        == 202
    )

    # Check normalized SOC event contract export
    soc_evts = client.get("/api/v1/soc-bridge/events").json()["items"]
    assert len(soc_evts) >= 1
    first = soc_evts[0]
    assert first["event_id"].startswith("edr-")
    assert first["source_system"].startswith("ANDHAK EDR · ")
    assert first["endpoint"] == "TUF-DHARM007"
    assert first["source_ip"] == "198.51.100.44"

    # Build contract-compliant mock ANDHAK SOC peer for bidirectional IOC sync
    mock_soc = FastAPI()
    soc_indicators = [
        {
            "id": 99,
            "value": "evil-c2.example",
            "kind": "domain",
            "severity": "high",
            "description": "SOC Watchlist Domain",
        }
    ]

    @mock_soc.get("/api/v1/health")
    def _soc_health() -> dict:
        return {"status": "ok", "service": "obsidian-soc-local"}

    @mock_soc.get("/api/v1/intelligence/indicators")
    def _soc_list() -> list[dict]:
        return soc_indicators

    @mock_soc.post("/api/v1/intelligence/indicators", status_code=201)
    def _soc_add(item: dict) -> dict:
        soc_indicators.append({"id": len(soc_indicators) + 100, **item})
        return item

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_soc),
        base_url="http://127.0.0.1:8000",
    ) as peer:
        sync_res = await sync_with_soc(settings=cfg, http_client=peer)

    assert sync_res["soc_reachable"] is True
    assert sync_res["iocs_pulled"] == 1
    assert sync_res["iocs_pushed"] == 1
    assert any(i["value"] == "198.51.100.44" for i in soc_indicators)
    edr_iocs = client.get("/api/v1/intel/iocs").json()["items"]
    assert any(i["value"] == "evil-c2.example" and i["source"] == "soc_watchlist" for i in edr_iocs)

    # Test HMAC-signed SOC -> EDR containment proposal (rejects invalid HMAC, enforces safety)
    ts = str(int(time.time()))
    req_body = json.dumps(
        {
            "soc_approval_id": "appr_soc_001",
            "action_type": "isolate_endpoint",
            "endpoint_hostname": "TUF-DHARM007",
            "target_value": "TUF-DHARM007",
            "reason": "Escalated from ANDHAK SOC",
            "soc_actor": "soc_lead",
        }
    ).encode("utf-8")

    # Bad signature -> 401
    assert (
        client.post(
            "/api/v1/soc-bridge/responses/request",
            content=req_body,
            headers={
                "X-ANDHAK-Timestamp": ts,
                "X-ANDHAK-Signature": "deadbeef",
                "Content-Type": "application/json",
            },
        ).status_code
        == 401
    )

    sig = sign_bridge_payload(SOC_SHARED_SECRET, ts, req_body)
    ok_res = client.post(
        "/api/v1/soc-bridge/responses/request",
        content=req_body,
        headers={
            "X-ANDHAK-Timestamp": ts,
            "X-ANDHAK-Signature": sig,
            "Content-Type": "application/json",
        },
    )
    assert ok_res.status_code == 202
    assert ok_res.json()["bridge_status"] == "queued_for_edr_approval"
    assert ok_res.json()["action"]["status"] == "pending_approval"
    assert ok_res.json()["action"]["soc_approval_id"] == "appr_soc_001"

    # Unsupported revoke_session returns 501 honestly
    rev_body = json.dumps(
        {"action_type": "revoke_session", "endpoint_hostname": "TUF-DHARM007"}
    ).encode()
    rev_sig = sign_bridge_payload(SOC_SHARED_SECRET, ts, rev_body)
    assert (
        client.post(
            "/api/v1/soc-bridge/responses/request",
            content=rev_body,
            headers={
                "X-ANDHAK-Timestamp": ts,
                "X-ANDHAK-Signature": rev_sig,
                "Content-Type": "application/json",
            },
        ).status_code
        == 501
    )

    status_res = client.get("/api/v1/soc-bridge/status").json()
    assert len(status_res["recent_sync_logs"]) >= 3
