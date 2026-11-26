"""Stage 05 tests: RBAC, protected target denylist, approvals, quarantine, isolation, & audit."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.auth import create_user
from app.config import Settings, get_settings
from app.db import get_connection, init_database
from app.main import app
from app.response.audit import verify_audit_chain
from app.services.ingest import issue_enrollment_token

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_BIN_RELEASE = REPO_ROOT / "agent" / "target" / "release" / "andhak-edr-agent.exe"
AGENT_BIN_DEBUG = REPO_ROOT / "agent" / "target" / "debug" / "andhak-edr-agent.exe"
BACKEND_PY = REPO_ROOT / "backend" / ".venv" / "Scripts" / "python.exe"


def _agent_binary() -> Path:
    if AGENT_BIN_RELEASE.is_file():
        return AGENT_BIN_RELEASE
    if AGENT_BIN_DEBUG.is_file():
        return AGENT_BIN_DEBUG
    pytest.skip("andhak-edr-agent.exe not built yet")


@pytest.fixture()
def ctx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    db_file = tmp_path / "stage05-test.sqlite3"
    monkeypatch.setenv("ANDHAK_EDR_DB_PATH", str(db_file))
    monkeypatch.setenv("ANDHAK_EDR_JWT_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("ANDHAK_DEMO_MODE", "false")
    get_settings.cache_clear()
    cfg = Settings(db_path=db_file, jwt_secret=os.environ["ANDHAK_EDR_JWT_SECRET"])
    init_database(cfg)

    pw = f"Pw!{secrets.token_hex(8)}"
    create_user("alice_admin", "Alice Admin", "admin", pw, settings=cfg)
    create_user("bob_resp", "Bob Responder", "responder", pw, settings=cfg)
    create_user("carol_ana", "Carol Analyst", "analyst", pw, settings=cfg)
    create_user("dave_demo", "Dave Demo", "readonly_demo", pw, settings=cfg)

    with TestClient(app) as client:
        tokens = {}
        for uname in ("alice_admin", "bob_resp", "carol_ana", "dave_demo"):
            r = client.post("/api/v1/auth/login", json={"username": uname, "password": pw})
            assert r.status_code == 200, r.text
            tokens[uname] = r.json()["access_token"]
        yield {
            "client": client,
            "tokens": tokens,
            "password": pw,
            "monkeypatch": monkeypatch,
            "settings": cfg,
        }
    get_settings.cache_clear()


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _enroll(client: TestClient, hostname: str = "RESP-WS01") -> tuple[str, str]:
    tok = issue_enrollment_token(description=hostname)["bootstrap_token"]
    res = client.post(
        "/api/v1/agent/enroll",
        json={
            "bootstrap_token": tok,
            "hostname": hostname,
            "os_family": "windows",
            "os_version": "Windows 11",
            "architecture": "x86_64",
            "agent_version": "0.5.0",
        },
    )
    assert res.status_code == 201
    data = res.json()
    return data["endpoint_id"], data["agent_token"]


def test_rbac_protected_targets_approval_flow_and_audit_chain(ctx: dict) -> None:
    client: TestClient = ctx["client"]
    tok = ctx["tokens"]
    mp: pytest.MonkeyPatch = ctx["monkeypatch"]

    # Unauthenticated request rejected with 401
    assert client.get("/api/v1/responses").status_code == 401
    assert client.get("/api/v1/auth/me", headers=_hdr(tok["carol_ana"])).status_code == 200

    # Bad password rejected with 401
    assert (
        client.post(
            "/api/v1/auth/login",
            json={"username": "alice_admin", "password": "wrong-password-123"},
        ).status_code
        == 401
    )

    # RBAC privilege boundaries
    assert client.get("/api/v1/users", headers=_hdr(tok["bob_resp"])).status_code == 403
    assert client.get("/api/v1/users", headers=_hdr(tok["alice_admin"])).status_code == 200
    assert (
        client.put(
            "/api/v1/policies",
            headers=_hdr(tok["bob_resp"]),
            json={"heartbeat_seconds": 30},
        ).status_code
        == 403
    )

    # Admin policy & retention update bumps version cleanly
    pol_res = client.put(
        "/api/v1/policies",
        headers=_hdr(tok["alice_admin"]),
        json={"heartbeat_seconds": 30, "retention_days": {"telemetry": 45}},
    )
    assert pol_res.status_code == 200
    assert pol_res.json()["policy"]["version"] == 2
    assert pol_res.json()["retention"]["telemetry"] == 45

    # Enroll endpoint & record lsass.exe telemetry so DB cross-check catches raw PID requests too
    ep_id, agent_token = _enroll(client, "DENYLIST-WS01")
    batch = {
        "batch_id": "b_resp_1",
        "endpoint_id": ep_id,
        "sent_at": "2026-11-26T18:10:00Z",
        "events": [
            {
                "event_id": "evt_lsass_rec",
                "telemetry_origin": "test_fixture",
                "category": "process",
                "event_type": "process_start",
                "occurred_at": "2026-11-26T18:10:00Z",
                "dedup_hash": hashlib.sha256(b"lsass_rec").hexdigest(),
                "process": {
                    "process_guid": f"{ep_id}-912-1",
                    "pid": 912,
                    "ppid": 500,
                    "name": "lsass.exe",
                    "executable_path": "C:\\Windows\\System32\\lsass.exe",
                    "command_line": "C:\\Windows\\System32\\lsass.exe",
                    "user_context": "NT AUTHORITY\\SYSTEM",
                    "signature_status": "valid",
                    "started_at": "2026-11-26T18:10:00Z",
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
                "Authorization": f"Bearer {agent_token}",
                "X-Endpoint-ID": ep_id,
                "X-Payload-SHA256": hashlib.sha256(raw_b).hexdigest(),
                "Content-Type": "application/json",
            },
        ).status_code
        == 202
    )

    # Protected Target Denylist checks (422 PROTECTED_TARGET_BLOCKED)
    protected_cases = [
        ("terminate_process", "4", {}),
        ("terminate_process", "912", {}),  # Caught via recorded telemetry PID->lsass.exe lookup
        ("terminate_process", "4242", {"process_name": "csrss.exe"}),
        ("terminate_process", "5555", {"is_edr_agent": True}),
        ("quarantine_file", "C:\\Windows\\System32\\kernel32.dll", {}),
        ("quarantine_file", "C:\\Temp\\..\\Windows\\System32\\cmd.exe", {}),
        ("quarantine_file", "C:\\ProgramData\\AndhakEDR\\andhak-edr-agent.exe", {}),
        ("block_network_indicator", "127.0.0.1", {}),
        ("block_network_indicator", "localhost", {}),
    ]
    for action_type, target_val, meta in protected_cases:
        res = client.post(
            "/api/v1/responses",
            headers=_hdr(tok["carol_ana"]),
            json={
                "endpoint_id": ep_id,
                "action_type": action_type,
                "target_value": target_val,
                "target_metadata": meta,
                "reason": "Safety test",
            },
        )
        assert res.status_code == 422, f"{action_type} {target_val}: {res.text}"
        assert res.json()["error"]["code"] == "PROTECTED_TARGET_BLOCKED"

    # readonly_demo cannot even propose
    assert (
        client.post(
            "/api/v1/responses",
            headers=_hdr(tok["dave_demo"]),
            json={
                "endpoint_id": ep_id,
                "action_type": "isolate_endpoint",
                "target_value": ep_id,
                "reason": "Demo violation",
            },
        ).status_code
        == 403
    )

    # Analyst proposes isolation -> status = pending_approval
    prop = client.post(
        "/api/v1/responses",
        headers=_hdr(tok["carol_ana"]),
        json={
            "endpoint_id": ep_id,
            "action_type": "isolate_endpoint",
            "target_value": ep_id,
            "reason": "C2 beaconing containment",
        },
    )
    assert prop.status_code == 201
    action_id = prop.json()["action_id"]
    assert prop.json()["status"] == "pending_approval"

    # Analyst CANNOT approve own/any action -> 403
    assert (
        client.post(
            f"/api/v1/responses/{action_id}/decision",
            headers=_hdr(tok["carol_ana"]),
            json={"decision": "approve", "note": "Self approve attempt"},
        ).status_code
        == 403
    )

    # Responder approves action -> pending_commands appears on next agent heartbeat
    dec = client.post(
        f"/api/v1/responses/{action_id}/decision",
        headers=_hdr(tok["bob_resp"]),
        json={"decision": "approve", "note": "Verified C2 evidence"},
    )
    assert dec.status_code == 200
    assert dec.json()["status"] == "approved"

    # Double decision -> 409 Conflict
    assert (
        client.post(
            f"/api/v1/responses/{action_id}/decision",
            headers=_hdr(tok["bob_resp"]),
            json={"decision": "reject", "note": "Too late"},
        ).status_code
        == 409
    )

    hb = client.post(
        "/api/v1/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent_token}", "X-Endpoint-ID": ep_id},
        json={
            "endpoint_id": ep_id,
            "agent_version": "0.5.0",
            "uptime_seconds": 30,
            "cpu_percent": 10.0,
            "memory_used_mb": 2048,
            "memory_total_mb": 8192,
            "disk_used_percent": 50.0,
            "agent_rss_mb": 14.0,
            "spool_queue_depth": 0,
            "policy_version": 2,
            "sensors": {
                "process": "ready",
                "network": "ready",
                "filesystem": "ready",
                "system": "ready",
                "sysmon": "unavailable",
            },
        },
    )
    assert hb.status_code == 200
    cmds = hb.json()["pending_commands"]
    assert len(cmds) == 1 and cmds[0]["action_id"] == action_id

    # Agent acknowledges isolation execution -> endpoint isolated
    ack = client.post(
        f"/api/v1/agent/commands/{action_id}/ack",
        headers={"Authorization": f"Bearer {agent_token}", "X-Endpoint-ID": ep_id},
        json={
            "success": True,
            "verification": {"mode": "dry_run_unprivileged", "isolated": True},
        },
    )
    assert ack.status_code == 200
    assert ack.json()["status"] == "executed"

    # Rollback isolation -> release_isolation queued & acknowledged -> original becomes rolled_back
    rb = client.post(
        f"/api/v1/responses/{action_id}/rollback",
        headers=_hdr(tok["bob_resp"]),
        json={"reason": "Threat neutralized"},
    )
    assert rb.status_code == 201
    rb_id = rb.json()["action_id"]
    assert rb.json()["action_type"] == "release_isolation"
    assert (
        client.post(
            f"/api/v1/agent/commands/{rb_id}/ack",
            headers={"Authorization": f"Bearer {agent_token}", "X-Endpoint-ID": ep_id},
            json={"success": True, "verification": {"isolated": False}},
        ).status_code
        == 200
    )

    actions = client.get(
        "/api/v1/responses",
        headers=_hdr(tok["carol_ana"]),
        params={"endpoint_id": ep_id},
    ).json()["items"]
    by_id = {a["action_id"]: a for a in actions}
    assert by_id[action_id]["status"] == "rolled_back"
    assert by_id[rb_id]["status"] == "executed"

    # Public demo mode strictly blocks mutations even with an admin JWT
    mp.setenv("ANDHAK_DEMO_MODE", "true")
    get_settings.cache_clear()
    assert client.get("/api/v1/responses", headers=_hdr(tok["alice_admin"])).status_code == 200
    assert (
        client.post(
            "/api/v1/responses",
            headers=_hdr(tok["alice_admin"]),
            json={
                "endpoint_id": ep_id,
                "action_type": "isolate_endpoint",
                "target_value": ep_id,
                "reason": "Blocked in demo mode",
            },
        ).status_code
        == 403
    )
    mp.setenv("ANDHAK_DEMO_MODE", "false")
    get_settings.cache_clear()

    # Audit hash chain integrity verification + tamper detection
    audit_res = client.get("/api/v1/audit", headers=_hdr(tok["alice_admin"])).json()
    assert audit_res["chain_verification"]["valid"] is True
    assert audit_res["total"] >= 8

    with get_connection() as conn:
        conn.execute("UPDATE audit_logs SET actor_id = 'tampered_user' WHERE seq = 1")
    assert verify_audit_chain()["valid"] is False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _generate_tls(cert_dir: Path) -> tuple[Path, Path, Path]:
    now = dt.datetime.now(dt.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ANDHAK Stage05 Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = cert_dir / "ca.crt"
    cert_path = cert_dir / "srv.crt"
    key_path = cert_dir / "srv.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


def test_live_compiled_agent_quarantine_restore_and_process_kill(tmp_path: Path) -> None:
    agent_exe = _agent_binary()
    ca_path, cert_path, key_path = _generate_tls(tmp_path)
    ssl_ctx = ssl.create_default_context(cafile=str(ca_path))

    db_file = tmp_path / "stage05-e2e.sqlite3"
    port = _free_port()
    base_url = f"https://127.0.0.1:{port}"
    jwt_secret = secrets.token_urlsafe(48)
    admin_pw = f"Adm!{secrets.token_hex(8)}"

    env = os.environ.copy()
    env["ANDHAK_EDR_DB_PATH"] = str(db_file)
    env["ANDHAK_EDR_JWT_SECRET"] = jwt_secret
    env["ANDHAK_EDR_BOOTSTRAP_ADMIN_USER"] = "soc_admin"
    env["ANDHAK_EDR_BOOTSTRAP_ADMIN_PASSWORD"] = admin_pw
    env["PYTHONPATH"] = str(REPO_ROOT / "backend")

    server = subprocess.Popen(
        [
            str(BACKEND_PY),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--ssl-certfile",
            str(cert_path),
            "--ssl-keyfile",
            str(key_path),
        ],
        cwd=str(REPO_ROOT / "backend"),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    dummy_proc: subprocess.Popen[str] | None = None
    try:
        with httpx.Client(verify=ssl_ctx, timeout=3.0) as client:
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                try:
                    if client.get(f"{base_url}/api/v1/health").status_code == 200:
                        break
                except httpx.RequestError:
                    time.sleep(0.2)
            else:
                pytest.fail("HTTPS server failed to start for Stage 05 E2E")

            login = client.post(
                f"{base_url}/api/v1/auth/login",
                json={"username": "soc_admin", "password": admin_pw},
            )
            assert login.status_code == 200
            hdr = {"Authorization": f"Bearer {login.json()['access_token']}"}

            boot = client.post(
                f"{base_url}/api/v1/agent/enrollment-tokens",
                json={"description": "Stage 05 live agent"},
            ).json()["bootstrap_token"]

            staging_dir = tmp_path / "Temp"
            staging_dir.mkdir()
            suspect_file = staging_dir / "drop_sample.bin"
            original_bytes = b"ANDHAK_E2E_QUARANTINE_ROUNDTRIP_PAYLOAD_BYTES"
            suspect_file.write_bytes(original_bytes)
            orig_sha = hashlib.sha256(original_bytes).hexdigest()

            vault_dir = tmp_path / "vault"
            cfg_file = tmp_path / "agent.toml"
            cfg_file.write_text(
                "\n".join(
                    [
                        f'backend_url = "{base_url}"',
                        f'ca_cert_path = "{ca_path.as_posix()}"',
                        f'state_file = "{(tmp_path / "state.json").as_posix()}"',
                        f'spool_db_path = "{(tmp_path / "spool.sqlite3").as_posix()}"',
                        f'quarantine_dir = "{vault_dir.as_posix()}"',
                        f'watch_paths = ["{staging_dir.as_posix()}"]',
                    ]
                ),
                encoding="utf-8",
            )

            enroll_proc = subprocess.run(
                [str(agent_exe), "--config", str(cfg_file), "enroll", "--token", boot],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            assert enroll_proc.returncode == 0, enroll_proc.stderr
            ep_id = json.loads(enroll_proc.stdout)["endpoint_id"]

            # 1. Live Quarantine via approved command -> compiled Rust agent
            q_prop = client.post(
                f"{base_url}/api/v1/responses",
                headers=hdr,
                json={
                    "endpoint_id": ep_id,
                    "action_type": "quarantine_file",
                    "target_value": str(suspect_file),
                    "reason": "Quarantine staged payload",
                },
            ).json()
            assert (
                client.post(
                    f"{base_url}/api/v1/responses/{q_prop['action_id']}/decision",
                    headers=hdr,
                    json={"decision": "approve", "note": "Confirmed unauthorized drop"},
                ).status_code
                == 200
            )

            poll1 = subprocess.run(
                [str(agent_exe), "--config", str(cfg_file), "poll-commands-once"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            assert poll1.returncode == 0, poll1.stderr
            assert json.loads(poll1.stdout)["commands_acknowledged"] == 1
            assert not suspect_file.exists()

            q_items = client.get(f"{base_url}/api/v1/quarantine", headers=hdr).json()["items"]
            assert len(q_items) == 1
            assert q_items[0]["sha256_before"] == orig_sha
            assert q_items[0]["status"] == "quarantined"

            # 2. Controlled Rollback -> Rust agent restores exact file bytes & SHA-256
            assert (
                client.post(
                    f"{base_url}/api/v1/responses/{q_prop['action_id']}/rollback",
                    headers=hdr,
                    json={"reason": "Analyst restoration test"},
                ).status_code
                == 201
            )
            poll2 = subprocess.run(
                [str(agent_exe), "--config", str(cfg_file), "poll-commands-once"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            assert poll2.returncode == 0, poll2.stderr
            assert suspect_file.exists()
            assert suspect_file.read_bytes() == original_bytes
            q_after = client.get(f"{base_url}/api/v1/quarantine", headers=hdr).json()["items"]
            assert q_after[0]["status"] == "restored"

            # 3. Live Controlled Process Termination against harmless test child process
            dummy_proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            kill_prop = client.post(
                f"{base_url}/api/v1/responses",
                headers=hdr,
                json={
                    "endpoint_id": ep_id,
                    "action_type": "terminate_process",
                    "target_value": str(dummy_proc.pid),
                    "target_metadata": {"process_name": "python.exe"},
                    "reason": "Controlled test child process termination",
                },
            ).json()
            assert (
                client.post(
                    f"{base_url}/api/v1/responses/{kill_prop['action_id']}/decision",
                    headers=hdr,
                    json={"decision": "approve", "note": "Approved benign fixture kill"},
                ).status_code
                == 200
            )
            poll3 = subprocess.run(
                [str(agent_exe), "--config", str(cfg_file), "poll-commands-once"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            assert poll3.returncode == 0, poll3.stderr
            assert dummy_proc.wait(timeout=5) is not None

            audit = client.get(f"{base_url}/api/v1/audit", headers=hdr).json()
            assert audit["chain_verification"]["valid"] is True
    finally:
        if dummy_proc is not None and dummy_proc.poll() is None:
            dummy_proc.kill()
        server.terminate()
        server.wait(timeout=5)
