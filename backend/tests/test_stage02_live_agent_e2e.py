"""Stage 02 End-to-End Integration Test: compiled Rust agent -> HTTPS TLS FastAPI backend."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import time
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_BIN_DEBUG = REPO_ROOT / "agent" / "target" / "debug" / "andhak-edr-agent.exe"
AGENT_BIN_RELEASE = REPO_ROOT / "agent" / "target" / "release" / "andhak-edr-agent.exe"
BACKEND_PY = REPO_ROOT / "backend" / ".venv" / "Scripts" / "python.exe"


def _agent_binary() -> Path:
    if AGENT_BIN_RELEASE.is_file():
        return AGENT_BIN_RELEASE
    if AGENT_BIN_DEBUG.is_file():
        return AGENT_BIN_DEBUG
    pytest.skip("andhak-edr-agent.exe not built yet")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _generate_tls_ca_and_leaf(cert_dir: Path) -> tuple[Path, Path, Path]:
    now = dt.datetime.now(dt.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ANDHAK EDR Test Root CA")])
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
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
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
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = cert_dir / "ca.crt"
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
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


def _run_agent(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    assert proc.returncode == 0, f"cmd={args}\nstdout={proc.stdout}\nstderr={proc.stderr}"
    return proc


def test_compiled_rust_agent_collects_and_uploads_over_https(tmp_path: Path) -> None:
    agent_exe = _agent_binary()
    ca_path, cert_path, key_path = _generate_tls_ca_and_leaf(tmp_path)
    ssl_ctx = ssl.create_default_context(cafile=str(ca_path))

    db_file = tmp_path / "live-e2e.sqlite3"
    watch_dir = tmp_path / "watched"
    watch_dir.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    base_url = f"https://127.0.0.1:{port}"

    env = os.environ.copy()
    env["ANDHAK_EDR_DB_PATH"] = str(db_file)
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

    runner: subprocess.Popen[str] | None = None
    try:
        deadline = time.monotonic() + 15.0
        with httpx.Client(verify=ssl_ctx, timeout=2.0) as client:
            while time.monotonic() < deadline:
                try:
                    r = client.get(f"{base_url}/api/v1/health")
                    if r.status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("TLS backend failed to start")

            tok_res = client.post(
                f"{base_url}/api/v1/agent/enrollment-tokens",
                json={"description": "rust-live-e2e"},
            )
            assert tok_res.status_code == 201
            bootstrap_token = tok_res.json()["bootstrap_token"]

        state_file = tmp_path / "agent-state.json"
        spool_file = tmp_path / "agent-spool.sqlite3"
        agent_cfg = tmp_path / "agent.toml"
        agent_cfg.write_text(
            "\n".join(
                [
                    f"backend_url = {json.dumps(base_url)}",
                    f"ca_cert_path = {json.dumps(str(ca_path))}",
                    f"state_file = {json.dumps(str(state_file))}",
                    f"spool_db_path = {json.dumps(str(spool_file))}",
                    f"watch_paths = [{json.dumps(str(watch_dir))}]",
                    'exclusions = ["*.tmp"]',
                    "heartbeat_seconds = 2",
                    "process_poll_ms = 1000",
                    "network_poll_ms = 2000",
                    "flush_interval_ms = 300",
                    "batch_max_events = 100",
                ]
            ),
            encoding="utf-8",
        )

        # 1. Status check before enrollment
        status_proc = _run_agent([str(agent_exe), "status", "--config", str(agent_cfg)])
        status_data = json.loads(status_proc.stdout)
        assert status_data["enrolled"] is False
        assert status_data["host"]["os_family"] == "windows"

        # 2. Enroll over HTTPS with custom root CA verification
        enroll_proc = _run_agent(
            [str(agent_exe), "enroll", "--config", str(agent_cfg), "--token", bootstrap_token]
        )
        enroll_data = json.loads(enroll_proc.stdout)
        assert enroll_data["enrolled"] is True
        endpoint_id = enroll_data["endpoint_id"]
        assert state_file.is_file()

        # 3. Real collect-once sweep + upload over HTTPS
        collect_proc = _run_agent([str(agent_exe), "collect-once", "--config", str(agent_cfg)])
        collect_data = json.loads(collect_proc.stdout)
        assert collect_data["collected_events"] > 10
        assert collect_data["uploaded"] > 10
        assert collect_data["remaining_spool_depth"] == 0

        # 4. Run live watcher + heartbeat, wait until sensor loop starts, then trigger FS activity
        runner = subprocess.Popen(
            [str(agent_exe), "run", "--config", str(agent_cfg)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert runner.stderr is not None
        ready_deadline = time.monotonic() + 20.0
        seen_stderr: list[str] = []
        while time.monotonic() < ready_deadline:
            line = runner.stderr.readline()
            if line:
                seen_stderr.append(line)
            if "sensor loop started" in line:
                break
        else:
            raise RuntimeError(
                f"Agent runner did not signal sensor loop startup: {''.join(seen_stderr)}"
            )

        probe_file = watch_dir / "stage02-probe.exe"
        probe_file.write_bytes(b"MZ-stage02-harmless-probe")

        fs_events: dict = {"total": 0, "items": []}
        poll_deadline = time.monotonic() + 12.0
        with httpx.Client(verify=ssl_ctx, timeout=5.0) as client:
            while time.monotonic() < poll_deadline:
                fs_events = client.get(
                    f"{base_url}/api/v1/telemetry/events"
                    f"?endpoint_id={endpoint_id}&category=filesystem&limit=50"
                ).json()
                if fs_events["total"] > 0:
                    break
                time.sleep(0.4)

            runner.terminate()
            runner.wait(timeout=10)
            runner = None

            ep_res = client.get(f"{base_url}/api/v1/endpoints").json()
            assert ep_res["total"] == 1
            assert ep_res["items"][0]["endpoint_id"] == endpoint_id

            proc_events = client.get(
                f"{base_url}/api/v1/telemetry/events?endpoint_id={endpoint_id}&category=process&limit=500"
            ).json()
            net_events = client.get(
                f"{base_url}/api/v1/telemetry/events?endpoint_id={endpoint_id}&category=network&limit=500"
            ).json()
            sys_events = client.get(
                f"{base_url}/api/v1/telemetry/events?endpoint_id={endpoint_id}&category=system&limit=50"
            ).json()

            assert proc_events["total"] > 0
            assert net_events["total"] > 0
            assert sys_events["total"] > 0
            assert fs_events["total"] > 0
            assert any(
                "stage02-probe.exe" in (item.get("file_path") or "") for item in fs_events["items"]
            )
    finally:
        if runner is not None:
            runner.terminate()
            runner.wait(timeout=5)
        server.terminate()
        server.wait(timeout=5)
