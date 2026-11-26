"""Stage 03 tests: YARA-X, EMBER PE scoring, FIM, 8 behavioral rules, IOC intel, and scoring."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.db import init_database
from app.detection.ember_classifier import classify_pe_bytes, extract_ember_features
from app.detection.scoring import compute_risk_score
from app.detection.yara_scanner import scan_bytes_yara, validate_rule_source
from app.main import app
from app.services.ingest import issue_enrollment_token

EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _build_minimal_pe(
    extra_section_bytes: bytes = b"hello",
    rwx: bool = False,
    add_injection_strings: bool = False,
) -> bytes:
    """Construct a minimal syntactically valid Windows PE32+ binary fixture for tests."""
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew = 0x80

    pe_sig = b"PE\x00\x00"
    # COFF Header: Machine=AMD64(0x8664), NumberOfSections=1, SizeOfOptionalHeader=0xF0
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x67452301, 0, 0, 0xF0, 0x0022)

    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x020B)  # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt, 56, 0x3000)  # SizeOfImage
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)  # Subsystem = CUI
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes

    raw_payload = bytearray(extra_section_bytes)
    if add_injection_strings:
        raw_payload += b"\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    while len(raw_payload) < 0x200 or len(raw_payload) % 0x200 != 0:
        raw_payload.append(0)

    characteristics = 0xE0000020 if rwx else 0x60000020
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(raw_payload),
        0x1000,
        len(raw_payload),
        0x200,
        0,
        0,
        0,
        0,
        characteristics,
    )
    headers = bytes(dos_header) + pe_sig + coff + bytes(opt) + sec_hdr
    headers = headers.ljust(0x200, b"\x00")
    return headers + bytes(raw_payload)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    db_file = tmp_path / "stage03-test.sqlite3"
    monkeypatch.setenv("ANDHAK_EDR_DB_PATH", str(db_file))
    monkeypatch.setenv("ANDHAK_INTEL_EXTERNAL_ENABLED", "false")
    get_settings.cache_clear()
    init_database(Settings(db_path=db_file))
    with TestClient(app) as tc:
        yield tc
    get_settings.cache_clear()


def _enroll(client: TestClient, hostname: str = "LAB-HOST") -> tuple[str, str]:
    tok = issue_enrollment_token(description=hostname)["bootstrap_token"]
    res = client.post(
        "/api/v1/agent/enroll",
        json={
            "bootstrap_token": tok,
            "hostname": hostname,
            "os_family": "windows",
            "os_version": "Windows 11",
            "architecture": "x86_64",
            "agent_version": "0.2.0",
        },
    )
    assert res.status_code == 201
    data = res.json()
    return data["endpoint_id"], data["agent_token"]


def _post_events(client: TestClient, endpoint_id: str, token: str, events: list[dict]) -> dict:
    batch = {
        "batch_id": f"b_{hashlib.sha256(json.dumps(events).encode()).hexdigest()[:12]}",
        "endpoint_id": endpoint_id,
        "sent_at": "2026-11-26T17:30:00Z",
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


def test_yara_validation_and_harmless_test_signatures(client: TestClient) -> None:
    ok, err = validate_rule_source('rule valid_test { strings: $a = "abc" condition: $a }')
    assert ok and err is None

    bad_ok, bad_err = validate_rule_source("rule broken_test { condition: unknown_var }")
    assert not bad_ok and bad_err

    eicar = scan_bytes_yara("eicar.txt", EICAR_BYTES)
    assert eicar["detected"] is True
    assert eicar["matches"][0]["rule_id"] == "ANDHAK_EICAR_Test_String"
    assert eicar["matches"][0]["severity"] == "info"

    ep_id, _ = _enroll(client, "YARA-HOST")
    scan_res = client.post(
        "/api/v1/malware/scan",
        json={
            "file_name": "dropper_test.ps1",
            "content_base64": base64.b64encode(
                b"powershell.exe -EncodedCommand SQBuAHYAbwBrAGUA"
            ).decode("ascii"),
            "endpoint_id": ep_id,
            "telemetry_origin": "test_fixture",
        },
    )
    assert scan_res.status_code == 200
    body = scan_res.json()
    assert body["verdict"] == "malicious"
    assert any(
        m["rule_id"] == "ANDHAK_PowerShell_Encoded_Execution" for m in body["yara"]["matches"]
    )
    assert len(body["alerts_created"]) >= 1


def test_ember_static_pe_feature_extraction_and_provenance(client: TestClient) -> None:
    non_pe = classify_pe_bytes("readme.txt", b"plain text content")
    assert non_pe["is_pe"] is False
    assert non_pe["ember_score"] is None

    # High-entropy + RWX section PE fixture
    high_ent_bytes = bytes(os.urandom(4096))
    suspicious_pe = _build_minimal_pe(
        extra_section_bytes=high_ent_bytes,
        rwx=True,
        add_injection_strings=True,
    )
    vec, summary = extract_ember_features(suspicious_pe)
    assert vec.shape == (2381,)
    assert summary["rwx_sections"] == 1
    assert summary["max_section_entropy"] > 7.2

    ember_susp = classify_pe_bytes("packed_probe.exe", suspicious_pe)
    assert ember_susp["is_pe"] is True
    assert 0.0 <= ember_susp["ember_score"] <= 1.0
    assert ember_susp["ember_score"] >= 0.5
    assert "never treat as standalone proof" in ember_susp["caveat"].lower()

    # Check real benign Windows PE if running on Windows
    whoami = Path("C:/Windows/System32/whoami.exe")
    if whoami.is_file():
        benign_res = classify_pe_bytes("whoami.exe", whoami.read_bytes())
        assert benign_res["is_pe"] is True
        assert benign_res["ember_score"] < ember_susp["ember_score"]


def test_fim_baseline_drift_and_signature_degradation(client: TestClient, tmp_path: Path) -> None:
    ep_id, token = _enroll(client, "FIM-HOST")
    protected_dir = tmp_path / "critical_cfg"
    protected_dir.mkdir()
    hosts_file = protected_dir / "service.cfg"
    hosts_file.write_bytes(b"trusted=1")

    base_res = client.post(
        "/api/v1/fim/baselines",
        json={"endpoint_id": ep_id, "directory": str(protected_dir)},
    )
    assert base_res.status_code == 201
    assert base_res.json()["files_captured"] == 1

    # Simulate unauthorized modification and signature degradation
    tampered_hash = hashlib.sha256(b"malicious=1").hexdigest()
    ingest = _post_events(
        client,
        ep_id,
        token,
        [
            {
                "event_id": "evt_fim_mod",
                "telemetry_origin": "test_fixture",
                "category": "filesystem",
                "event_type": "file_modified",
                "severity": "info",
                "occurred_at": "2026-11-26T17:31:00Z",
                "dedup_hash": hashlib.sha256(b"fim1").hexdigest(),
                "filesystem": {
                    "file_path": str(hosts_file.resolve()),
                    "sha256": tampered_hash,
                    "size_bytes": 11,
                    "signature_status": "unsigned",
                },
            }
        ],
    )
    assert ingest["alerts_emitted"] >= 1
    fim_events = client.get(f"/api/v1/fim/events?endpoint_id={ep_id}").json()
    assert fim_events["total"] == 1
    assert fim_events["items"][0]["change_type"] == "modified"
    assert fim_events["items"][0]["observed_sha256"] == tampered_hash


def test_all_eight_behavioral_scenarios_and_ioc_matching(client: TestClient) -> None:
    ep_id, token = _enroll(client, "BEH-HOST")
    # Add local IOC IP + Hash (policy disables external outbound calls)
    ioc_res = client.post(
        "/api/v1/intel/iocs",
        json={"value": "203.0.113.55", "severity": "critical", "description": "Test C2 IP"},
    )
    assert ioc_res.status_code == 201
    lookup = client.post("/api/v1/intel/lookup", json={"value": "203.0.113.55"}).json()
    assert lookup["external_enabled"] is False
    assert len(lookup["local_matches"]) == 1

    parent_guid = f"{ep_id}-2000-10"
    child_guid = f"{ep_id}-3000-11"
    events = [
        # BEH-002 parent process (winword.exe)
        {
            "event_id": "evt_p1",
            "telemetry_origin": "test_fixture",
            "category": "process",
            "event_type": "process_start",
            "occurred_at": "2026-11-26T17:32:00Z",
            "dedup_hash": hashlib.sha256(b"b1").hexdigest(),
            "process": {
                "process_guid": parent_guid,
                "pid": 2000,
                "ppid": 4,
                "name": "winword.exe",
                "executable_path": "C:\\Program Files\\Microsoft Office\\winword.exe",
                "command_line": "winword.exe invoice.docx",
                "user_context": "LAB\\User",
                "signature_status": "valid",
                "started_at": "2026-11-26T17:32:00Z",
            },
        },
        # BEH-003 unexpected executable drop in Temp
        {
            "event_id": "evt_fdrop",
            "telemetry_origin": "test_fixture",
            "category": "filesystem",
            "event_type": "file_created",
            "occurred_at": "2026-11-26T17:32:01Z",
            "dedup_hash": hashlib.sha256(b"b2").hexdigest(),
            "filesystem": {
                "file_path": "C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe",
                "sha256": "b" * 64,
                "size_bytes": 1024,
                "signature_status": "unsigned",
            },
        },
        # BEH-001 (encoded) + BEH-002 (winword->ps) + BEH-004 (schtasks) + BEH-006 (minidump)
        {
            "event_id": "evt_p2",
            "telemetry_origin": "test_fixture",
            "category": "process",
            "event_type": "process_start",
            "occurred_at": "2026-11-26T17:32:02Z",
            "dedup_hash": hashlib.sha256(b"b3").hexdigest(),
            "process": {
                "process_guid": child_guid,
                "parent_process_guid": parent_guid,
                "pid": 3000,
                "ppid": 2000,
                "name": "powershell.exe",
                "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": (
                    "powershell.exe -EncodedCommand AA && schtasks /create /tn Upd /tr x && "
                    "rundll32 comsvcs.dll,MiniDump"
                ),
                "user_context": "LAB\\User",
                "signature_status": "valid",
                "started_at": "2026-11-26T17:32:02Z",
            },
        },
        # BEH-008 execution from Temp correlating with evt_fdrop
        {
            "event_id": "evt_p3",
            "telemetry_origin": "test_fixture",
            "category": "process",
            "event_type": "process_start",
            "occurred_at": "2026-11-26T17:32:03Z",
            "dedup_hash": hashlib.sha256(b"b4").hexdigest(),
            "process": {
                "process_guid": f"{ep_id}-3001-12",
                "parent_process_guid": child_guid,
                "pid": 3001,
                "ppid": 3000,
                "name": "payload.exe",
                "executable_path": "C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe",
                "command_line": "payload.exe",
                "user_context": "LAB\\User",
                "sha256": "b" * 64,
                "signature_status": "unsigned",
                "started_at": "2026-11-26T17:32:03Z",
            },
        },
        # BEH-005 abnormal outbound + IOC IP match
        {
            "event_id": "evt_net1",
            "telemetry_origin": "test_fixture",
            "category": "network",
            "event_type": "socket_observed",
            "occurred_at": "2026-11-26T17:32:04Z",
            "dedup_hash": hashlib.sha256(b"b5").hexdigest(),
            "network": {
                "protocol": "tcp",
                "local_addr": "192.168.1.50",
                "local_port": 51000,
                "remote_addr": "203.0.113.55",
                "remote_port": 4444,
                "state": "Established",
                "pid": 3001,
                "process_name": "payload.exe",
                "process_guid": f"{ep_id}-3001-12",
            },
        },
        # Sensitive location path modification (BEH-006)
        {
            "event_id": "evt_hosts",
            "telemetry_origin": "test_fixture",
            "category": "filesystem",
            "event_type": "file_modified",
            "occurred_at": "2026-11-26T17:32:05Z",
            "dedup_hash": hashlib.sha256(b"b6").hexdigest(),
            "filesystem": {
                "file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "sha256": "c" * 64,
                "size_bytes": 250,
                "signature_status": "unknown",
            },
        },
    ]

    # Add 12 rapid filesystem modifications to trigger BEH-007 ransomware burst
    from datetime import UTC, datetime

    now_iso = datetime.now(UTC).isoformat()
    for idx in range(12):
        events.append(
            {
                "event_id": f"evt_burst_{idx}",
                "telemetry_origin": "test_fixture",
                "category": "filesystem",
                "event_type": "file_modified",
                "occurred_at": now_iso,
                "dedup_hash": hashlib.sha256(f"burst_{idx}".encode()).hexdigest(),
                "filesystem": {
                    "file_path": f"C:\\Users\\User\\Documents\\doc_{idx}.locked",
                    "sha256": hashlib.sha256(f"d_{idx}".encode()).hexdigest(),
                    "size_bytes": 512,
                    "signature_status": "unknown",
                },
            }
        )

    ingest_res = _post_events(client, ep_id, token, events)
    assert ingest_res["accepted"] == len(events)

    alerts = client.get(f"/api/v1/detections/alerts?endpoint_id={ep_id}&limit=200").json()["items"]
    rule_ids = {a["rule_id"] for a in alerts}
    for expected in (
        "BEH-001",
        "BEH-002",
        "BEH-003",
        "BEH-004",
        "BEH-005",
        "BEH-006",
        "BEH-007",
        "BEH-008",
        "IOC-IP",
    ):
        assert expected in rule_ids, f"Missing expected rule {expected}; got {rule_ids}"

    # Verify confidence and severity are distinct and properly scored
    assert compute_risk_score("critical", 0.9) > compute_risk_score("low", 0.9)
    beh8 = next(a for a in alerts if a["rule_id"] == "BEH-008")
    assert "evt_fdrop" in beh8["evidence_event_ids"]
