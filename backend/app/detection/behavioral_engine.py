"""Stateful behavioral detection engine covering eight core EDR scenarios."""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from app.detection.scoring import AlertCandidate
from app.schemas import TelemetryEventIn

BEHAVIORAL_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "BEH-001",
        "name": "Suspicious Encoded Command Execution",
        "severity": "high",
        "confidence": 0.88,
        "mitre": ["T1059.001", "T1059.003"],
        "description": "Detects encoded or hidden-window PowerShell/shell command execution.",
    },
    {
        "rule_id": "BEH-002",
        "name": "Unusual Parent-Child Process Relationship",
        "severity": "high",
        "confidence": 0.84,
        "mitre": ["T1204.002", "T1059.001"],
        "description": (
            "Office, PDF reader, or browser process spawned a scripting or command interpreter."
        ),
    },
    {
        "rule_id": "BEH-003",
        "name": "Unexpected Executable Creation",
        "severity": "medium",
        "confidence": 0.74,
        "mitre": ["T1105"],
        "description": "Executable or script dropped in temporary, public, or staging directories.",
    },
    {
        "rule_id": "BEH-004",
        "name": "Suspicious Startup or Persistence Modification",
        "severity": "high",
        "confidence": 0.85,
        "mitre": ["T1547.001", "T1053.005", "T1543.003"],
        "description": (
            "Detects Run-key, Startup folder, Scheduled Task, or Service creation commands."
        ),
    },
    {
        "rule_id": "BEH-005",
        "name": "Abnormal Outbound Network Activity",
        "severity": "high",
        "confidence": 0.78,
        "mitre": ["T1071.001"],
        "description": (
            "External outbound socket from unsigned/staging binary or onto suspicious C2 ports."
        ),
    },
    {
        "rule_id": "BEH-006",
        "name": "Sensitive Location Access or Modification",
        "severity": "high",
        "confidence": 0.82,
        "mitre": ["T1565.001", "T1003.001"],
        "description": (
            "Modification or suspicious command targeting hosts, SAM, LSASS, or SSH keys."
        ),
    },
    {
        "rule_id": "BEH-007",
        "name": "Rapid File Modification Burst (Ransomware Pattern)",
        "severity": "critical",
        "confidence": 0.89,
        "mitre": ["T1486"],
        "description": (
            "High-velocity file modifications or renames exceeding threshold within 60 seconds."
        ),
    },
    {
        "rule_id": "BEH-008",
        "name": "Suspicious Execution from Temporary Directory",
        "severity": "high",
        "confidence": 0.81,
        "mitre": ["T1204.002"],
        "description": (
            "Process executed from Temp, Downloads, or Users\\Public (elevated if unsigned)."
        ),
    },
)

_ENCODED_RE = re.compile(
    r"(?i)(?:-enc(?:odedcommand)?\b|\s/enc\b|frombase64string|-w\s+hidden|-windowstyle\s+hidden)"
)
_PERSIST_CMD_RE = re.compile(
    r"(?i)(?:reg\s+add\b.*\\run\b|schtasks(?:\.exe)?\s+/create\b|sc(?:\.exe)?\s+create\b)"
)
_SENSITIVE_CMD_RE = re.compile(
    r"(?i)(?:comsvcs\.dll,minidump|procdump.*lsass|\\system32\\drivers\\etc\\hosts|\\system32\\config\\sam)"
)

SUSPICIOUS_PARENTS = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "msedge.exe",
    "chrome.exe",
    "firefox.exe",
}
INTERPRETER_CHILDREN = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}
STAGING_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
    "\\programdata\\",
    "/tmp/",
)
EXECUTABLE_EXTS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".hta", ".msi")
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 9001, 6667, 8443}
SENSITIVE_PATHS = (
    "\\system32\\drivers\\etc\\hosts",
    "\\system32\\config\\sam",
    "\\microsoft\\windows\\start menu\\programs\\startup",
    "/.ssh/",
    "\\.ssh\\",
)


_RFC1918_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def _is_external_candidate(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
            return False
        return not any(addr in net for net in _RFC1918_NETS)
    except ValueError:
        return False


def evaluate_behavioral_event(
    conn: sqlite3.Connection,
    endpoint_id: str,
    evt: TelemetryEventIn,
) -> list[AlertCandidate]:
    alerts: list[AlertCandidate] = []
    origin = evt.telemetry_origin

    if evt.process is not None and evt.event_type == "process_start":
        proc = evt.process
        cmd = proc.command_line or ""
        exe_lower = proc.executable_path.lower().replace("/", "\\")
        proc_lower = proc.name.lower()

        # BEH-001: Suspicious encoded command execution
        if _ENCODED_RE.search(cmd):
            alerts.append(
                AlertCandidate(
                    endpoint_id=endpoint_id,
                    rule_id="BEH-001",
                    rule_name="Suspicious Encoded Command Execution",
                    detection_source="behavioral",
                    severity="high",
                    confidence=0.88,
                    process_guid=proc.process_guid,
                    pid=proc.pid,
                    process_name=proc.name,
                    file_sha256=proc.sha256,
                    evidence_event_ids=[evt.event_id],
                    evidence_summary=f"{proc.name} (PID {proc.pid}) executed encoded/hidden flags",
                    mitre_techniques=["T1059.001", "T1059.003"],
                    recommended_actions=[
                        "Decode base64 payload safely without executing",
                        "Inspect parent process and spawned network connections",
                    ],
                    telemetry_origin=origin,
                )
            )

        # BEH-002: Unusual parent-child process relationships
        if proc.parent_process_guid:
            parent_row = conn.execute(
                "SELECT process_name, pid FROM process_executions WHERE process_guid = ?",
                (proc.parent_process_guid,),
            ).fetchone()
            if parent_row:
                parent_name = str(parent_row["process_name"]).lower()
                if parent_name in SUSPICIOUS_PARENTS and proc_lower in INTERPRETER_CHILDREN:
                    alerts.append(
                        AlertCandidate(
                            endpoint_id=endpoint_id,
                            rule_id="BEH-002",
                            rule_name="Unusual Parent-Child Process Relationship",
                            detection_source="behavioral",
                            severity="high",
                            confidence=0.86,
                            process_guid=proc.process_guid,
                            pid=proc.pid,
                            process_name=proc.name,
                            file_sha256=proc.sha256,
                            evidence_event_ids=[evt.event_id],
                            evidence_summary=(
                                f"{parent_row['process_name']} (PID {parent_row['pid']}) "
                                f"spawned {proc.name} (PID {proc.pid})"
                            ),
                            mitre_techniques=["T1204.002", "T1059.001"],
                            recommended_actions=[
                                "Inspect document or browser tab context",
                                "Consider terminating child interpreter process",
                            ],
                            telemetry_origin=origin,
                        )
                    )

        # BEH-004: Suspicious startup / scheduled task / service persistence
        if _PERSIST_CMD_RE.search(cmd):
            alerts.append(
                AlertCandidate(
                    endpoint_id=endpoint_id,
                    rule_id="BEH-004",
                    rule_name="Suspicious Startup or Persistence Modification",
                    detection_source="behavioral",
                    severity="high",
                    confidence=0.85,
                    process_guid=proc.process_guid,
                    pid=proc.pid,
                    process_name=proc.name,
                    evidence_event_ids=[evt.event_id],
                    evidence_summary=f"Persistence command detected in {proc.name}: {cmd[:180]}",
                    mitre_techniques=["T1547.001", "T1053.005", "T1543.003"],
                    recommended_actions=[
                        "Audit created Run key, scheduled task, or service binary path",
                    ],
                    telemetry_origin=origin,
                )
            )

        # BEH-006: Sensitive credential/config command targeting
        if _SENSITIVE_CMD_RE.search(cmd):
            alerts.append(
                AlertCandidate(
                    endpoint_id=endpoint_id,
                    rule_id="BEH-006",
                    rule_name="Sensitive Location Access or Modification",
                    detection_source="behavioral",
                    severity="critical",
                    confidence=0.90,
                    process_guid=proc.process_guid,
                    pid=proc.pid,
                    process_name=proc.name,
                    evidence_event_ids=[evt.event_id],
                    evidence_summary=f"Sensitive credential/system target in {proc.name}",
                    mitre_techniques=["T1003.001"],
                    recommended_actions=[
                        "Terminate offending process and isolate endpoint",
                        "Rotate affected credentials immediately",
                    ],
                    telemetry_origin=origin,
                )
            )

        # BEH-008: Execution from temporary/staging directories (+ temp drop correlation boost)
        if any(marker in exe_lower for marker in STAGING_MARKERS):
            recent_drop = conn.execute(
                """
                SELECT event_id FROM telemetry_events
                WHERE endpoint_id = ? AND category IN ('filesystem', 'fim')
                  AND LOWER(REPLACE(file_path, '/', '\\')) = ?
                ORDER BY occurred_at DESC LIMIT 1
                """,
                (endpoint_id, exe_lower),
            ).fetchone()
            corroboration = 1 if recent_drop else 0
            if proc.signature_status in {"unsigned", "invalid"}:
                corroboration += 1
            severity = "high" if proc.signature_status != "valid" else "medium"
            conf = min(0.95, 0.74 + corroboration * 0.08)
            ev_ids = [evt.event_id] + ([recent_drop["event_id"]] if recent_drop else [])
            alerts.append(
                AlertCandidate(
                    endpoint_id=endpoint_id,
                    rule_id="BEH-008",
                    rule_name="Suspicious Execution from Temporary Directory",
                    detection_source="behavioral",
                    severity=severity,
                    confidence=conf,
                    corroborating_signals=corroboration,
                    process_guid=proc.process_guid,
                    pid=proc.pid,
                    process_name=proc.name,
                    file_sha256=proc.sha256,
                    evidence_event_ids=ev_ids,
                    evidence_summary=(
                        f"Executed from staging path {proc.executable_path} "
                        f"(sig={proc.signature_status})"
                    ),
                    mitre_techniques=["T1204.002"],
                    recommended_actions=[
                        "Scan executable with YARA-X and EMBER",
                        "Quarantine unsigned temporary binary if unapproved",
                    ],
                    telemetry_origin=origin,
                )
            )

    if evt.filesystem is not None:
        fs = evt.filesystem
        norm_path = fs.file_path.lower().replace("/", "\\")

        # BEH-003: Unexpected executable creation in staging/system paths
        if evt.event_type == "file_created" and norm_path.endswith(EXECUTABLE_EXTS):
            if any(m in norm_path for m in STAGING_MARKERS) or "\\windows\\system32\\" in norm_path:
                sev = "high" if fs.signature_status != "valid" else "medium"
                alerts.append(
                    AlertCandidate(
                        endpoint_id=endpoint_id,
                        rule_id="BEH-003",
                        rule_name="Unexpected Executable Creation",
                        detection_source="behavioral",
                        severity=sev,
                        confidence=0.78 if fs.signature_status != "valid" else 0.62,
                        file_sha256=fs.sha256,
                        evidence_event_ids=[evt.event_id],
                        evidence_summary=(
                            f"Executable created at {fs.file_path} (sig={fs.signature_status})"
                        ),
                        mitre_techniques=["T1105"],
                        recommended_actions=[
                            "Inspect binary via YARA-X and EMBER static PE analyzer",
                        ],
                        telemetry_origin=origin,
                        dedup_scope=fs.file_path,
                    )
                )

        # BEH-004 / BEH-006: Sensitive startup or critical file location changes
        if any(s in norm_path for s in SENSITIVE_PATHS):
            is_startup = "startup" in norm_path
            alerts.append(
                AlertCandidate(
                    endpoint_id=endpoint_id,
                    rule_id="BEH-004" if is_startup else "BEH-006",
                    rule_name=(
                        "Suspicious Startup or Persistence Modification"
                        if is_startup
                        else "Sensitive Location Access or Modification"
                    ),
                    detection_source="behavioral",
                    severity="high",
                    confidence=0.84,
                    file_sha256=fs.sha256,
                    evidence_event_ids=[evt.event_id],
                    evidence_summary=f"{evt.event_type} on sensitive location {fs.file_path}",
                    mitre_techniques=["T1547.001"] if is_startup else ["T1565.001"],
                    recommended_actions=["Verify change authorization and inspect file hash"],
                    telemetry_origin=origin,
                    dedup_scope=fs.file_path,
                )
            )

        # BEH-007: Rapid file modification/rename bursts (windowed velocity check)
        if evt.event_type in {"file_modified", "file_renamed", "file_created"}:
            cutoff = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
            burst_rows = conn.execute(
                """
                SELECT event_id FROM telemetry_events
                WHERE endpoint_id = ? AND category = 'filesystem'
                  AND event_type IN ('file_modified', 'file_renamed', 'file_created')
                  AND occurred_at >= ?
                ORDER BY occurred_at DESC LIMIT 25
                """,
                (endpoint_id, cutoff),
            ).fetchall()
            if len(burst_rows) >= 12:
                alerts.append(
                    AlertCandidate(
                        endpoint_id=endpoint_id,
                        rule_id="BEH-007",
                        rule_name="Rapid File Modification Burst (Ransomware Pattern)",
                        detection_source="behavioral",
                        severity="critical",
                        confidence=0.89,
                        corroborating_signals=1,
                        evidence_event_ids=[r["event_id"] for r in burst_rows[:10]],
                        evidence_summary=(
                            f"Observed {len(burst_rows)} rapid filesystem writes/renames "
                            f"within 60s window (latest: {fs.file_path})"
                        ),
                        mitre_techniques=["T1486"],
                        recommended_actions=[
                            "Isolate endpoint immediately if activity is not a known updater",
                            "Identify and terminate process driving rapid writes",
                        ],
                        telemetry_origin=origin,
                        dedup_scope="rapid_fs_burst",
                    )
                )

    if evt.network is not None:
        net = evt.network
        if net.remote_port > 0 and (
            net.remote_port in SUSPICIOUS_PORTS or _is_external_candidate(net.remote_addr)
        ):
            suspicious_port = net.remote_port in SUSPICIOUS_PORTS
            unsigned_or_temp = False
            proc_sig = "unknown"
            proc_path = ""
            if net.process_guid:
                prow = conn.execute(
                    "SELECT executable_path, signature_status FROM process_executions "
                    "WHERE process_guid = ?",
                    (net.process_guid,),
                ).fetchone()
                if prow:
                    proc_path = str(prow["executable_path"] or "").lower()
                    proc_sig = str(prow["signature_status"] or "unknown")
                    unsigned_or_temp = proc_sig in {"unsigned", "invalid"} or any(
                        m in proc_path for m in STAGING_MARKERS
                    )

            if suspicious_port or unsigned_or_temp:
                conf = 0.86 if (suspicious_port and unsigned_or_temp) else 0.76
                alerts.append(
                    AlertCandidate(
                        endpoint_id=endpoint_id,
                        rule_id="BEH-005",
                        rule_name="Abnormal Outbound Network Activity",
                        detection_source="behavioral",
                        severity="high",
                        confidence=conf,
                        corroborating_signals=1 if (suspicious_port and unsigned_or_temp) else 0,
                        process_guid=net.process_guid,
                        pid=net.pid,
                        process_name=net.process_name,
                        evidence_event_ids=[evt.event_id],
                        evidence_summary=(
                            f"{net.process_name or 'Unknown'} (PID {net.pid}) -> "
                            f"{net.remote_addr}:{net.remote_port} ({net.protocol}, sig={proc_sig})"
                        ),
                        mitre_techniques=["T1071.001"],
                        recommended_actions=[
                            "Check remote IP reputation and block indicator if malicious",
                            "Inspect process binary and command line",
                        ],
                        telemetry_origin=origin,
                        dedup_scope=f"{net.remote_addr}:{net.remote_port}:{net.process_name}",
                    )
                )

    return alerts
