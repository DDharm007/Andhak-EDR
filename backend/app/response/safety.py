"""Protected OS target denylist preventing host-bricking response actions."""

from __future__ import annotations

import ipaddress
import ntpath
import sqlite3
from typing import Any

PROTECTED_PROCESS_NAMES = frozenset(
    {
        "system",
        "system idle process",
        "idle",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "lsm.exe",
        "winlogon.exe",
        "svchost.exe",
        "dwm.exe",
        "fontdrvhost.exe",
        "sihost.exe",
        "explorer.exe",
        "andhak-edr-agent",
        "andhak-edr-agent.exe",
        "systemd",
        "init",
        "launchd",
    }
)

PROTECTED_PATH_PREFIXES = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
    "c:\\programdata\\andhakedr\\quarantine\\",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
)

PROTECTED_EXACT_PATHS = frozenset(
    {
        "c:\\windows\\explorer.exe",
        "c:\\windows\\system32\\ntoskrnl.exe",
        "c:\\windows\\system32\\cmd.exe",
        "c:\\windows\\system32\\drivers\\etc\\hosts",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
    }
)


class ProtectedTargetError(Exception):
    def __init__(self, code: str, message: str, detail: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}

    def to_envelope(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "detail": self.detail,
            }
        }


def validate_response_target(
    conn: sqlite3.Connection,
    endpoint_id: str,
    action_type: str,
    target_value: str,
    target_metadata: dict[str, Any] | None = None,
) -> None:
    meta = target_metadata or {}
    target = target_value.strip()
    if not target:
        raise ProtectedTargetError(
            "INVALID_TARGET",
            "Response target cannot be empty.",
            {"action_type": action_type},
        )

    if action_type == "terminate_process":
        _validate_process_target(conn, endpoint_id, target, meta)
    elif action_type == "quarantine_file":
        _validate_file_target(target)
    elif action_type == "restore_file":
        if ".." in target.replace("\\", "/").split("/"):
            raise ProtectedTargetError(
                "PROTECTED_TARGET_BLOCKED",
                "Path traversal segments are forbidden in restore target.",
                {"target": target},
            )
    elif action_type == "block_network_indicator":
        _validate_network_target(target)
    elif action_type in {"isolate_endpoint", "release_isolation"}:
        if target != endpoint_id:
            raise ProtectedTargetError(
                "INVALID_TARGET",
                "Isolation target must match the specified endpoint_id.",
                {"endpoint_id": endpoint_id, "target_value": target},
            )


def _validate_process_target(
    conn: sqlite3.Connection,
    endpoint_id: str,
    target: str,
    meta: dict[str, Any],
) -> None:
    try:
        pid = int(target)
    except ValueError as exc:
        raise ProtectedTargetError(
            "INVALID_TARGET",
            "Process termination target_value must be a numeric PID.",
            {"target_value": target},
        ) from exc

    if pid <= 4:
        raise ProtectedTargetError(
            "PROTECTED_TARGET_BLOCKED",
            f"Kernel/system PID {pid} is protected and cannot be terminated.",
            {"pid": pid, "rule": "protected_kernel_pid"},
        )

    if meta.get("is_edr_agent") or meta.get("is_edr_backend"):
        raise ProtectedTargetError(
            "PROTECTED_TARGET_BLOCKED",
            "Self-termination of ANDHAK EDR agent or backend process is prohibited.",
            {"pid": pid, "rule": "edr_self_protection"},
        )

    candidates: list[str] = []
    for key in ("process_name", "executable_path"):
        val = str(meta.get(key) or "").strip()
        if val:
            candidates.append(val)

    # Also cross-check recorded telemetry on that endpoint for this PID
    row = conn.execute(
        """
        SELECT process_name, executable_path
        FROM process_executions
        WHERE endpoint_id = ? AND pid = ?
        ORDER BY started_at DESC LIMIT 1
        """,
        (endpoint_id, pid),
    ).fetchone()
    if row:
        candidates.extend([str(row["process_name"] or ""), str(row["executable_path"] or "")])

    for cand in candidates:
        base = ntpath.basename(cand.replace("/", "\\")).lower()
        if base in PROTECTED_PROCESS_NAMES:
            raise ProtectedTargetError(
                "PROTECTED_TARGET_BLOCKED",
                f"Target process '{base}' (PID {pid}) is protected and cannot be terminated.",
                {"pid": pid, "process_name": base, "rule": "protected_os_process"},
            )


def _validate_file_target(target: str) -> None:
    norm = target.replace("/", "\\").strip().lower()
    if ".." in norm.split("\\"):
        raise ProtectedTargetError(
            "PROTECTED_TARGET_BLOCKED",
            "Path traversal ('..') is forbidden in file quarantine target.",
            {"file_path": target, "rule": "path_traversal"},
        )

    base = ntpath.basename(norm)
    if base in {"andhak-edr-agent.exe", "andhak-edr-agent"}:
        raise ProtectedTargetError(
            "PROTECTED_TARGET_BLOCKED",
            "ANDHAK EDR agent binary cannot be quarantined.",
            {"file_path": target, "rule": "edr_self_protection"},
        )

    posix_norm = target.replace("\\", "/").strip().lower()
    if norm in PROTECTED_EXACT_PATHS or posix_norm in PROTECTED_EXACT_PATHS:
        raise ProtectedTargetError(
            "PROTECTED_TARGET_BLOCKED",
            f"Protected system file '{target}' cannot be quarantined.",
            {"file_path": target, "rule": "protected_system_file"},
        )

    for prefix in PROTECTED_PATH_PREFIXES:
        check = norm if "\\" in prefix else posix_norm
        if check.startswith(prefix):
            raise ProtectedTargetError(
                "PROTECTED_TARGET_BLOCKED",
                f"Protected OS directory target '{target}' cannot be quarantined.",
                {"file_path": target, "rule": "protected_os_directory"},
            )


def _validate_network_target(target: str) -> None:
    low = target.lower()
    if low in {"localhost", "0.0.0.0", "::", "::1"}:
        raise ProtectedTargetError(
            "PROTECTED_TARGET_BLOCKED",
            f"Network control target '{target}' is loopback/unspecified and protected.",
            {"target": target, "rule": "protected_loopback_target"},
        )
    addr = None
    try:
        addr = ipaddress.ip_address(target.split("/")[0])
    except ValueError:
        if low.endswith(".local") and low == "localhost.local":
            raise ProtectedTargetError(
                "PROTECTED_TARGET_BLOCKED",
                "Localhost alias cannot be blocked.",
                {"target": target},
            ) from None
    if addr is not None and (
        addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local
    ):
        raise ProtectedTargetError(
            "PROTECTED_TARGET_BLOCKED",
            f"Protected/non-routable IP '{target}' cannot be blocked.",
            {"target": target, "rule": "protected_network_range"},
        )
