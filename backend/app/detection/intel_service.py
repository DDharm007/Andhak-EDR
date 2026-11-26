"""Local IOC intelligence store and policy-gated external threat-intel enrichment."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import uuid
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.config import Settings, get_settings
from app.db import get_connection, utc_now_iso
from app.detection.scoring import AlertCandidate
from app.schemas import TelemetryEventIn

_HASH_RE = re.compile(r"(?i)^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def classify_ioc(value: str) -> tuple[str, str]:
    """Normalize and classify IOCs matching ANDHAK SOC indicator contract."""
    normalized = value.strip()
    if not normalized:
        raise ValueError("IOC value cannot be empty.")
    try:
        addr = ipaddress.ip_address(normalized)
        return "ip", addr.compressed
    except ValueError:
        pass

    if _HASH_RE.fullmatch(normalized):
        return "file_hash", normalized.lower()

    candidate = normalized.lower()
    if candidate.startswith(("http://", "https://")):
        if urlsplit(candidate).hostname:
            return "url", candidate
        raise ValueError("Invalid HTTP/HTTPS URL indicator.")

    domain = candidate.rstrip(".")
    if _DOMAIN_RE.fullmatch(domain):
        return "domain", domain
    raise ValueError("Enter a valid IP, domain, HTTP(S) URL, or file hash.")


def add_ioc(
    value: str,
    severity: str = "high",
    source: str = "local",
    description: str = "",
    mitre_tags: list[str] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    kind, normalized = classify_ioc(value)
    ioc_id = f"ioc_{uuid.uuid4().hex[:16]}"
    now = utc_now_iso()
    with get_connection(settings) as conn:
        conn.execute(
            """
            INSERT INTO iocs(
                ioc_id, value, kind, severity, source, description, mitre_tags_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc_id,
                normalized,
                kind,
                severity,
                source,
                description.strip(),
                json.dumps(mitre_tags or []),
                now,
            ),
        )
        row = conn.execute("SELECT * FROM iocs WHERE ioc_id = ?", (ioc_id,)).fetchone()
    return _format_ioc(row)


def list_iocs(settings: Settings | None = None) -> list[dict[str, Any]]:
    with get_connection(settings) as conn:
        rows = conn.execute("SELECT * FROM iocs ORDER BY created_at DESC").fetchall()
    return [_format_ioc(r) for r in rows]


def delete_ioc(ioc_id: str, settings: Settings | None = None) -> bool:
    with get_connection(settings) as conn:
        cur = conn.execute("DELETE FROM iocs WHERE ioc_id = ?", (ioc_id,))
        return cur.rowcount > 0


def _format_ioc(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["mitre_tags"] = json.loads(d.pop("mitre_tags_json", "[]"))
    return d


def match_telemetry_iocs(
    conn: sqlite3.Connection,
    endpoint_id: str,
    evt: TelemetryEventIn,
) -> list[AlertCandidate]:
    iocs = [dict(r) for r in conn.execute("SELECT * FROM iocs").fetchall()]
    if not iocs:
        return []

    hashes: set[str] = set()
    ips: set[str] = set()
    text_haystack = ""

    if evt.process:
        if evt.process.sha256:
            hashes.add(evt.process.sha256.lower())
        text_haystack += f" {evt.process.command_line}".lower()
        proc_guid = evt.process.process_guid
        pid = evt.process.pid
        proc_name = evt.process.name
    elif evt.network:
        ips.add(evt.network.remote_addr.lower())
        proc_guid = evt.network.process_guid
        pid = evt.network.pid
        proc_name = evt.network.process_name
    elif evt.filesystem:
        if evt.filesystem.sha256:
            hashes.add(evt.filesystem.sha256.lower())
        proc_guid = None
        pid = None
        proc_name = None
    else:
        proc_guid = None
        pid = None
        proc_name = None

    alerts: list[AlertCandidate] = []
    for ioc in iocs:
        val = str(ioc["value"]).lower()
        kind = str(ioc["kind"])
        matched = (
            (kind == "file_hash" and val in hashes)
            or (kind == "ip" and val in ips)
            or (kind in {"domain", "url"} and val in text_haystack)
        )
        if not matched:
            continue
        mitre = json.loads(ioc.get("mitre_tags_json") or "[]")
        alerts.append(
            AlertCandidate(
                endpoint_id=endpoint_id,
                rule_id=f"IOC-{kind.upper()}",
                rule_name=f"Threat Intel IOC Match ({kind})",
                detection_source="ioc",
                severity=str(ioc["severity"]),
                confidence=0.95 if kind in {"file_hash", "ip"} else 0.85,
                process_guid=proc_guid,
                pid=pid,
                process_name=proc_name,
                file_sha256=val if kind == "file_hash" else None,
                evidence_event_ids=[evt.event_id],
                evidence_summary=(
                    f"Matched IOC {ioc['value']} (source={ioc['source']}): "
                    f"{ioc.get('description') or 'Local watchlist indicator'}"
                ),
                mitre_techniques=mitre or ["T1071.001"],
                recommended_actions=[
                    "Review associated endpoint process and network activity",
                    "Block network indicator or quarantine matching file",
                ],
                telemetry_origin=evt.telemetry_origin,
                dedup_scope=f"ioc:{val}",
            )
        )
    return alerts


async def enrich_indicator_reputation(
    value: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Query local IOC DB first; optionally query external intel only when policy allows."""
    cfg = settings or get_settings()
    kind, normalized = classify_ioc(value)

    with get_connection(cfg) as conn:
        local_rows = conn.execute(
            "SELECT * FROM iocs WHERE value = ? COLLATE NOCASE",
            (normalized,),
        ).fetchall()
    local_matches = [_format_ioc(r) for r in local_rows]

    result: dict[str, Any] = {
        "query": normalized,
        "kind": kind,
        "local_matches": local_matches,
        "external_enabled": cfg.intel_external_enabled,
        "external_results": [],
        "privacy_policy": {
            "hash_only": cfg.intel_allow_hash_only,
            "file_upload_allowed": False,
        },
    }

    if not cfg.intel_external_enabled:
        result["note"] = "External threat-intel lookups disabled by policy; local IOC DB only."
        return result

    async with httpx.AsyncClient(timeout=8.0) as client:
        if kind == "file_hash" and cfg.malwarebazaar_auth_key:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                headers={"Auth-Key": cfg.malwarebazaar_auth_key},
                data={"query": "get_info", "hash": normalized},
            )
            result["external_results"].append(
                {
                    "provider": "malwarebazaar",
                    "status_code": resp.status_code,
                    "data": resp.json() if resp.status_code == 200 else {},
                }
            )
        elif kind == "ip" and cfg.abuseipdb_api_key:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": cfg.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": normalized, "maxAgeInDays": 90},
            )
            result["external_results"].append(
                {
                    "provider": "abuseipdb",
                    "status_code": resp.status_code,
                    "data": resp.json() if resp.status_code == 200 else {},
                }
            )
        elif cfg.virustotal_api_key and kind in {"file_hash", "ip", "domain"}:
            vt_path = {"file_hash": "files", "ip": "ip_addresses", "domain": "domains"}[kind]
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/{vt_path}/{normalized}",
                headers={"x-apikey": cfg.virustotal_api_key},
            )
            result["external_results"].append(
                {
                    "provider": "virustotal",
                    "status_code": resp.status_code,
                    "data": resp.json() if resp.status_code == 200 else {},
                }
            )
    return result
