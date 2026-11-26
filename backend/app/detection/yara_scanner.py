"""YARA-X rule compiler, validator, and in-memory file scanner."""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

import yara_x

RULES_DIR = Path(__file__).resolve().parents[1] / "rules" / "yara"
MAX_SCAN_BYTES = 20 * 1024 * 1024


def validate_rule_source(source: str) -> tuple[bool, str | None]:
    """Validate YARA-X rule syntax before compilation or registration."""
    try:
        yara_x.compile(source)
        return True, None
    except Exception as exc:  # noqa: BLE001 - surface exact compiler syntax message
        return False, str(exc)


@lru_cache(maxsize=1)
def _load_compiled_rules() -> tuple[yara_x.Rules, list[dict[str, Any]]]:
    rule_files = sorted(RULES_DIR.glob("*.yar"))
    if not rule_files:
        raise RuntimeError(f"No YARA-X rule files found in {RULES_DIR}")

    compiler = yara_x.Compiler()
    catalog: list[dict[str, Any]] = []
    for path in rule_files:
        src = path.read_text(encoding="utf-8")
        compiler.add_source(src)
        catalog.append({"file": path.name, "bytes": len(src.encode("utf-8"))})
    return compiler.build(), catalog


def reload_rules() -> None:
    _load_compiled_rules.cache_clear()


def scanner_status() -> dict[str, Any]:
    try:
        _, files = _load_compiled_rules()
        return {
            "engine": "YARA-X",
            "available": True,
            "rule_files": files,
            "max_file_bytes": MAX_SCAN_BYTES,
            "license": "BSD-3-Clause (YARA-X) / MIT (ANDHAK rules)",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "engine": "YARA-X",
            "available": False,
            "rule_files": [],
            "max_file_bytes": MAX_SCAN_BYTES,
            "detail": str(exc),
        }


def _meta_dict(rule: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in getattr(rule, "metadata", ()):
        result[str(key)] = value
    return result


def scan_bytes_yara(file_name: str, content: bytes) -> dict[str, Any]:
    if not content:
        raise ValueError("Cannot scan an empty file.")
    if len(content) > MAX_SCAN_BYTES:
        raise ValueError("File exceeds 20 MB maximum scan limit.")

    rules, _ = _load_compiled_rules()
    scan_results = rules.scan(content)
    matches: list[dict[str, Any]] = []

    for rule in scan_results.matching_rules:
        meta = _meta_dict(rule)
        matched_patterns: list[dict[str, Any]] = []
        for pat in getattr(rule, "patterns", ()):
            for m in getattr(pat, "matches", ()):
                matched_patterns.append(
                    {
                        "identifier": str(pat.identifier),
                        "offset": int(m.offset),
                        "length": int(m.length),
                    }
                )
        severity = str(meta.get("severity", "medium")).lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "medium"
        try:
            confidence = float(meta.get("confidence", 0.75))
        except (TypeError, ValueError):
            confidence = 0.75
        mitre_raw = str(meta.get("mitre", "")).strip()
        mitre_tags = [t.strip() for t in mitre_raw.split(",") if t.strip()]

        matches.append(
            {
                "rule_id": str(rule.identifier),
                "namespace": str(getattr(rule, "namespace", "default")),
                "severity": severity,
                "confidence": max(0.0, min(1.0, confidence)),
                "description": str(meta.get("description", "Matched YARA-X signature")),
                "kind": str(meta.get("kind", "signature")),
                "author": str(meta.get("author", "ANDHAK EDR")),
                "license": str(meta.get("license", "MIT")),
                "mitre_techniques": mitre_tags,
                "patterns": matched_patterns[:20],
            }
        )

    return {
        "file_name": Path(file_name).name[:255],
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "engine": "YARA-X",
        "detected": bool(matches),
        "matches": matches,
        "saved_to_disk": False,
    }
