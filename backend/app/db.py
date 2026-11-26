"""Local SQLite WAL database manager enforcing Stage 01 relational DDL."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.config import Settings, get_settings

DEFAULT_POLICY_ID = "pol_default_windows"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def hash_secret(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def init_database(settings: Settings | None = None) -> Path:
    cfg = settings or get_settings()
    db_file = cfg.resolved_db_path
    db_file.parent.mkdir(parents=True, exist_ok=True)
    schema_sql = cfg.schema_sql_path.read_text(encoding="utf-8")

    conn = sqlite3.connect(db_file, timeout=15)
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.executescript(schema_sql)
        _seed_defaults(conn, cfg)
        conn.commit()
    finally:
        conn.close()
    return db_file


def _seed_defaults(conn: sqlite3.Connection, cfg: Settings) -> None:
    from app.detection.pipeline import sync_detection_rules

    now = utc_now_iso()
    conn.execute(
        """
        INSERT OR IGNORE INTO users(
            user_id, username, display_name, role, password_hash, is_active, created_at
        ) VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (
            "usr_system_admin",
            "system",
            "System Provisioner",
            "admin",
            "!disabled-system-account!",
            now,
        ),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO policies(
            policy_id, name, version, fim_paths_json, exclusions_json,
            collection_intervals_json, intel_external_enabled, allow_file_upload,
            updated_by, updated_at
        ) VALUES (?, ?, 1, ?, ?, ?, 0, 0, ?, ?)
        """,
        (
            DEFAULT_POLICY_ID,
            "Default Windows Workstation Policy",
            '["C:\\\\Windows\\\\System32\\\\drivers\\\\etc"]',
            '["*.tmp", "*.log", "*.etl", "agent-spool.sqlite3*"]',
            (
                '{"heartbeat_seconds": 15, "process_poll_ms": 2000, '
                '"network_poll_ms": 5000, "system_poll_ms": 5000, '
                '"batch_max_events": 100, "flush_interval_ms": 2000}'
            ),
            "usr_system_admin",
            now,
        ),
    )
    for domain, days in (
        ("telemetry", cfg.retention_telemetry_days),
        ("alerts", cfg.retention_alerts_days),
        ("incidents", cfg.retention_incidents_days),
        ("audit", cfg.retention_audit_days),
    ):
        conn.execute(
            """
            INSERT OR IGNORE INTO retention_policies(domain, retention_days, updated_at)
            VALUES (?, ?, ?)
            """,
            (domain, days, now),
        )
    if cfg.bootstrap_token:
        token_hash = hash_secret(cfg.bootstrap_token)
        conn.execute(
            """
            INSERT OR IGNORE INTO enrollment_tokens(
                token_id, token_hash, description, created_by, expires_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "tok_env_bootstrap",
                token_hash,
                "Environment configured bootstrap token",
                "usr_system_admin",
                "2099-12-31T23:59:59+00:00",
            ),
        )
    if cfg.bootstrap_admin_username and cfg.bootstrap_admin_password:
        from app.auth import hash_password

        existing = conn.execute(
            "SELECT user_id FROM users WHERE username = ?",
            (cfg.bootstrap_admin_username.strip(),),
        ).fetchone()
        if existing is None:
            pw_hash = hash_password(cfg.bootstrap_admin_password)
            conn.execute(
                """
                INSERT INTO users(
                    user_id, username, display_name, role, password_hash, is_active, created_at
                ) VALUES (?, ?, ?, 'admin', ?, 1, ?)
                """,
                (
                    f"usr_boot_{hash_secret(cfg.bootstrap_admin_username)[:10]}",
                    cfg.bootstrap_admin_username.strip(),
                    cfg.bootstrap_admin_username.strip(),
                    pw_hash,
                    now,
                ),
            )
    sync_detection_rules(conn)


@contextmanager
def get_connection(settings: Settings | None = None) -> Iterator[sqlite3.Connection]:
    cfg = settings or get_settings()
    conn = sqlite3.connect(cfg.resolved_db_path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
