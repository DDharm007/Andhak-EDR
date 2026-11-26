"""Argon2id password hashing, JWT session auth, and RBAC dependencies."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, Header, HTTPException, Request

from app.config import Settings, get_settings
from app.db import get_connection, utc_now_iso

VALID_ROLES = ("admin", "responder", "analyst", "readonly_demo")
_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    if not password_hash or password_hash.startswith("!"):
        return False
    try:
        return _HASHER.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def _validate_jwt_secret(settings: Settings) -> str:
    secret = settings.jwt_secret
    if settings.edr_env == "production" and (len(secret) < 32 or secret.startswith("CHANGE_ME")):
        raise RuntimeError(
            "Production environment requires ANDHAK_EDR_JWT_SECRET (>= 32 random chars)."
        )
    return secret


def create_user(
    username: str,
    display_name: str,
    role: str,
    password: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    if role not in VALID_ROLES:
        raise ValueError(f"Unsupported role '{role}'. Must be one of {VALID_ROLES}.")
    uname = username.strip()
    if len(uname) < 2:
        raise ValueError("Username must be at least 2 characters.")
    pw_hash = hash_password(password)
    user_id = f"usr_{uuid.uuid4().hex[:16]}"
    now = utc_now_iso()
    with get_connection(settings) as conn:
        conn.execute(
            """
            INSERT INTO users(
                user_id, username, display_name, role, password_hash, is_active, created_at
            ) VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (user_id, uname, display_name.strip() or uname, role, pw_hash, now),
        )
    return {
        "user_id": user_id,
        "username": uname,
        "display_name": display_name.strip() or uname,
        "role": role,
        "is_active": True,
        "created_at": now,
    }


def list_users(settings: Settings | None = None) -> list[dict[str, Any]]:
    with get_connection(settings) as conn:
        rows = conn.execute(
            """
            SELECT user_id, username, display_name, role, is_active, created_at, last_login_at
            FROM users
            ORDER BY created_at ASC
            """
        ).fetchall()
    return [
        {
            **dict(r),
            "is_active": bool(r["is_active"]),
        }
        for r in rows
    ]


def authenticate_user(
    username: str,
    password: str,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    cfg = settings or get_settings()
    with get_connection(cfg) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username.strip(),),
        ).fetchone()
        if row is None:
            return None
        if not verify_password(row["password_hash"], password):
            return None
        now = utc_now_iso()
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE user_id = ?",
            (now, row["user_id"]),
        )
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "last_login_at": now,
    }


def create_access_token(
    user: dict[str, Any],
    settings: Settings | None = None,
) -> dict[str, Any]:
    cfg = settings or get_settings()
    secret = _validate_jwt_secret(cfg)
    now_dt = datetime.now(UTC)
    exp_dt = now_dt + timedelta(minutes=cfg.jwt_expire_minutes)
    jti = uuid.uuid4().hex
    payload = {
        "sub": user["user_id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "role": user["role"],
        "iat": int(now_dt.timestamp()),
        "exp": int(exp_dt.timestamp()),
        "jti": jti,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": exp_dt.isoformat(),
        "user": user,
    }


def decode_access_token(token: str, settings: Settings | None = None) -> dict[str, Any]:
    cfg = settings or get_settings()
    secret = _validate_jwt_secret(cfg)
    return jwt.decode(token, secret, algorithms=["HS256"])


def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    cfg = get_settings()
    if cfg.demo_mode and request.method == "GET" and not authorization:
        return {
            "user_id": "usr_readonly_demo",
            "username": "demo_observer",
            "display_name": "Public Demo Observer",
            "role": "readonly_demo",
            "is_active": True,
        }

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Bearer JWT token.")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty Bearer JWT token.")
    try:
        claims = decode_access_token(token, cfg)
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid or expired JWT: {exc}") from exc

    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="JWT missing subject claim.")

    if cfg.demo_mode and claims.get("role") != "readonly_demo":
        # Demo mode strictly downgrades non-demo sessions to read-only inspection
        return {
            "user_id": str(user_id),
            "username": str(claims.get("username", "demo_observer")),
            "display_name": str(claims.get("display_name", "Demo Observer")),
            "role": "readonly_demo",
            "is_active": True,
        }

    with get_connection(cfg) as conn:
        row = conn.execute(
            """
            SELECT user_id, username, display_name, role, is_active
            FROM users
            WHERE user_id = ? AND is_active = 1
            """,
            (user_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="User account is inactive or unknown.")
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
    }


def require_role(*allowed_roles: str) -> Callable[..., dict[str, Any]]:
    """Enforce RBAC role membership and block state mutations in public demo mode."""

    def _dependency(
        request: Request,
        user: dict[str, Any] = Depends(get_current_user),
    ) -> dict[str, Any]:
        cfg = get_settings()
        if cfg.demo_mode and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            raise HTTPException(
                status_code=403,
                detail="Public demo mode is strictly read-only; mutations are disabled.",
            )
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Insufficient permissions for role '{user['role']}'; "
                    f"requires one of: {', '.join(allowed_roles)}."
                ),
            )
        return user

    return _dependency


def guard_demo_readonly() -> None:
    """Block operator mutations when running in public read-only demo mode."""
    cfg = get_settings()
    if cfg.demo_mode:
        raise HTTPException(
            status_code=403,
            detail="Public demo mode is strictly read-only; mutations are disabled.",
        )
