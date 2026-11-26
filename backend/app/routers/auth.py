"""Authentication, session verification, and admin user management routes."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.auth import (
    authenticate_user,
    create_access_token,
    create_user,
    get_current_user,
    list_users,
    require_role,
)
from app.config import get_settings
from app.db import get_connection
from app.response.audit import append_audit_log

router = APIRouter(prefix="/api/v1", tags=["auth-rbac"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=2, max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    role: Literal["admin", "responder", "analyst", "readonly_demo"]
    password: str = Field(min_length=8, max_length=256)


@router.post("/auth/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    cfg = get_settings()
    user = authenticate_user(payload.username, payload.password, settings=cfg)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token_bundle = create_access_token(user, settings=cfg)
    with get_connection(cfg) as conn:
        append_audit_log(
            conn,
            actor_id=user["user_id"],
            actor_role=user["role"],
            action="auth.login",
            resource_type="user",
            resource_id=user["user_id"],
            detail={"username": user["username"]},
        )
    return token_bundle


@router.get("/auth/me")
def whoami(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return user


@router.get("/users")
def get_users(
    _: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    items = list_users(get_settings())
    return {"items": items, "total": len(items)}


@router.post("/users", status_code=201)
def add_user(
    payload: UserCreateRequest,
    actor: dict[str, Any] = Depends(require_role("admin")),
) -> dict[str, Any]:
    cfg = get_settings()
    try:
        created = create_user(
            username=payload.username,
            display_name=payload.display_name,
            role=payload.role,
            password=payload.password,
            settings=cfg,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(status_code=409, detail="Username already exists.") from exc
        raise
    with get_connection(cfg) as conn:
        append_audit_log(
            conn,
            actor_id=actor["user_id"],
            actor_role=actor["role"],
            action="user.created",
            resource_type="user",
            resource_id=created["user_id"],
            detail={"username": created["username"], "role": created["role"]},
        )
    return created
