"""Stage 03 API routes: detections, FIM, malware analysis, and IOC intelligence."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from app.auth import guard_demo_readonly
from app.config import get_settings
from app.db import get_connection
from app.detection.ember_classifier import DATASET_PROVENANCE, FEATURE_SCHEMA_VERSION, MODEL_VERSION
from app.detection.fim_engine import capture_directory_baseline, list_fim_status
from app.detection.intel_service import (
    add_ioc,
    delete_ioc,
    enrich_indicator_reputation,
    list_iocs,
)
from app.detection.pipeline import analyze_file_bytes
from app.detection.scoring import list_alerts
from app.detection.yara_scanner import MAX_SCAN_BYTES, scanner_status

router = APIRouter(prefix="/api/v1", tags=["detection-intel"])


class AlertStatusPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "resolved", "false_positive"]


class FimBaselineCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str = Field(min_length=4, max_length=64)
    directory: str = Field(min_length=1, max_length=1024)
    recursive: bool = True


class MalwareScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file_name: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=4, max_length=28_000_000)
    endpoint_id: str | None = Field(default=None, max_length=64)
    file_path: str | None = Field(default=None, max_length=1024)
    telemetry_origin: Literal["real_endpoint", "recorded_demo", "test_fixture"] = "real_endpoint"


class IocCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(min_length=1, max_length=512)
    severity: Literal["critical", "high", "medium", "low", "info"] = "high"
    description: str = Field(default="", max_length=2000)
    mitre_tags: list[str] = Field(default_factory=list)


class IocLookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str = Field(min_length=1, max_length=512)


@router.get("/detections/alerts")
def get_alerts(
    endpoint_id: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    items = list_alerts(
        endpoint_id=endpoint_id,
        severity=severity,
        source=source,
        status=status,
        limit=limit,
    )
    return {"items": items, "total": len(items)}


@router.patch("/detections/alerts/{alert_id}", dependencies=[Depends(guard_demo_readonly)])
def update_alert_status(alert_id: str, payload: AlertStatusPatch) -> dict[str, Any]:
    with get_connection() as conn:
        cur = conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?",
            (payload.status, alert_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found.")
        row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    return dict(row)


@router.get("/detections/rules")
def get_rules() -> dict[str, Any]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM detection_rules ORDER BY source, rule_id").fetchall()
    items = []
    for r in rows:
        item = dict(r)
        item["mitre_techniques"] = json.loads(item.pop("mitre_techniques_json", "[]"))
        items.append(item)
    return {"items": items, "total": len(items)}


@router.get("/fim/status")
def fim_status(endpoint_id: str | None = None) -> dict[str, Any]:
    return list_fim_status(endpoint_id=endpoint_id)


@router.post("/fim/baselines", status_code=201, dependencies=[Depends(guard_demo_readonly)])
def fim_create_baseline(payload: FimBaselineCreate) -> dict[str, Any]:
    try:
        return capture_directory_baseline(
            endpoint_id=payload.endpoint_id,
            directory=Path(payload.directory),
            recursive=payload.recursive,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/fim/events")
def fim_events(endpoint_id: str | None = None) -> dict[str, Any]:
    data = list_fim_status(endpoint_id=endpoint_id)
    return {"items": data["events"], "total": len(data["events"])}


@router.get("/malware/status")
def malware_engine_status() -> dict[str, Any]:
    return {
        "yara": scanner_status(),
        "ember": {
            "model_version": MODEL_VERSION,
            "feature_schema": FEATURE_SCHEMA_VERSION,
            "provenance": DATASET_PROVENANCE,
            "advisory_only": True,
        },
    }


@router.get("/malware/analyses")
def list_malware_analyses(limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM malware_analyses ORDER BY analyzed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        item["yara_matches"] = json.loads(item.pop("yara_matches_json", "[]"))
        item["ioc_reputation"] = json.loads(item.pop("ioc_reputation_json", "{}"))
        items.append(item)
    return {"items": items, "total": len(items)}


@router.post("/malware/scan", dependencies=[Depends(guard_demo_readonly)])
async def scan_malware_file(payload: MalwareScanRequest) -> dict[str, Any]:
    try:
        content = base64.b64decode(payload.content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail="File must be valid base64.") from exc
    if not content:
        raise HTTPException(status_code=422, detail="File cannot be empty.")
    if len(content) > MAX_SCAN_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 20 MB maximum size.")
    return await analyze_file_bytes(
        file_name=payload.file_name,
        content=content,
        endpoint_id=payload.endpoint_id,
        file_path=payload.file_path,
        telemetry_origin=payload.telemetry_origin,
        settings=get_settings(),
    )


@router.get("/intel/iocs")
def get_iocs() -> dict[str, Any]:
    items = list_iocs()
    return {"items": items, "total": len(items)}


@router.post("/intel/iocs", status_code=201, dependencies=[Depends(guard_demo_readonly)])
def create_ioc(payload: IocCreateRequest) -> dict[str, Any]:
    try:
        return add_ioc(
            value=payload.value,
            severity=payload.severity,
            description=payload.description,
            mitre_tags=payload.mitre_tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        if "UNIQUE constraint failed" in str(exc):
            raise HTTPException(status_code=409, detail="IOC already exists.") from exc
        raise


@router.delete("/intel/iocs/{ioc_id}", dependencies=[Depends(guard_demo_readonly)])
def remove_ioc(ioc_id: str) -> dict[str, bool]:
    if not delete_ioc(ioc_id):
        raise HTTPException(status_code=404, detail="IOC not found.")
    return {"deleted": True}


@router.post("/intel/lookup")
async def lookup_ioc(payload: IocLookupRequest) -> dict[str, Any]:
    try:
        return await enrich_indicator_reputation(payload.value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
