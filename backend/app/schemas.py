"""Pydantic v2 contracts aligned with Stage 01 telemetry and API specifications."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TelemetryOrigin = Literal["real_endpoint", "recorded_demo", "test_fixture"]
TelemetryCategory = Literal["process", "network", "filesystem", "system", "sysmon", "fim"]
Severity = Literal["critical", "high", "medium", "low", "info"]
SensorState = Literal["ready", "partial", "unavailable", "pending"]
SignatureStatus = Literal["valid", "unsigned", "invalid", "unknown"]


class EnrollmentTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str = Field(default="Workstation enrollment", max_length=255)
    ttl_hours: int = Field(default=24, ge=1, le=720)


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bootstrap_token: str = Field(min_length=8, max_length=256)
    hostname: str = Field(min_length=1, max_length=255)
    fqdn: str | None = Field(default=None, max_length=255)
    os_family: Literal["windows", "linux", "macos"]
    os_version: str = Field(min_length=1, max_length=255)
    architecture: str = Field(min_length=1, max_length=64)
    agent_version: str = Field(min_length=1, max_length=64)
    primary_ip: str | None = Field(default=None, max_length=64)
    mac_address: str | None = Field(default=None, max_length=64)
    elevated_sensor: bool = False
    sysmon_available: bool = False


class SensorHealthMap(BaseModel):
    model_config = ConfigDict(extra="forbid")
    process: SensorState = "unavailable"
    network: SensorState = "unavailable"
    filesystem: SensorState = "unavailable"
    system: SensorState = "unavailable"
    sysmon: SensorState = "unavailable"


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str = Field(min_length=4, max_length=64)
    agent_version: str = Field(min_length=1, max_length=64)
    uptime_seconds: int = Field(ge=0)
    cpu_percent: float = Field(ge=0.0, le=100.0)
    memory_used_mb: int = Field(ge=0)
    memory_total_mb: int = Field(ge=0)
    disk_used_percent: float = Field(ge=0.0, le=100.0)
    agent_rss_mb: float = Field(ge=0.0)
    spool_queue_depth: int = Field(ge=0)
    policy_version: int = Field(ge=1)
    sensors: SensorHealthMap


class ProcessPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    process_guid: str = Field(min_length=1, max_length=128)
    parent_process_guid: str | None = Field(default=None, max_length=128)
    pid: int = Field(ge=0)
    ppid: int = Field(ge=0)
    name: str = Field(min_length=1, max_length=255)
    executable_path: str = Field(default="", max_length=1024)
    command_line: str = Field(default="", max_length=8192)
    user_context: str = Field(default="", max_length=255)
    sha256: str | None = Field(default=None, max_length=64)
    signature_status: SignatureStatus = "unknown"
    signer_subject: str | None = Field(default=None, max_length=512)
    started_at: str = Field(min_length=1, max_length=64)


class NetworkPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["tcp", "udp"]
    local_addr: str = Field(min_length=1, max_length=64)
    local_port: int = Field(ge=0, le=65535)
    remote_addr: str = Field(default="0.0.0.0", max_length=64)
    remote_port: int = Field(ge=0, le=65535)
    state: str = Field(min_length=1, max_length=64)
    pid: int | None = Field(default=None, ge=0)
    process_name: str | None = Field(default=None, max_length=255)
    process_guid: str | None = Field(default=None, max_length=128)


class FilesystemPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file_path: str = Field(min_length=1, max_length=1024)
    previous_path: str | None = Field(default=None, max_length=1024)
    sha256: str | None = Field(default=None, max_length=64)
    size_bytes: int | None = Field(default=None, ge=0)
    signature_status: SignatureStatus = "unknown"
    modified_at: str | None = Field(default=None, max_length=64)


class SystemPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu_percent: float = Field(ge=0.0, le=100.0)
    memory_used_mb: int = Field(ge=0)
    memory_total_mb: int = Field(ge=0)
    disk_used_percent: float = Field(ge=0.0, le=100.0)
    agent_rss_mb: float = Field(ge=0.0)
    os_version: str = Field(min_length=1, max_length=255)
    uptime_seconds: int = Field(ge=0)


class TelemetryEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(min_length=4, max_length=128)
    telemetry_origin: TelemetryOrigin = "real_endpoint"
    category: TelemetryCategory
    event_type: str = Field(min_length=1, max_length=128)
    severity: Severity = "info"
    occurred_at: str = Field(min_length=1, max_length=64)
    dedup_hash: str = Field(min_length=16, max_length=128)
    process: ProcessPayload | None = None
    network: NetworkPayload | None = None
    filesystem: FilesystemPayload | None = None
    system: SystemPayload | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class TelemetryBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str = Field(min_length=4, max_length=128)
    endpoint_id: str = Field(min_length=4, max_length=64)
    sent_at: str = Field(min_length=1, max_length=64)
    events: list[TelemetryEventIn] = Field(min_length=1, max_length=500)
