# ANDHAK EDR — Endpoint Telemetry & Agent Transport Contract

**Version:** `1.0.0` (Stage 01 Contract)  
**Transport:** HTTPS / TLS 1.2+ (`rustls` on Rust sensor), UTF-8 JSON payloads, optional gzip body compression.  
**Authentication:** One-time bootstrap token at enrollment; scoped per-endpoint bearer token (`Authorization: Bearer <agent_token>`) + `X-Endpoint-ID` + `X-Agent-Timestamp` + `X-Payload-SHA256` on subsequent requests.

---

## 1. Agent Enrollment (`POST /api/v1/agent/enroll`)

Issued once during endpoint provisioning. Bootstrap token is consumed on success and never embedded inside compiled agent binaries.

### Request
```json
{
  "bootstrap_token": "andhak_bs_...",
  "hostname": "WORKSTATION-01",
  "fqdn": "workstation-01.local",
  "os_family": "windows",
  "os_version": "Windows 11 10.0.26300",
  "architecture": "x86_64",
  "agent_version": "0.1.0",
  "primary_ip": "192.168.1.50",
  "mac_address": "00:11:22:33:44:55",
  "elevated_sensor": false,
  "sysmon_available": false
}
```

### Response (`201 Created`)
```json
{
  "endpoint_id": "ep_019ab...",
  "agent_token": "andhak_ag_...",
  "credential_id": "cred_...",
  "policy": {
    "policy_id": "pol_default_windows",
    "version": 1,
    "heartbeat_seconds": 15,
    "batch_max_events": 100,
    "flush_interval_ms": 2000,
    "fim_paths": ["C:\\Windows\\System32\\drivers\\etc"],
    "exclusions": ["*.tmp", "*.log"]
  }
}
```

---

## 2. Heartbeat & Command Polling (`POST /api/v1/agent/heartbeat`)

Sent every `heartbeat_seconds` (default 15 s). Reports sensor health and receives pending policy updates or analyst-approved response commands.

### Request
```json
{
  "endpoint_id": "ep_019ab...",
  "agent_version": "0.1.0",
  "uptime_seconds": 3600,
  "cpu_percent": 14.2,
  "memory_used_mb": 6420,
  "memory_total_mb": 16384,
  "disk_used_percent": 58.4,
  "agent_rss_mb": 18.5,
  "spool_queue_depth": 0,
  "policy_version": 1,
  "sensors": {
    "process": "ready",
    "network": "ready",
    "filesystem": "ready",
    "system": "ready",
    "sysmon": "unavailable"
  }
}
```

### Response (`200 OK`)
```json
{
  "server_time": "2026-11-26T17:10:00Z",
  "policy_update_available": false,
  "pending_commands": [
    {
      "action_id": "act_019ac...",
      "action_type": "quarantine_file",
      "target_value": "C:\\Users\\Public\\suspicious.exe",
      "target_metadata": {
        "expected_sha256": "..."
      },
      "issued_at": "2026-11-26T17:09:50Z"
    }
  ]
}
```

---

## 3. Batched Telemetry Envelope (`POST /api/v1/agent/telemetry`)

### Request
```json
{
  "batch_id": "batch_uuid",
  "endpoint_id": "ep_019ab...",
  "sent_at": "2026-11-26T17:10:02Z",
  "events": [
    {
      "event_id": "evt_uuid",
      "telemetry_origin": "real_endpoint",
      "category": "process",
      "event_type": "process_start",
      "occurred_at": "2026-11-26T17:10:01.412Z",
      "dedup_hash": "sha256_of_canonical_fields",
      "process": {
        "process_guid": "{ep_019ab...}-12400-1337700000",
        "parent_process_guid": "{ep_019ab...}-4120-1337699900",
        "pid": 12400,
        "ppid": 4120,
        "name": "powershell.exe",
        "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -NoProfile -EncodedCommand ...",
        "user_context": "WORKSTATION-01\\Analyst",
        "sha256": "e3b0c442...",
        "signature_status": "valid",
        "signer_subject": "Microsoft Windows",
        "started_at": "2026-11-26T17:10:01.412Z"
      },
      "network": null,
      "filesystem": null,
      "system": null
    }
  ]
}
```

### Category-Specific Sub-Payloads

- **`network` (`socket_observed`):** `protocol` (`tcp|udp`), `local_addr`, `local_port`, `remote_addr`, `remote_port`, `state`, `pid`, `process_name`, `process_guid`. **No packet payloads or credentials are ever collected.**
- **`filesystem` (`file_created | file_modified | file_deleted | file_renamed`):** `file_path`, `previous_path` (for renames), `sha256` (null on delete or locked/oversized >25 MB), `size_bytes`, `signature_status`, `modified_at`.
- **`system` (`host_metrics`):** `cpu_percent`, `memory_used_mb`, `memory_total_mb`, `disk_used_percent`, `agent_rss_mb`, `os_version`, `uptime_seconds`.
- **`sysmon` (`sysmon_event`):** `sysmon_event_id` (e.g., `1`, `3`, `11`, `13`, `22`), `record_id`, `raw_fields`.

### Backpressure & Deduplication Rules
- **Backend `429 Too Many Requests` / `503 Service Unavailable`:** Agent honors `Retry-After` header, retains batch in local SQLite spool, applies exponential backoff (`1s -> 2s -> 4s ... max 60s`) with +/-20% jitter.
- **Deduplication:** Agent computes `dedup_hash` over `(category, event_type, canonical_target, 1-second_bucket or record_id)`. Backend enforces `UNIQUE(endpoint_id, dedup_hash)` and returns `accepted` + `duplicate_skipped` counts cleanly (`200 OK` / `202 Accepted`).

---

## 4. Command Execution Receipt (`POST /api/v1/agent/commands/{action_id}/ack`)

```json
{
  "endpoint_id": "ep_019ab...",
  "action_id": "act_019ac...",
  "status": "executed",
  "executed_at": "2026-11-26T17:10:05Z",
  "verification": {
    "sha256_before": "abc...",
    "sha256_after": "abc...",
    "vault_path": "C:\\ProgramData\\AndhakEDR\\quarantine\\quar_019ac.vault",
    "original_path_removed": true
  },
  "error": null
}
```
