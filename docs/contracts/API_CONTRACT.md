# ANDHAK EDR — REST & WebSocket API Contract

**Base URL (Local Default):** `http://127.0.0.1:8010`  
**API Prefix:** `/api/v1`  
**Content Type:** `application/json`

---

## 1. Authentication & RBAC Matrix

| Surface | Auth Mechanism | Roles / Scope |
| :--- | :--- | :--- |
| **Agent Endpoints** (`/api/v1/agent/heartbeat`, `/telemetry`, `/policy`, `/commands/*/ack`) | `Authorization: Bearer <agent_token>` + `X-Endpoint-ID` | Scoped per-endpoint only |
| **Agent Enrollment** (`/api/v1/agent/enroll`) | One-time `bootstrap_token` | Single-use endpoint registration |
| **Analyst / Console REST** | `Authorization: Bearer <jwt>` | `readonly_demo`, `analyst`, `responder`, `admin` |
| **SOC Bridge** (`/api/v1/soc-bridge/*`) | `X-ANDHAK-Signature` (HMAC-SHA256 + timestamp) | Mutual EDR <-> SOC bridge |
| **Public Demo Mode** (`ANDHAK_DEMO_MODE=true`) | Read-only demo session or unauthenticated read-only | Strictly `GET` demo endpoints; all `POST/PUT/DELETE` mutations blocked (`403`) |

### Role Permissions
- **`readonly_demo`:** Read-only access to `/api/v1/demo/*` and `GET` views over `recorded_demo` data.
- **`analyst`:** Read all telemetry/alerts/incidents/FIM/malware; run threat hunting queries, deterministic triage, forensic export, and create **response proposals** (`pending_approval`). Cannot approve or execute containment.
- **`responder`:** All `analyst` permissions + approve/reject/rollback `response_actions` and quarantine restorations.
- **`admin`:** All `responder` permissions + manage users, enrollment tokens, policies, retention rules, threat-intel external policy flags, and SOC bridge settings.

---

## 2. REST Endpoints

### Health & System
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Public | API readiness, DB status, active mode (`live` / `demo`), version |
| `POST` | `/api/v1/auth/login` | Public | Issue JWT access token for analyst/responder/admin |
| `GET` | `/api/v1/auth/me` | JWT | Current user identity & RBAC role |

### Agent Control Plane
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/agent/enrollment-tokens` | `admin` | Generate one-time endpoint enrollment token |
| `POST` | `/api/v1/agent/enroll` | Bootstrap | Enroll new endpoint and issue scoped agent credential |
| `POST` | `/api/v1/agent/heartbeat` | Agent | Update endpoint liveness/metrics & retrieve pending commands |
| `POST` | `/api/v1/agent/telemetry` | Agent | Ingest batched normalized events (backpressure & dedup) |
| `GET` | `/api/v1/agent/policy` | Agent | Pull active policy version, FIM paths, and exclusions |
| `POST` | `/api/v1/agent/commands/{action_id}/ack` | Agent | Submit command execution result & verification metadata |

### Endpoints & Telemetry Views
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/overview` | `analyst+` | Fleet posture KPIs, alert counts, trends, agent health summary |
| `GET` | `/api/v1/endpoints` | `analyst+` | List enrolled endpoints with OS, version, status, heartbeat, active alerts |
| `GET` | `/api/v1/endpoints/{endpoint_id}` | `analyst+` | Detailed host posture, running processes, sockets, FIM, alerts, responses |
| `GET` | `/api/v1/telemetry/events` | `analyst+` | Searchable/filterable telemetry stream (`endpoint_id`, `category`, `process`, `sha256`, `ip`, `domain`, `severity`, `origin`, `from`, `to`) |

### Detection, FIM, Malware & Threat Intel
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/detections/alerts` | `analyst+` | List/filter detection alerts (`severity`, `confidence`, `risk_score`, `source`, `mitre`) |
| `PATCH` | `/api/v1/detections/alerts/{alert_id}` | `analyst+` | Update alert status (`investigating`, `resolved`, `false_positive`) |
| `GET` | `/api/v1/detections/rules` | `analyst+` | Catalog of YARA-X, EMBER, FIM, behavioral, and IOC rules with attribution |
| `GET` | `/api/v1/fim/status` | `analyst+` | Protected directories, baseline state, drift summary |
| `POST` | `/api/v1/fim/baselines` | `admin` | Capture or refresh authorized FIM baseline for endpoint |
| `GET` | `/api/v1/fim/events` | `analyst+` | Unauthorized modifications, hash diffs, signature checks |
| `GET` | `/api/v1/malware/analyses` | `analyst+` | Static analysis history (YARA-X + EMBER + Authenticode + IOC reputation) |
| `POST` | `/api/v1/malware/scan` | `analyst+` | On-demand in-memory PE/file scan via YARA-X + EMBER + signature inspection |
| `GET` | `/api/v1/intel/iocs` | `analyst+` | Manage local IOC indicators & provenance |
| `POST` | `/api/v1/intel/iocs` | `analyst+` | Add IOC (`ip`, `domain`, `url`, `file_hash`) |
| `DELETE` | `/api/v1/intel/iocs/{ioc_id}` | `responder+` | Remove IOC |

### Correlation, Attack Graph, Forensics & Deterministic Investigation
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/incidents` | `analyst+` | List correlated incidents with severity, confidence, and risk score |
| `GET` | `/api/v1/incidents/{incident_id}` | `analyst+` | Incident detail, correlated alerts, process tree, chronological timeline, ATT&CK evidence |
| `GET` | `/api/v1/incidents/{incident_id}/graph` | `analyst+` | React Flow node/edge payload (`process`, `file`, `socket`, `endpoint`, `alert`) |
| `POST` | `/api/v1/incidents/{incident_id}/investigate` | `analyst+` | Run deterministic investigation/triage engine and persist cited report |
| `POST` | `/api/v1/incidents/{incident_id}/forensics` | `analyst+` | Collect/seal SHA-256 verified forensic evidence bundle |
| `GET` | `/api/v1/forensics/{bundle_id}` | `analyst+` | Download/inspect forensic evidence bundle with manifest |

### Controlled Response, Quarantine & Audit
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/responses` | `analyst+` | Pending approvals, active containments, completed responses |
| `POST` | `/api/v1/responses` | `analyst+` | Create response proposal (validates target against protected denylist) |
| `POST` | `/api/v1/responses/{action_id}/decision` | `responder+` | Approve or reject pending response action |
| `POST` | `/api/v1/responses/{action_id}/rollback` | `responder+` | Initiate controlled recovery (un-isolate endpoint / restore quarantined file) |
| `GET` | `/api/v1/quarantine` | `analyst+` | List quarantined files with pre/post SHA-256 and status |
| `GET` | `/api/v1/audit` | `analyst+` | Query tamper-evident response & security audit log |
| `GET/PUT` | `/api/v1/policies` | `admin` | Read/update endpoint policies and retention settings |

### Public Read-Only Demo Endpoints
| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/demo/scenarios` | Public | List clearly labeled recorded demonstration scenarios |
| `POST` | `/api/v1/demo/replay/{scenario_id}` | Public (demo-safe) | Reset/start read-only WebSocket replay stream of recorded telemetry |

---

## 3. WebSocket Contracts

| Endpoint | Direction | Payload Structure |
| :--- | :--- | :--- |
| `/ws/telemetry` | Server -> Client | `{"type": "telemetry.event", "origin": "real_endpoint\|recorded_demo", "data": {...}}` |
| `/ws/alerts` | Server -> Client | `{"type": "alert.created \| incident.updated", "origin": "...", "data": {...}}` |
| `/ws/responses` | Server -> Client | `{"type": "response.pending \| response.executed \| response.rolled_back", "data": {...}}` |

All WebSocket handlers support query filters (`endpoint_id`, `origin`), periodic JSON `ping`/`pong` keepalives, and clean client reconnection state signaling.

---

## 4. Standard Error Envelope

```json
{
  "error": {
    "code": "PROTECTED_TARGET_BLOCKED",
    "message": "Target process 'lsass.exe' is protected and cannot be terminated.",
    "detail": {"pid": 912, "rule": "protected_os_process"}
  }
}
```
HTTP mappings: `400` malformed request, `401` invalid credentials, `403` insufficient RBAC role or read-only demo violation, `404` resource missing, `409` duplicate or already-decided approval, `422` validation or protected-target block, `429` backpressure limit, `503` subsystem unavailable.
