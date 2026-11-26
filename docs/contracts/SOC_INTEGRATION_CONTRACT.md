# ANDHAK EDR <-> ANDHAK SOC Integration Contract

**Purpose:** Define the modular, non-destructive contract connecting **ANDHAK EDR** (`D:\Personal Projects\Andhak EDR`) with the existing **ANDHAK SOC** console (`D:\Personal Projects\Andhak SOC`).  
**Design Rule:** ANDHAK SOC continues to operate standalone without breaking changes. All integration flows use versioned adapters and documented contracts.

---

## 1. Verified ANDHAK SOC Baseline Contracts

Inspection of `D:\Personal Projects\Andhak SOC` confirmed the following existing schemas and constraints:
- **SOC Event Record (`services.py` `events` table):**
  `event_id`, `timestamp`, `source_system`, `event_type`, `severity` (`critical|high|medium|low|info`), `summary`, `endpoint`, `evidence_reference`, `details`, `source_ip`.
- **SOC Indicator Record (`services.py` `indicators` table):**
  `value`, `kind` (`ip|domain|url|file_hash`), `severity`, `description`, `created_at`.
- **SOC Investigation Context (`agent/routes.py`):**
  `context: {kind: "alert" | "endpoint" | "graph" | "none", id: string, label: string}`.
- **SOC Graph Node IDs (`agent/graph.py`):**
  `endpoint:<host>`, `process:<name>`, `ip:<address>`, `ioc:<value>`, `alert:<id>`, and ATT&CK tags formatted as `t1059.001` (lowercase).
- **SOC Response Gateway (`agent/gateway.py`):**
  Only `add_ioc_watchlist` executes inside SOC; `isolate_endpoint`, `block_network_indicator`, `terminate_process`, and `revoke_session` currently fail with `"No connector"`.

---

## 2. EDR -> SOC Event & Alert Mapping

When `ANDHAK_SOC_ENABLED=true`, the EDR SOC-Bridge module transforms EDR `alerts` and `incidents` into SOC's canonical `events` envelope:

| ANDHAK EDR Field | ANDHAK SOC `events` Column | Transformation Rule |
| :--- | :--- | :--- |
| `"edr-" + alert_id` | `event_id` | Deterministic prefixed primary key preventing collision with `win-*`, `sigma-*`, `scan-*` |
| `detected_at` | `timestamp` | UTC ISO-8601 string |
| `"ANDHAK EDR · " + detection_source` | `source_system` | Identifies `yara_x`, `ember`, `fim`, `behavioral`, `ioc`, `sysmon` |
| `rule_id` | `event_type` | Preserves rule attribution |
| `severity` | `severity` | Exact enum match (`critical|high|medium|low|info`) |
| `rule_name + " (" + hostname + ")"` | `summary` | Human-readable SOC alert row |
| `hostname` (`endpoint_id`) | `endpoint` | Matches SOC `endpoint:<hostname>` graph node convention |
| `process_name + " · PID " + pid + " · " + sha256[:12]` | `evidence_reference` | Structured forensic handle |
| `evidence_summary + " | Confidence: ... | ATT&CK: ..."` | `details` | Secret-redacted summary; includes MITRE tags |
| `remote_ip` (if external IPv4/IPv6) | `source_ip` | Populated only for public remote peers so SOC's offline GeoIP map plots accurately |

---

## 3. Bidirectional IOC Synchronization

- **EDR <-> SOC Sync Endpoint (`GET /api/v1/soc-bridge/indicators`, `POST /api/v1/soc-bridge/indicators/sync`):**
  - Reuses SOC's exact classification types (`ip`, `domain`, `url`, `file_hash`) and severity values (`critical`, `high`, `medium`, `low`, `info`).
  - Uses normalized lowercase values (`COLLATE NOCASE` parity) and preserves origin attribution (`edr_local`, `soc_watchlist`, `malwarebazaar`, `abuseipdb`).
  - Never syncs private host file paths or sensitive internal hostnames as external IOCs.

---

## 4. Fulfilling SOC's Missing Containment Connectors

Where ANDHAK SOC's `gateway.py` previously stopped at `ACTIONS_WITHOUT_CONNECTOR`, ANDHAK EDR exposes an authenticated connector bridge:

### Endpoint: `POST /api/v1/soc-bridge/responses/request`
- **Headers:** `X-ANDHAK-Timestamp`, `X-ANDHAK-Signature` (`HMAC-SHA256(shared_secret, timestamp + "." + body)`).
- **Accepted Actions:** `isolate_endpoint`, `release_isolation`, `terminate_process`, `quarantine_file`, `block_network_indicator`. (Identity-provider `revoke_session` remains explicitly unsupported and returns `501` / `"no identity connector"` honestly.)
- **Payload:**
```json
{
  "soc_approval_id": "appr_123...",
  "action_type": "isolate_endpoint",
  "endpoint_hostname": "TUF-DHARM007",
  "target_value": "TUF-DHARM007",
  "reason": "Triggered via ANDHAK SOC investigation",
  "soc_actor": "Local analyst"
}
```
- **Governance Invariant:** A request arriving from ANDHAK SOC does **not** bypass EDR RBAC or target validation. It creates a `pending_approval` (or executes only when explicitly signed with a pre-authorized `responder`/`admin` token), runs the protected-target denylist check, executes via the Rust agent, records the SHA-256 audit chain entry, and returns a verification receipt (`executed`, `verification`, `audit_id`) back to SOC.

---

## 5. SOC-Side Non-Invasive Integration Pattern (Stage 06)

Because `ANDHAK SOC` binds strictly to `127.0.0.1:8000` without authentication:
1. All EDR-to-SOC HTTP bridge requests remain strictly on loopback (`127.0.0.1`) or an authenticated private tunnel with HMAC signatures (`ANDHAK_SOC_BRIDGE_SHARED_SECRET`).
2. Stage 06 adds an optional, backwards-compatible bridge route set in SOC (or an external SOC connector worker writing normalized `edr-*` rows and relaying approved actions) without altering existing standalone SOC pages, local collection, or SQLite tables.
3. UI integration preserves identical ANDHAK brand assets (`andhak-logo.png`), crimson/charcoal palette discipline, and entity handoff links (`endpoint:<hostname>`, `process:<name>`, `ip:<addr>`, `ioc:<value>`).
