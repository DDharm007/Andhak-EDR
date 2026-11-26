# ANDHAK EDR — Security Threat Model

**Scope:** Threat analysis, trust boundaries, authentication/authorization architecture, response safety controls, and data privacy invariants across all six EDR subsystems.

---

## 1. Trust Boundaries

1. **TB-1: Endpoint OS <-> Rust Sensor (`andhak-edr-agent`)**
   - Unprivileged Windows processes may attempt to tamper with files, launch obfuscated commands, or exhaust sensor buffers.
   - Sensor privilege boundary depends on service account rights (`SYSTEM`/Administrator vs standard user). Missing privileges must degrade sensor coverage honestly, never silently spoof data.
2. **TB-2: Endpoint Sensor <-> Management Backend (`HTTPS + Scoped Auth`)**
   - Network transport between endpoints and the EDR API is untrusted unless authenticated and integrity-checked.
   - Risk of spoofed telemetry, rogue enrollment, or unauthorized response command injection.
3. **TB-3: Operator Browser <-> EDR Backend (`JWT + RBAC + Origin Checks`)**
   - Operators trigger high-impact containment actions (kill process, quarantine file, network isolation).
   - Risk of privilege escalation (`analyst` or `readonly_demo` invoking `responder`/`admin` actions), CSRF, or cross-site WebSocket hijacking.
4. **TB-4: EDR Backend <-> ANDHAK SOC Bridge (`Loopback / HMAC`)**
   - Existing ANDHAK SOC runs unauthenticated on `127.0.0.1:8000`.
   - EDR must never expose SOC's unauthenticated API directly to external networks and must authenticate bridge commands with HMAC + timestamp replay protection.
5. **TB-5: EDR Backend <-> External Intelligence Feeds (Policy-Gated)**
   - Risk of leaking internal hostnames, file contents, or proprietary binaries to third-party APIs (VirusTotal, MalwareBazaar, AbuseIPDB).

---

## 2. STRIDE Threat Matrix & Controls

| Threat | Category | Affected Component | Concrete Control in ANDHAK EDR |
| :--- | :--- | :--- | :--- |
| **Rogue agent impersonating endpoint** | Spoofing | Agent API | One-time `bootstrap_token` exchanged once; scoped per-endpoint `agent_token` stored SHA-256-hashed (`agent_credentials`); zero credentials compiled into Rust binary. |
| **Tampering with offline spool or telemetry** | Tampering | Agent / Ingest | `X-Payload-SHA256` payload digest check; deduplication key uniqueness; SQLite WAL integrity; strict Pydantic v2 validation discarding unknown/oversized payloads. |
| **Repudiation of containment actions** | Repudiation | Response Engine | Append-only `audit_logs` with SHA-256 hash chain (`entry_hash = sha256(prev_hash + canonical_record)`); captures `actor_id`, `role`, `decision_note`, `verification_json`, and UTC timestamps. |
| **Exfiltration of private files/secrets** | Info Disclosure | Intel / Logs | `ANDHAK_INTEL_EXTERNAL_ENABLED=false` and `ANDHAK_INTEL_ALLOW_FILE_UPLOAD=false` by default; only hash/IP/domain metadata queried when enabled; secret-regex redaction (`password=`, `token=`, `Bearer ...`) applied before storing command lines or rendering reports. |
| **Telemetry flood exhausting memory/disk** | Denial of Service | Sensor & Backend | Bounded channel capacity in Tokio; max 256 MB SQLite spool cap with informational-first eviction; HTTP `429` backpressure + exponential backoff; API batch size limit (max 500 events/request). |
| **Accidental host bricking via containment** | Elevation / Safety | Response Executor | Immutable **Protected Target Denylist** blocks termination of `System`, `smss.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `svchost.exe` (critical PIDs), and `andhak-edr-agent`; network isolation preserves explicit firewall rule permitting backend IP/port for recovery/rollback. |
| **Demo user triggering live mutation or viewing live host** | Elevation of Privilege | Demo Mode | `ANDHAK_DEMO_MODE=true` mounts isolated demo DB (`recorded_demo`), disables enrollment/response/config routers (`403 Forbidden`), and forces `readonly_demo` RBAC role. |
| **Malicious PE/YARA input crashing parser** | Tampering / DoS | Detection Engine | Strict 20 MB scan cap (`MAX_FILE_BYTES`), bounded `pefile` parsing (`fast_load` + exception isolation), in-memory scanning without writing untrusted uploads into executable paths. |

---

## 3. Authentication & Authorization Design

- **Password Storage:** `Argon2id` (`argon2-cffi`) per-user salted hashes in `users`; no plaintext credentials anywhere in repository or logs.
- **Session Tokens:** HS256 JWT (`PyJWT`) signed with `ANDHAK_EDR_JWT_SECRET` (minimum 32 random bytes enforced outside test/dev), short TTL, strict `sub`, `role`, `exp`, `jti` claims.
- **RBAC Enforcement:** FastAPI `Depends(require_role(...))` on every protected route:
  - `readonly_demo`: Read-only demo datasets only.
  - `analyst`: Read telemetry/alerts/incidents, run hunts, trigger deterministic investigations, propose responses.
  - `responder`: Approve/reject/rollback responses and restore quarantined files.
  - `admin`: Manage users, enrollment tokens, FIM policies, retention, external intel gates, and SOC bridge config.
- **Agent Authentication:** Separate dependency `verify_agent_credential` checking `X-Endpoint-ID` against active (`revoked = 0`) SHA-256 hashed `agent_credentials` in constant time (`hmac.compare_digest`).

---

## 4. Quarantine Vault & Isolation Safety Rules

1. **Quarantine:** Files are copied to a dedicated non-executable vault directory (`%ProgramData%\AndhakEDR\quarantine\` or configured local vault), verified with `sha256_before == sha256_after` before unlinking the original path, stored under a non-executable `.vault` extension with restricted ACLs, and XOR/envelope-wrapped or header-neutralized so Windows cannot accidentally execute them.
2. **Isolation:** Endpoint isolation creates scoped Windows Filtering Platform / Windows Firewall rules blocking general inbound/outbound traffic **except** loopback (`127.0.0.1/8`, `::1`), DHCP/DNS if required for local recovery, and the explicit EDR Management Backend IP + port so the analyst can inspect telemetry and issue `release_isolation` rollback at any time.
3. **No Stealth / No Anti-AV Tampering:** The agent never uses rootkit hooks, hidden persistence, undocumented kernel manipulation, or Defender/security-product disabling.
