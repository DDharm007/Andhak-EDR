# ANDHAK EDR — Persistent Development Log

---

## Stage 01 — Architecture & Engineering Foundation
**Date:** 2026-11-26  
**Milestone Status:** Complete (pending final milestone commit/push)  
**Author / Operator:** Principal Engineering Agent + Dharm Patel (`DDharm007`)

### 1. Summary of Work Completed
1. **Workspace & Repository Inspection:**
   - Verified `D:\Personal Projects\Andhak EDR` was empty and initialized `git` on branch `main`, linked to `https://github.com/DDharm007/Andhak-EDR.git` (confirmed reachable & empty via `git ls-remote`).
   - Audited existing [Andhak SOC](file:///D:/Personal%20Projects/Andhak%20SOC) (`f2fe618`), mapping its FastAPI endpoints, SQLite schemas (`events`, `indicators`, `network_connections`, `agent_*`), `yara_scan.py`, `sigma_rules.py`, `agent/gateway.py` approval limits, `agent/graph.py` MITRE/entity IDs, and frontend tokens.
   - Pulled official ANDHAK branding assets (`andhak-logo.png`, `favicon.svg`) and `LICENSE` from `Andhak SOC` without modifying `Andhak SOC`.
   - Audited local Windows 11 environment: confirmed `rustc 1.100.0` (`x86_64-pc-windows-gnu`), `cargo 1.100.0`, `python 3.12.10`, `node v24.21.0`, `npm 11.19.0`, `playwright 1.63.0`, and `yara-x 1.24.0` (verified in SOC `.venv`); confirmed `psql`, `redis-server`, `docker`, `gh`, `ruff`, `cl.exe`, and Sysmon are currently absent locally.
2. **Scope Alignment with Project Owner:**
   - Confirmed **local-first SQLite WAL database** + in-process `asyncio` event bus as primary local runtime (retaining SQLAlchemy/PostgreSQL/Redis schema parity).
   - Confirmed **no generative AI / LLM runtime** (`"without ai"`); designed deterministic evidence-cited investigation & triage engine for Stage 04 / View 11.
3. **Architecture, Contracts & Governance Delivered:**
   - Created repository hygiene files: [`.gitignore`](../.gitignore), [`.env.example`](../.env.example), [`LICENSE`](../LICENSE).
   - Created architecture & governance docs:
     - [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) (6 subsystems `A`–`F`, 4 Mermaid diagrams, retention policies, environment profiles)
     - [`docs/DECISIONS.md`](DECISIONS.md) (ADRs `001`–`007`)
     - [`docs/SECURITY_MODEL.md`](SECURITY_MODEL.md) (trust boundaries, STRIDE threat matrix, RBAC, quarantine & isolation invariants)
     - [`docs/MILESTONES.md`](MILESTONES.md) (7-stage milestone tracker)
     - [`docs/KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) (honest local Windows constraints & scope decisions)
   - Created typed contract specifications:
     - [`docs/contracts/DATABASE_SCHEMA.sql`](contracts/DATABASE_SCHEMA.sql) (20 normalized tables + indexes + provenance constraints)
     - [`docs/contracts/TELEMETRY_SCHEMA.md`](contracts/TELEMETRY_SCHEMA.md) (enrollment, heartbeat, batch telemetry, backpressure, ack contracts)
     - [`docs/contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) (REST API, RBAC matrix, WebSocket channels, standard error envelope)
     - [`docs/contracts/SOC_INTEGRATION_CONTRACT.md`](contracts/SOC_INTEGRATION_CONTRACT.md) (EDR-to-SOC event mapping, IOC sync, approval connector fulfillment)

### 2. Files Added in Stage 01
- `.gitignore`, `.env.example`, `LICENSE`
- `frontend/public/andhak-logo.png`, `frontend/public/favicon.svg`, `docs/assets/andhak-logo.png`
- `docs/ARCHITECTURE.md`, `docs/DECISIONS.md`, `docs/SECURITY_MODEL.md`, `docs/MILESTONES.md`, `docs/KNOWN_LIMITATIONS.md`, `docs/DEVELOPMENT_LOG.md`
- `docs/contracts/DATABASE_SCHEMA.sql`, `docs/contracts/TELEMETRY_SCHEMA.md`, `docs/contracts/API_CONTRACT.md`, `docs/contracts/SOC_INTEGRATION_CONTRACT.md`

### 3. Verification & Checks Executed (Stage 01 Gate)
- SQL DDL validation against Python 3.12 `sqlite3` in-memory engine (`PRAGMA foreign_keys = ON`): **PASS** (`22` tables, `24` indexes created; `users` and `endpoints` FK/CHECK insert probe passed).
- Required Stage 01 deliverables check: **PASS** (`16` files verified present).
- Relative Markdown link check across `docs/`: **PASS** (`0` broken links).
- Secret hygiene & repo diff check: **PASS** (`.env` absent, `.env.example` placeholder-only, no secrets detected; `Andhak SOC` working tree clean).

### 4. Bugs / Constraints Discovered
- Local Windows host lacks `cl.exe` MSVC linker in standard VS paths; `x86_64-pc-windows-gnu` is active, requiring `rustls` rather than `openssl-sys` in Stage 02.
- Sysmon is not installed locally; Stage 02 agent must gracefully report Sysmon channel `unavailable`.

### 5. Remaining Work
- **Stage 02:** Build Rust endpoint sensor (`agent/`) + minimal FastAPI ingestion receiver to prove end-to-end real Windows telemetry collection and transport.
- **Stages 03–07:** Detection/FIM/EMBER, correlation/forensics/deterministic investigation, controlled response, SOC integration + 12-view React console, testing, screenshots, and release.

---

## Project Handoff Summary (End of Stage 01 -> Ready for Stage 02)
- **Repository Root:** `D:\Personal Projects\Andhak EDR` (`main` branch -> `https://github.com/DDharm007/Andhak-EDR.git`).
- **Companion SOC Path:** `D:\Personal Projects\Andhak SOC` (read-only reference; do not break standalone SOC behavior).
- **Database Strategy:** SQLite `WAL` primary local database defined in `docs/contracts/DATABASE_SCHEMA.sql`; all schemas preserve PostgreSQL parity via SQLAlchemy 2.x.
- **No-AI Policy:** Zero LLM/generative AI modules; all investigation/triage features must be deterministic, rule-based, and evidence-cited.
- **Next Immediate Action (Stage 02):** Scaffold `agent/` Cargo workspace using `stable-x86_64-pc-windows-gnu` + `tokio` + `serde` + `sysinfo` + `windows` + `notify` + `sha2` + `reqwest` (`rustls-tls`) + `rusqlite` (`bundled`), implement portable collector traits and Windows collectors (process/network/filesystem/system/Sysmon-probe), plus a lightweight Stage 02 FastAPI ingest verification endpoint implementing `docs/contracts/TELEMETRY_SCHEMA.md`.

---

## Stage 02 — Rust Endpoint Sensor
- **Date:** 2026-11-26
- **Milestone Status:** Complete
- **Author / Operator:** Principal Engineering Agent + Dharm Patel (`DDharm007`)

### 1. Summary of Work Completed
1. **Rust Sensor Core (`agent/src/`):**
   - [`config.rs`](../agent/src/config.rs): TOML + env config, non-loopback HTTP rejection guard, externalized `AgentState` persistence (no embedded credentials in binaries).
   - [`models.rs`](../agent/src/models.rs): Normalized telemetry contracts (`TelemetryBatchRequest`, `TelemetryEventIn`, `ProcessPayload`, `NetworkPayload`, `FilesystemPayload`, `SystemPayload`, `HeartbeatRequest`) and deterministic `compute_dedup_hash` / `make_process_guid`.
   - [`spool.rs`](../agent/src/spool.rs): Local SQLite WAL offline ring spool (`agent-spool.sqlite3`) with deduplication (`UNIQUE(dedup_hash)`) and informational-first bounded backpressure eviction.
   - [`transport.rs`](../agent/src/transport.rs): HTTPS/TLS client (`reqwest` + `rustls`), custom CA bundle validation, `X-Payload-SHA256` digest headers, `429`/`503` `Retry-After` handling, and exponential backoff.
   - [`main.rs`](../agent/src/main.rs): `enroll`, `status`, `collect-once`, and `run` commands with stderr structured JSON `tracing` logs, bounded channel backpressure, policy polling, and `Ctrl+C` flush shutdown.
2. **Portable Collectors & Native Windows Implementation (`agent/src/collectors/`):**
   - [`mod.rs`](../agent/src/collectors/mod.rs) & [`portable_fallback.rs`](../agent/src/collectors/portable_fallback.rs): OS-agnostic `ProcessCollector`, `NetworkCollector`, `SystemCollector`, `EventLogCollector` traits.
   - [`windows.rs`](../agent/src/collectors/windows.rs): Real Windows process delta monitoring (PID/PPID, parent GUID correlation, executable SHA-256 cache, command lines, user context), Win32 `WinVerifyTrust` + `CryptCATAdmin*` Windows Catalog signature verification + signer subject extraction, Win32 IP Helper `GetExtendedTcpTable`/`GetExtendedUdpTable` (IPv4+IPv6 TCP/UDP sockets mapped to owning PID/process), CPU/RAM/disk/RSS metrics, `TokenElevation` probe, and honest `Microsoft-Windows-Sysmon/Operational` probe (`unavailable` when not installed).
   - [`filesystem.rs`](../agent/src/collectors/filesystem.rs): `notify` (`ReadDirectoryChangesW`) filesystem watcher with `globset` exclusions, 750ms sliding-window deduplication, SHA-256 hashing, and PE Authenticode probing.
3. **Stage 02 Ingestion Backend (`backend/app/`):**
   - [`config.py`](../backend/app/config.py), [`db.py`](../backend/app/db.py), [`schemas.py`](../backend/app/schemas.py), [`services/ingest.py`](../backend/app/services/ingest.py), [`routers/agent.py`](../backend/app/routers/agent.py), [`main.py`](../backend/app/main.py), [`cli.py`](../backend/app/cli.py).
   - Enforces single-use bootstrap token hashing, constant-time agent credential verification, payload SHA-256 integrity checks, secret redaction, and SQLite WAL persistence against Stage 01 DDL.
4. **Setup Documentation:** [`docs/AGENT_SETUP.md`](AGENT_SETUP.md).

### 2. Bugs Discovered & Resolved During Stage 02
- **Windows Catalog Signatures:** Modern Windows 11 system binaries (`notepad.exe`, `powershell.exe`) use Windows Security Catalog signing rather than embedded PE PKCS7 blobs, initially returning `TRUST_E_NOSIGNATURE` under `WTD_CHOICE_FILE`. Implemented `CryptCATAdminCalcHashFromFileHandle` + `CryptCATAdminEnumCatalogFromHash` + `WTD_CHOICE_CATALOG` verification and `.cat` signer extraction.
- **Structured Logging Stream Isolation:** `tracing_subscriber` initially wrote JSON logs to `stdout`, mixing logs with CLI JSON output. Redirected tracing output to `stderr`.
- **Startup Latency on Initial Baseline:** Initial binary hashing/WinVerifyTrust sweep across ~250 live processes delayed first loop ticks; moved baseline snapshot before `tokio::select!` and tightened `fs_tick` to `300ms`.
- **Self-Signed TLS Validation:** `rustls` rejected self-signed `ca=True` leaf certs; updated E2E test fixture to generate a proper Root CA + `ExtendedKeyUsage(SERVER_AUTH)` leaf cert.

### 3. Tests Executed & Results
- `cargo fmt --manifest-path agent\Cargo.toml --check`: **PASS**
- `cargo clippy --manifest-path agent\Cargo.toml --all-targets -- -D warnings`: **PASS** (`0` warnings)
- `cargo test --manifest-path agent\Cargo.toml`: **PASS** (`7` unit tests passed in `5.64s`, including live Windows process/socket/metric capture and `notepad.exe` catalog signature verification)
- `cargo build --manifest-path agent\Cargo.toml`: **PASS**
- `ruff check backend\app backend\tests`: **PASS** (`All checks passed!`)
- `pytest backend\tests -v`: **PASS** (`3` passed in `28.40s`, including live HTTPS compiled Rust agent enrollment, `collect-once`, and live `ReadDirectoryChangesW` filesystem upload E2E)

### 4. Handoff Summary -> Ready for Stage 03
- **Stage 02 Gate Passed:** Compiled Rust sensor collects real Windows process, network, filesystem, and system telemetry and persists batches over verified HTTPS/TLS to the local SQLite WAL backend.
- **Stage 03 Next Steps:** Implement `backend/app/detection/` modules: YARA-X scanner (`yara-x>=1.24`), EMBER static PE feature extractor & versioned classifier, FIM baseline/drift/signature engine, 8 windowed behavioral rules, policy-gated IOC intelligence, and transparent risk scoring (`severity` vs `confidence`).

---

## Stage 03 — Detection & Integrity Intelligence
- **Date:** 2026-11-26
- **Milestone Status:** Complete
- **Author / Operator:** Principal Engineering Agent + Dharm Patel (`DDharm007`)

### 1. Summary of Work Completed
1. **YARA-X Scanner (`backend/app/detection/yara_scanner.py` & `backend/app/rules/yara/andhak_edr_rules.yar`):**
   - Integrated native `yara-x` (`>=1.24`, BSD-3-Clause preserved in `THIRD_PARTY_LICENSES/YARA-X-BSD-3-Clause.txt`) with syntax validation, 20 MB bounded in-memory scanning, rule attribution metadata, and curated local rules (`EICAR`, encoded PowerShell, PE injection API triplet, ransom-note indicators, LSASS credential dump markers, and download-execute script stagers).
2. **EMBER Static PE Classifier (`backend/app/detection/ember_classifier.py`):**
   - Built `pefile` + `numpy` 2381-dim EMBER-aligned feature extraction (byte histogram, 16x16 byte-entropy, printable strings, PE header/sections/imports/exports/data directories) with finite-value validation and calibrated non-generative `HistGradientBoostingClassifier` (`andhak-ember-gbdt-v1.0`), explicit dataset/model provenance, and non-conclusive advisory caveats.
3. **File Integrity Monitoring (`backend/app/detection/fim_engine.py`):**
   - Implemented directory SHA-256 baseline creation (`fim_baselines`), drift comparison (`created`, `modified`, `deleted`, `renamed`, `signature_changed`), Authenticode degradation detection, and FIM alert emission (`fim_events`).
4. **Stateful Behavioral Engine (`backend/app/detection/behavioral_engine.py`):**
   - Implemented all eight scenarios (`BEH-001` through `BEH-008`), including `winword.exe -> powershell.exe` ancestry inspection, Temp drop + execution multi-event correlation, and 60s sliding-window rapid file-write burst detection (`BEH-007`).
5. **Threat Intelligence & Scoring (`intel_service.py`, `scoring.py`, `pipeline.py`, `routers/detections.py`):**
   - Added local IOC store (`ip`, `domain`, `url`, `file_hash`), policy-gated MalwareBazaar/AbuseIPDB/VirusTotal adapters (disabled by default; no private file uploads), separate `severity` and `confidence` scoring, automatic detection evaluation on ingestion, and `/api/v1/{detections,fim,malware,intel}/*` endpoints.
6. **Documentation:** Added [`docs/DETECTION_ARCHITECTURE.md`](DETECTION_ARCHITECTURE.md).

### 2. Bugs Discovered & Resolved During Stage 03
- **RFC 5737 Test-Net Classification in Python 3.12:** `ipaddress.ip_address("203.0.113.55").is_private` evaluates `True` in Python 3.12, causing `BEH-005` to skip documentation-range C2 tests. Replaced `is_private` check with explicit RFC 1918/ULA filtering + suspicious port triggers (`4444`, `5555`, `1337`, etc.).

### 3. Tests Executed & Results
- `ruff check backend\app backend\tests`: **PASS** (`All checks passed!`)
- `pytest backend\tests -v`: **PASS** (`7` passed in `50.56s`: Stage 02 ingest `2/2`, live HTTPS compiled Rust E2E `1/1`, Stage 03 YARA-X/EMBER/FIM/8-behavioral/IOC suite `4/4`).

### 4. Handoff Summary -> Ready for Stage 04
- **Stage 03 Gate Passed:** YARA-X, EMBER static PE scoring, FIM, all 8 behavioral scenarios, and IOC matching verified end-to-end.
- **Stage 04 Next Steps:** Implement incident correlation (`time_window`, `process_guid`, `endpoint`, `ioc`, duplicate alert grouping), multi-level process tree builder, chronological attack timeline, evidence-backed MITRE ATT&CK attribution, SHA-256-sealed forensic bundles, and **Deterministic Investigation & Automated Triage Engine** (no generative AI/LLM per ADR-002).

---

## Stage 04 — Forensics, Correlation & Threat Investigation
- **Date:** 2026-11-26
- **Milestone Status:** Complete
- **Author / Operator:** Principal Engineering Agent + Dharm Patel (`DDharm007`)

### 1. Summary of Work Completed
1. **Incident Correlation Engine (`backend/app/forensics/correlator.py`):**
   - Groups unassigned endpoint alerts by root `process_guid` ancestry, same-endpoint 30-minute time windows, and shared incident aggregates (`max severity`, `max confidence`, corroborated `risk_score`, distinct MITRE tactics/techniques, multi-stage title escalation).
   - Automatically invoked inside `ingest_telemetry_batch` (`backend/app/services/ingest.py`) and `analyze_file_bytes` (`backend/app/detection/pipeline.py`).
2. **Process Tree & React Flow Graph Builder (`backend/app/forensics/process_tree.py`):**
   - Walks ancestor and descendant `process_executions` chains (`winword.exe -> powershell.exe -> payload.exe`), attaches per-process alerts and outbound `network_sockets`, and emits React Flow node/edge payloads (`endpoint`, `process`, `alert`, `network`, `file`).
3. **Chronological Timeline & Evidence-Backed MITRE ATT&CK Mapper (`backend/app/forensics/timeline.py`):**
   - Merges incident alerts, referenced `telemetry_events`, and endpoint `fim_events` into a strictly time-sorted attack timeline.
   - Maps only observed MITRE ATT&CK techniques backed by explicit `supporting_alert_ids`, `supporting_event_ids`, and `supporting_rules` (no unverified techniques).
4. **Forensic Bundles & Deterministic Triage (`bundler.py`, `investigator.py`, `routers/forensics.py`):**
   - Generates canonical JSON evidence bundles with SHA-256 integrity seals (`manifest_sha256`) and verifies bundle hashes on retrieval (`integrity_verified`).
   - Implemented Zero-AI `run_deterministic_investigation` (`deterministic_rules_v1`) producing evidence-cited narratives, corroboration & Authenticode posture false-positive checks, and approval-gated runbook recommendations.
   - Exposed `/api/v1/incidents*`, `/api/v1/forensics/{bundle_id}`, and `/api/v1/hunting/search` routes and registered them in `backend/app/main.py`.

### 2. Tests Executed & Results
- `backend\.venv\Scripts\ruff.exe format --check backend\app backend\tests`: **PASS** (`30 files already formatted`)
- `backend\.venv\Scripts\ruff.exe check backend\app backend\tests`: **PASS** (`All checks passed!`)
- `backend\.venv\Scripts\python.exe -m pytest backend\tests -v`: **PASS** (`8` passed in `42.00s`, including `test_multi_stage_correlation_forensics_triage_and_hunting` verifying 6-event attack-chain correlation, 3-level process tree, React Flow graph, chronological timeline, MITRE evidence discipline, forensic SHA-256 tamper detection, deterministic investigation, and hunting filters).

### 3. Handoff Summary -> Ready for Stage 05
- **Stage 04 Gate Passed:** Multi-stage alerts correlate deterministically into unified incidents with React Flow graphs, tamper-evident forensic bundles, and zero-AI cited investigations.
- **Stage 05 Next Steps:** Implement JWT authentication + RBAC (`readonly_demo`, `analyst`, `responder`, `admin`), protected OS target denylist, approval-gated response engine, reversible file quarantine vault + restore, reversible endpoint isolation, SHA-256 hash-chained `audit_logs`, and Rust agent Stage 05 response execution + acknowledgment.

---

## Stage 05 — Prevention & Incident Response Engine
- **Date:** 2026-11-26
- **Milestone Status:** Complete
- **Author / Operator:** Principal Engineering Agent + Dharm Patel (`DDharm007`)

### 1. Summary of Work Completed
1. **Authentication & RBAC (`backend/app/auth.py`, `backend/app/routers/auth.py`, `backend/app/cli.py`):**
   - Implemented `Argon2id` (`argon2-cffi`) password hashing, HS256 JWT tokens (`PyJWT`), `/api/v1/auth/login`, `/api/v1/auth/me`, `/api/v1/users`, CLI `create-user`, optional env-based bootstrap admin in `init_database`, and `require_role(...)` enforcement blocking both insufficient roles and any `ANDHAK_DEMO_MODE=true` mutations (`403`).
2. **Protected Target Denylist & Safety (`backend/app/response/safety.py`):**
   - Rejects unsafe actions (`422 PROTECTED_TARGET_BLOCKED`), blocking kernel PIDs (`<=4`), protected OS processes (`system`, `lsass.exe`, `csrss.exe`, `wininit.exe`, `services.exe`, `smss.exe`, `svchost.exe`, `explorer.exe`, `andhak-edr-agent` via both metadata and `process_executions` DB lookup), Windows `System32`/`SysWOW64`/`WinSxS` paths, path traversal (`..`), and loopback/non-routable network indicators (`127.0.0.1`, `localhost`).
3. **Approval-Gated Response, Reversible Quarantine/Isolation & Policies (`response/engine.py`, `routers/responses.py`, `routers/policies.py`):**
   - Built `pending_approval -> approved/rejected -> executed/failed -> rolled_back` state machine with `409 Conflict` guards against double decisions, reversible `release_isolation` and `restore_file` rollback initiation, `quarantine_vault` tracking, and versioned `/api/v1/policies` + retention management.
4. **Tamper-Evident SHA-256 Audit Log (`backend/app/response/audit.py`):**
   - Added append-only `audit_logs` hash chain (`entry_hash = sha256(prev_hash + canonical_record)`) and full chain verification endpoint (`verify_audit_chain`).
5. **Rust Agent Stage 05 Executor (`agent/src/response.rs`, `transport.rs`, `main.rs`):**
   - Added agent-side protected target guards, XOR-obfuscated `ANDHAKQ1` `.vault` quarantine + decrypted SHA-256 verification before unlink, exact-SHA-256 restoration, PID reuse check + process termination, reversible `netsh advfirewall firewall` isolation plan (or explicit unprivileged `dry_run_unprivileged`), `poll-commands-once`, and `POST /api/v1/agent/commands/{action_id}/ack`.

### 2. Bugs Discovered & Resolved During Stage 05
- **`ProtectedTargetError` Inheritance Masking:** Initial `ProtectedTargetError(ValueError)` was caught by `except ValueError:` inside `_validate_network_target` when validating `127.0.0.1`, allowing `block_network_indicator` to succeed (`201`) instead of returning `422`. Changed `ProtectedTargetError` to inherit directly from `Exception` and separated IP parsing from validation.
- **FastAPI `Depends()` Ruff `B008`:** Configured `extend-immutable-calls` in `backend/pyproject.toml` so FastAPI dependency declarations validate cleanly under `ruff check`.

### 3. Tests Executed & Results
- `cargo fmt --manifest-path agent\Cargo.toml` + `cargo clippy --manifest-path agent\Cargo.toml --all-targets -- -D warnings`: **PASS** (`0` warnings)
- `cargo test --manifest-path agent\Cargo.toml`: **PASS** (`10` passed, `0` failed; includes protected denylist, quarantine/restore SHA-256 roundtrip, isolation rule whitelist)
- `cargo build --manifest-path agent\Cargo.toml`: **PASS**
- `backend\.venv\Scripts\ruff.exe format --check` & `ruff check backend\app backend\tests`: **PASS** (`39` files formatted, `All checks passed!`)
- `backend\.venv\Scripts\python.exe -m pytest backend\tests -v`: **PASS** (`10` passed in `57.84s`, including RBAC boundaries, protected denylists, audit hash-chain tamper detection, and live HTTPS compiled-agent quarantine, SHA-256 restore, and real child-process termination).

### 4. Handoff Summary -> Ready for Stage 06
- **Stage 05 Gate Passed:** Authenticated RBAC, target safety, approval gates, quarantine vault + restore, isolation rollback, tamper-evident audit chain, and live Rust response execution verified.
- **Stage 06 Next Steps:** Implement backend WebSockets (`/ws/telemetry`, `/ws/alerts`, `/ws/responses`), `asyncio` event bus, fleet `/api/v1/overview` + `/api/v1/endpoints/{id}` detail views, HMAC-authenticated ANDHAK SOC Bridge (`/api/v1/soc-bridge/*`) + non-destructive SOC integration test, and full 12-view React/TS/Tailwind/Recharts/React Flow console matching `#101114`/`#A92532` and pulled `andhak-logo.png`.
