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
**Date:** 2026-11-26  
**Milestone Status:** Complete  
**Author / Operator:** Principal Engineering Agent + Dharm Patel (`DDharm007`)

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
**Date:** 2026-11-26  
**Milestone Status:** Complete  
**Author / Operator:** Principal Engineering Agent + Dharm Patel (`DDharm007`)

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
