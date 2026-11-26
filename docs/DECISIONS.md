# ANDHAK EDR — Architectural Decision Records (ADRs)

---

## ADR-001: Modular Separation from ANDHAK SOC via Bridge Contract
- **Status:** Accepted (Stage 01)
- **Context:** `D:\Personal Projects\Andhak SOC` is an existing standalone Windows local SOC console (`FastAPI` + `React` + `SQLite`) bound strictly to `127.0.0.1:8000` with no user auth and no external containment connectors.
- **Decision:** Build ANDHAK EDR in its own repository (`Andhak-EDR`) with independent agent, backend, storage, detection, response, and frontend modules. Integrate with ANDHAK SOC through a versioned, HMAC-signed loopback bridge contract ([SOC_INTEGRATION_CONTRACT.md](contracts/SOC_INTEGRATION_CONTRACT.md)) rather than merging repositories or breaking SOC's standalone guarantees.
- **Consequences:** Both products run independently or connected; SOC's unauthenticated localhost assumption stays safely isolated behind EDR's authenticated API.

---

## ADR-002: Zero-Generative-AI Deterministic Investigation & Triage Architecture
- **Status:** Accepted (Stage 01 — User Directive)
- **Context:** The original seven-stage template proposed an LLM-backed AI Security Analyst (Claude/GPT/Gemini/local LLM). During Stage 01 planning, the project owner explicitly instructed: *"we will create this edr system without ai"*.
- **Decision:** Omit all generative AI / LLM clients, cloud inference APIs, and local LLM sidecar runtimes from ANDHAK EDR. Replace Stage 04 Module 06 and Stage 06 View 11 with a **Deterministic Incident Investigation & Automated Triage Engine**:
  - Rule-driven narrative synthesis strictly grounded in observed telemetry timestamps and `event_id` references.
  - Deterministic process-tree reconstruction and chronological attack timelines.
  - Evidence-backed MITRE ATT&CK tactic/technique mapping (requiring concrete field/rule evidence).
  - Automated false-positive checklist (Authenticode signature validation, trusted system-path verification, baseline comparison).
  - Ranked deterministic containment runbooks mapped to alert rule IDs.
- **Note on EMBER (Stage 03):** Classic static PE classification (EMBER tabular PE feature extraction + LightGBM/scikit-learn heuristic scoring) is non-generative tabular binary triage and remains isolated inside the Stage 03 malware analysis pipeline with explicit probabilistic provenance; final confirmation always relies on deterministic YARA-X, FIM, signature, and behavioral evidence.
- **Consequences:** Zero LLM hallucination risk, zero external AI API keys or GPU VRAM overhead, 100% reproducible investigation outputs, and full auditability.

---

## ADR-003: Local-First SQLite Database & In-Process Asyncio Event Bus
- **Status:** Accepted (Stage 01 — User Directive)
- **Context:** Local environment inspection confirmed PostgreSQL, Redis, and Docker are not installed on the development host, and the user requested a local database (`"add a local database"`).
- **Decision:** Use **SQLite (WAL mode, `PRAGMA foreign_keys = ON`)** via SQLAlchemy 2.x (`aiosqlite`) as the primary zero-configuration local database (`.local-data/andhak-edr.sqlite3`) alongside an in-process `asyncio` pub/sub event bus for WebSocket fan-out. Maintain strict ANSI/PostgreSQL-compatible DDL and Alembic migration support so deployments with `ANDHAK_EDR_DB_URL=postgresql+asyncpg://...` and `ANDHAK_EDR_REDIS_URL=redis://...` work without code refactoring.
- **Consequences:** Runs out-of-the-box on Windows without external daemon setup while retaining clean horizontal scaling options via Docker/Postgres/Redis in Stage 07.

---

## ADR-004: Rust Sensor on `x86_64-pc-windows-gnu` with Pure-Rust TLS (`rustls`)
- **Status:** Accepted (Stage 01)
- **Context:** Toolchain inspection showed `rustc 1.100.0` defaults to `stable-x86_64-pc-windows-gnu` with WinLibs `cmake`, while MSVC `cl.exe`/`link.exe` was absent on disk.
- **Decision:** Standardize Rust HTTP/TLS transport on `reqwest` with `rustls-tls` and pure-Rust crypto/hashing (`sha2`, `ring`/`rustls`), avoiding native OpenSSL C compilation dependencies. Keep OS telemetry behind portable Rust traits (`platform::windows` primary).
- **Consequences:** Deterministic builds on the local Windows GNU toolchain and clean future portability to Linux/macOS.

---

## ADR-005: Per-Endpoint Enrollment & Scoped Credentials (No Binary Secrets)
- **Status:** Accepted (Stage 01)
- **Context:** Embedding shared API keys inside endpoint executables allows trivial secret extraction and cross-host spoofing.
- **Decision:** Agents enroll once with a short-lived operator-generated `bootstrap_token`, receive a unique `endpoint_id` and scoped `agent_token` stored only as a SHA-256 hash on the backend, and sign/digest batches with `X-Payload-SHA256`.
- **Consequences:** Individual endpoints can be revoked or rotated cleanly without recompiling agents.

---

## ADR-006: RBAC, Dual-Gate Approval & Protected Target Denylist for Response
- **Status:** Accepted (Stage 01)
- **Context:** Autonomous containment risks severe host disruption or lockout.
- **Decision:** Enforce RBAC (`analyst` may propose; `responder`/`admin` must approve), validate targets against an immutable OS critical process/path denylist, keep management-plane IP/port reachable during network isolation, verify pre/post SHA-256 during quarantine, and record every step in a SHA-256 hash-chained `audit_logs` table.
- **Consequences:** Safe, reversible, auditable endpoint response matching enterprise EDR governance.

---

## ADR-007: Strict `telemetry_origin` Isolation (`real_endpoint` vs `recorded_demo` vs `test_fixture`)
- **Status:** Accepted (Stage 01)
- **Context:** Rule D requires honest separation between live telemetry, recorded demo replays, and synthetic test fixtures.
- **Decision:** Tag every endpoint, telemetry event, alert, incident, and WebSocket message with an explicit `telemetry_origin` enum, surface visible UI provenance pills, and isolate public read-only demo replay into `ANDHAK_DEMO_MODE=true`.
- **Consequences:** Zero ambiguity between real host monitoring, captured demo sessions, and automated test fixtures.
