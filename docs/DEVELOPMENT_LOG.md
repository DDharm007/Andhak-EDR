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
