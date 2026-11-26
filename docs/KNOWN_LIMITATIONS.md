# ANDHAK EDR — Known Limitations & Scope Notes

This file tracks verified environment constraints, architectural scope adjustments, and unimplemented capabilities honestly across all stages.

---

## 1. Stage 01 Verified Environment Constraints

1. **Windows Security Event Log Elevation:**
   - Observed in `Andhak SOC`: standard non-elevated Windows sessions are denied read access to the `Security` Event Log channel.
   - Impact on EDR: when running unprivileged, the Rust sensor can read live process inventory, user-accessible filesystem paths, system metrics, and Windows TCP/UDP tables, while restricted process command lines / `SYSTEM` tokens and privileged channels report `partial` or `unavailable` honestly rather than fabricating fields.
2. **Sysmon Not Installed on Local Dev Host:**
   - Verified via `Get-WinEvent -ListLog "*Sysmon*"`: `Microsoft-Windows-Sysmon/Operational` is not present on this machine.
   - Impact on EDR: the Sysmon collector module will probe the channel at startup and report `"sysmon": "unavailable"` cleanly until Sysmon is installed and enabled by an administrator.
3. **Local Database & Event Bus Default (No External Postgres/Redis/Docker Running):**
   - Verified via toolchain check: `psql`, `redis-server`, and `docker` are not installed on this development machine.
   - Mitigation: local SQLite (`WAL` mode) and an in-process `asyncio` event bus serve as first-class zero-dependency defaults, while SQLAlchemy models and Docker Compose manifests keep PostgreSQL + Redis deployment parity ready.
4. **Rust GNU Toolchain (`x86_64-pc-windows-gnu`) & WDAC Native DLL Constraints:**
   - `rustc 1.100.0` defaults to `x86_64-pc-windows-gnu`; MSVC `cl.exe` was not detected. Native C-linked crates (like `openssl-sys`) may fail without Perl/MSVC, so `rustls` and pure-Rust crates are mandatory.
   - `Andhak SOC` previously noted Windows Application Control blocking certain unsigned native Python DLLs (`xxhash`). While `yara_x 1.24.0` imported cleanly in the SOC `.venv`, all Stage 03 native ML/scanner wheels (`yara-x`, `pefile`, `lightgbm`/`scikit-learn`) must be verified directly in the EDR `.venv`.
5. **GitHub CLI (`gh`) Absent:**
   - `gh` is not installed; Git remote operations rely on `git` + Windows Git Credential Manager.

---

## 2. Explicit Scope Decisions

- **No Generative AI / LLM Analyst (User Directive):** Per explicit owner instruction (*"without ai"*), Stage 04 and Stage 06 omit LLM/AI Security Analyst integrations (Claude, GPT, Gemini, local LLM). All investigation summaries, false-positive assessments, MITRE mappings, and remediation recommendations are produced by deterministic, evidence-cited rules and templates.
- **No Identity Provider Connector (`revoke_session`):** Unless an external IdP connector is explicitly configured in future roadmaps, identity session revocation cannot execute against local standalone Windows accounts and remains unsupported/explicitly reported.
- **Single-Host Lab Validation Scope (Stages 02–05):** Hardware access during initial build is a single Windows 11 development workstation; Linux and macOS sensor backends are isolated behind portable Rust collector traits for future expansion (`Stage 02+`), not natively compiled or tested on Linux/macOS hardware yet.

---

## 3. Current Implementation Status

- **Stage 01 (Current):** Architecture, database DDL, API/telemetry/SOC contracts, security threat model, and repository governance documentation completed.
- **Stages 02–07:** Not yet implemented (Rust sensor, detection engine, forensics/correlation engine, response engine, backend runtime, frontend console, and screenshots remain pending in upcoming stages).
