# ANDHAK EDR — Executive Engineering & Portfolio Summary

- **Product:** ANDHAK EDR (`Detect. Investigate. Respond.`)
- **Repository:** [https://github.com/DDharm007/Andhak-EDR](https://github.com/DDharm007/Andhak-EDR)
- **Companion Platform:** [ANDHAK SOC](https://github.com/DDharm007/Andhak-SOC) (`D:\Personal Projects\Andhak SOC`)

---

## 1. Engineering Problem & Design Philosophy

Endpoint security portfolios frequently stop at UI mockups or toy Python scripts masquerading as agents. **ANDHAK EDR** was engineered incrementally across seven gated milestones (`Stage 01`–`Stage 07`) to behave like a disciplined production telemetry, detection, forensics, and containment architecture on commodity local infrastructure:

1. **Systems-Level Endpoint Telemetry (Rust + Tokio + Win32):** Built `andhak-edr-agent` with `sysinfo`, Win32 `GetExtendedTcpTable`/`GetExtendedUdpTable`, `WinVerifyTrust` + `CryptCATAdmin*` (`WTD_CHOICE_CATALOG`) Authenticode verification for Windows catalog-signed system binaries, `notify` recursive filesystem watching with glob exclusions and deduplication, bounded SQLite WAL offline spooling with informational-first eviction, and `rustls` TLS transport carrying `X-Payload-SHA256` integrity headers.
2. **Evidence-Based Multi-Engine Detection (Zero AI):** Combined compiled native `yara-x`, structural 2381-dimensional Windows PE extraction (`pefile` + `numpy`) feeding a versioned advisory `HistGradientBoostingClassifier` (`andhak-ember-gbdt-v1.0`), SHA-256 + Authenticode File Integrity Monitoring (FIM), 8 stateful behavioral detection rules (`BEH-001`–`BEH-008`), and local/policy-gated IOC matching.
3. **Deterministic Correlation & Forensics (ADR-002):** Per explicit owner directive, ANDHAK EDR omits generative AI/LLM inference completely. Every correlated incident, React Flow attack graph, chronological UTC timeline, ATT&CK mapping, false-positive check, containment runbook, and SHA-256-sealed forensic bundle cites concrete recorded `alert_id` and `event_id` evidence.
4. **Fail-Safe Controlled Containment & Audit Integrity:** Protected target denylists prevent killing `System`, `lsass.exe`, `csrss.exe`, or self-PIDs and prevent quarantining `C:\Windows\System32` binaries. Containment requires explicit RBAC approval (`responder` / `admin`), XOR-obfuscated `ANDHAKQ1` vault verification (`sha256_before == sha256_after`), reversible isolation rollback (`release_isolation` / `restore_file`), and append-only SHA-256 hash-chained `audit_logs`.
5. **Non-Destructive ANDHAK SOC Bridge:** Connects to existing standalone ANDHAK SOC via versioned `edr-*` event export, bidirectional IOC sync, and HMAC-SHA256 authenticated containment request queuing without modifying `Andhak SOC` code or schema.

---

## 2. Demonstrated Technical Breadth

| Discipline | Concrete Implementation |
| :--- | :--- |
| **Systems Programming (Rust)** | `andhak-edr-agent` (`agent/src/`): portable collector traits, Win32 FFI (`windows-sys`), SQLite WAL ring buffer, `ANDHAKQ1` quarantine vault & SHA-256 restoration, PID reuse guards, graceful Ctrl+C flush. |
| **Security Detection Engineering** | `yara-x` signature matching, EMBER 2381-d static PE classifier, FIM drift & signature degradation, 8 behavioral correlation rules (`BEH-001`–`BEH-008`), separate Severity vs Confidence risk model. |
| **Forensics & Investigation** | Parent-child process tree reconstruction, React Flow attack graphs, chronological event timelines, evidence-gated ATT&CK attribution, canonical JSON forensic bundles with SHA-256 tamper verification. |
| **Application Security & Governance** | `Argon2id` credentials, HS256 JWT RBAC (`admin`, `responder`, `analyst`, `readonly_demo`), `ANDHAK_DEMO_MODE=true` mutation lockdown (`403`), command-line secret redaction, HMAC replay window verification. |
| **Frontend Architecture** | 12-view React 19 + TypeScript + Tailwind CSS + Recharts + React Flow (`@xyflow/react`) console built on Accessible HTML (`<dialog>`, `<search>`, sticky `<table>`, `aria-live`), `WS` auto-reconnect, and strict data-origin badging (`REAL TELEMETRY` / `RECORDED DEMO` / `TEST FIXTURE`). |

---

## 3. Verification Highlights

- **Rust Test & Static Gate:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (`0` warnings), `cargo test` (`10/10` unit tests including live Windows socket/process capture, catalog signature verification, and quarantine roundtrip).
- **Backend & Live Compiled-Agent E2E:** Ruff lint/format + `14/14` `pytest` tests spanning HTTPS TLS compiled-agent enrollment/upload (`Stage 02`), YARA-X/EMBER/FIM/8-behavioral/IOC (`Stage 03`), 6-stage attack correlation + forensic tamper check (`Stage 04`), RBAC/denylist/audit-chain + live compiled-agent quarantine/restore/child-PID termination (`Stage 05`), live WebSockets + SOC HMAC bridge (`Stage 06`), and demo-mode lockdown + secret redaction (`Stage 07`).
- **Frontend Build & Visual Proof:** `tsc -b && vite build` clean, `vitest run` (`3/3`), and 12 genuine Playwright headless browser screenshots verifying populated React Flow graphs, Recharts visualizations, live real-host telemetry (`TUF-DHARM007`), and `AUDIT SHA-256 CHAIN VERIFIED` status.
