# ANDHAK EDR — Seven-Stage Milestone Tracker

| Stage | Name | Target Commit Message | Status | Key Evidence / Gate |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 01** | Architecture & Engineering Foundation | `feat(architecture): establish ANDHAK EDR foundation` | **Completed** | Repo & SOC inspected; `andhak-logo.png` pulled; 6 docs + 4 contract files + SQL schema verified (`22` tables, `24` indexes in `sqlite3`; `0` broken links); `.gitignore` & `.env.example` created. |
| **Stage 02** | Rust Endpoint Sensor | `feat(agent): implement Rust endpoint sensor` | Pending | Compiled Rust agent collecting real Windows process, network, filesystem, and system telemetry; TLS transport with retry/dedup; unit & integration tests passing. |
| **Stage 03** | Detection & Integrity Intelligence | `feat(detection): add malware and integrity intelligence` | Pending | YARA-X scanner, EMBER static PE scoring, FIM baselines/drift, 8 windowed behavioral rules, IOC enrichment, risk scoring tests passing on fixtures. |
| **Stage 04** | Forensics, Correlation & Threat Investigation | `feat(forensics): implement event correlation and attack mapping` | Pending | Incident correlation, process tree, attack timeline, evidence-backed ATT&CK mapping, forensic bundles, deterministic triage engine verified end-to-end. |
| **Stage 05** | Prevention & Incident Response Engine | `feat(response): implement controlled endpoint response` | Pending | RBAC approval flow, protected target denylist, file quarantine/restore, reversible endpoint isolation, process termination, SHA-256 audit log verified. |
| **Stage 06** | SOC Integration & Frontend Development | `feat(soc): integrate EDR with ANDHAK SOC` | Pending | FastAPI + WebSocket backend + ANDHAK SOC bridge + 12-view React/TS/Tailwind/Recharts/React Flow console honoring `#101114`/`#A92532` tokens. |
| **Stage 07** | Testing, Docs, Deployment & Portfolio Release | `release: publish ANDHAK EDR portfolio release` | Pending | Full test suites, read-only public demo mode, Docker/CI, 12 real Playwright screenshots, annotated `README.md`, portfolio summary, secret scan, release push. |
