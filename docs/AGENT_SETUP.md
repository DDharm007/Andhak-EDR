# ANDHAK EDR — Rust Endpoint Sensor Installation & Configuration

## 1. Prerequisites & Build Instructions

- **Toolchain:** Rust `stable-x86_64-pc-windows-gnu` (`rustc >= 1.95` verified on `1.100.0`).
- **Build Binary:**

```powershell
cargo build --manifest-path agent\Cargo.toml --release
```

Output binary: `agent\target\release\andhak-edr-agent.exe`

---

## 2. Configuration

Copy [`agent/config.example.toml`](../agent/config.example.toml) to `agent.toml` (never commit live state/token files):

- `backend_url`: HTTPS management backend URL (`https://...`), or `http://127.0.0.1:8010` only when `allow_insecure_loopback_http = true` for local lab testing.
- `ca_cert_path`: Optional path to custom PEM root CA certificate for self-signed TLS servers.
- `state_file`: Path where the per-endpoint `endpoint_id` and scoped `agent_token` are written after enrollment (never embedded in the executable).
- `spool_db_path`: Local SQLite WAL queue (`agent-spool.sqlite3`) used for offline buffering, deduplication, and backpressure.
- `watch_paths` & `exclusions`: Filesystem monitoring directories and glob exclusions.

---

## 3. Enrollment & Execution

1. **Issue a one-time bootstrap token on the backend:**

```powershell
backend\.venv\Scripts\python.exe -m app.cli issue-token --description "Workstation 01"
```

2. **Enroll the Rust endpoint sensor:**

```powershell
agent\target\release\andhak-edr-agent.exe enroll --config agent.toml --token <BOOTSTRAP_TOKEN>
```

3. **Verify sensor health and local permissions:**

```powershell
agent\target\release\andhak-edr-agent.exe status --config agent.toml
```

4. **Run continuous telemetry collection (or run a single sweep):**

```powershell
agent\target\release\andhak-edr-agent.exe collect-once --config agent.toml
agent\target\release\andhak-edr-agent.exe run --config agent.toml
```

---

## 4. Windows Permission & Sysmon Notes

- Standard user sessions collect live processes, accessible command lines/SHA-256/Authenticode signatures, TCP/UDP sockets, user-writable filesystem watches, and host metrics; protected `SYSTEM` processes report `partial` gracefully when not elevated.
- If **Sysmon** (`Microsoft-Windows-Sysmon/Operational`) is not installed, the sensor reports `"sysmon": "unavailable"` rather than simulating Sysmon records.
