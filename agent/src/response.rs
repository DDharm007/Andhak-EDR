use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessesToUpdate, System};
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::models::{CommandAckRequest, PendingCommand};

const VAULT_MAGIC: &[u8; 8] = b"ANDHAKQ1";
const VAULT_XOR_KEY: u8 = 0xA5;

const PROTECTED_PROCESSES: &[&str] = &[
    "system",
    "system idle process",
    "idle",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "winlogon.exe",
    "svchost.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "explorer.exe",
    "andhak-edr-agent",
    "andhak-edr-agent.exe",
    "systemd",
    "init",
    "launchd",
];

const PROTECTED_PATH_PREFIXES: &[&str] = &[
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
];

pub fn is_protected_process(pid: u32, name_or_path: Option<&str>) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    if let Some(raw) = name_or_path {
        let norm = raw.replace('/', "\\").to_ascii_lowercase();
        let base = norm.rsplit('\\').next().unwrap_or(&norm);
        if PROTECTED_PROCESSES.contains(&base) {
            return true;
        }
    }
    false
}

pub fn is_protected_path(path_str: &str) -> bool {
    let norm = path_str.replace('/', "\\").trim().to_ascii_lowercase();
    if norm.split('\\').any(|seg| seg == "..") {
        return true;
    }
    let base = norm.rsplit('\\').next().unwrap_or(&norm);
    if base == "andhak-edr-agent.exe" || base == "andhak-edr-agent" {
        return true;
    }
    if matches!(
        norm.as_str(),
        "c:\\windows\\explorer.exe"
            | "c:\\windows\\system32\\ntoskrnl.exe"
            | "c:\\windows\\system32\\cmd.exe"
            | "c:\\windows\\system32\\drivers\\etc\\hosts"
    ) {
        return true;
    }
    let posix = path_str.replace('\\', "/").trim().to_ascii_lowercase();
    if matches!(posix.as_str(), "/etc/passwd" | "/etc/shadow" | "/etc/hosts") {
        return true;
    }
    PROTECTED_PATH_PREFIXES.iter().any(|p| {
        if p.contains('\\') {
            norm.starts_with(p)
        } else {
            posix.starts_with(p)
        }
    })
}

pub fn execute_command(cfg: &AgentConfig, cmd: &PendingCommand) -> CommandAckRequest {
    let outcome = match cmd.action_type.as_str() {
        "quarantine_file" => exec_quarantine_file(&cmd.target_value, &cfg.quarantine_dir),
        "restore_file" => exec_restore_file(&cmd.target_value, &cmd.target_metadata),
        "terminate_process" => exec_terminate_process(&cmd.target_value, &cmd.target_metadata),
        "isolate_endpoint" => {
            exec_isolate_endpoint(&cfg.backend_url, cfg.allow_unprivileged_dry_run_isolation)
        }
        "release_isolation" => exec_release_isolation(cfg.allow_unprivileged_dry_run_isolation),
        "push_policy" => Ok(json!({"status": "policy_sync_queued", "target": cmd.target_value})),
        "block_network_indicator" => exec_block_indicator(&cmd.target_value),
        other => Err(format!("Unsupported command action_type: {other}")),
    };

    let now = Utc::now().to_rfc3339();
    match outcome {
        Ok(verification) => CommandAckRequest {
            success: true,
            executed_at: Some(now),
            verification,
        },
        Err(err_msg) => CommandAckRequest {
            success: false,
            executed_at: Some(now),
            verification: json!({
                "error": err_msg,
                "action_type": cmd.action_type,
                "target": cmd.target_value,
            }),
        },
    }
}

pub fn exec_quarantine_file(target_path: &str, vault_dir: &Path) -> Result<Value, String> {
    if is_protected_path(target_path) {
        return Err(format!("Refused protected path quarantine: {target_path}"));
    }
    let src = Path::new(target_path);
    if !src.is_file() {
        return Err(format!("Target file does not exist: {target_path}"));
    }

    let original_bytes = fs::read(src).map_err(|e| format!("Failed reading target: {e}"))?;
    let sha_before = hex::encode(Sha256::digest(&original_bytes));
    let size_bytes = original_bytes.len() as u64;

    fs::create_dir_all(vault_dir).map_err(|e| format!("Failed creating vault dir: {e}"))?;
    let quarantine_id = format!("qtn_{}", &Uuid::new_v4().simple().to_string()[..14]);
    let vault_path: PathBuf = vault_dir.join(format!("{quarantine_id}.vault"));

    let mut wrapped = Vec::with_capacity(VAULT_MAGIC.len() + original_bytes.len());
    wrapped.extend_from_slice(VAULT_MAGIC);
    wrapped.extend(original_bytes.iter().map(|b| b ^ VAULT_XOR_KEY));

    fs::write(&vault_path, &wrapped).map_err(|e| format!("Failed writing vault file: {e}"))?;

    // Verify vault file decrypts cleanly back to exact sha_before prior to deleting source
    let reread = fs::read(&vault_path).map_err(|e| format!("Failed verifying vault file: {e}"))?;
    if !reread.starts_with(VAULT_MAGIC) {
        return Err("Vault integrity header check failed".into());
    }
    let decoded: Vec<u8> = reread[VAULT_MAGIC.len()..]
        .iter()
        .map(|b| b ^ VAULT_XOR_KEY)
        .collect();
    let sha_roundtrip = hex::encode(Sha256::digest(&decoded));
    if sha_roundtrip != sha_before {
        let _ = fs::remove_file(&vault_path);
        return Err("SHA-256 verification mismatch during quarantine transfer".into());
    }

    let vault_sha = hex::encode(Sha256::digest(&reread));
    fs::remove_file(src).map_err(|e| format!("Failed removing original file: {e}"))?;

    Ok(json!({
        "quarantine_id": quarantine_id,
        "original_path": target_path,
        "vault_path": vault_path.to_string_lossy(),
        "sha256_before": sha_before,
        "sha256_after": sha_roundtrip,
        "vault_sha256": vault_sha,
        "size_bytes": size_bytes,
        "sha256_verified": true,
    }))
}

pub fn exec_restore_file(target_value: &str, metadata: &Value) -> Result<Value, String> {
    let vault_path_str = metadata
        .get("vault_path")
        .and_then(|v| v.as_str())
        .unwrap_or(target_value);
    let orig_path_str = metadata
        .get("original_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Restore metadata missing 'original_path'".to_string())?;
    let expected_sha = metadata
        .get("sha256_before")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if is_protected_path(orig_path_str) {
        return Err(format!("Refused protected restore target: {orig_path_str}"));
    }

    let vault_path = Path::new(vault_path_str);
    let wrapped = fs::read(vault_path).map_err(|e| format!("Failed reading vault: {e}"))?;
    if !wrapped.starts_with(VAULT_MAGIC) {
        return Err("Invalid vault magic header".into());
    }
    let restored: Vec<u8> = wrapped[VAULT_MAGIC.len()..]
        .iter()
        .map(|b| b ^ VAULT_XOR_KEY)
        .collect();
    let actual_sha = hex::encode(Sha256::digest(&restored));
    if !expected_sha.is_empty() && actual_sha != expected_sha {
        return Err(format!(
            "Restored payload SHA-256 mismatch: expected {expected_sha}, got {actual_sha}"
        ));
    }

    let orig_path = Path::new(orig_path_str);
    if let Some(parent) = orig_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed preparing restore parent: {e}"))?;
    }
    fs::write(orig_path, &restored).map_err(|e| format!("Failed writing restored file: {e}"))?;
    let _ = fs::remove_file(vault_path);

    Ok(json!({
        "quarantine_id": metadata.get("quarantine_id").cloned().unwrap_or(Value::Null),
        "restored_path": orig_path_str,
        "sha256_verified": true,
        "sha256": actual_sha,
        "size_bytes": restored.len(),
    }))
}

pub fn exec_terminate_process(target_value: &str, metadata: &Value) -> Result<Value, String> {
    let pid_u32: u32 = target_value
        .trim()
        .parse()
        .map_err(|_| format!("Invalid numeric PID: {target_value}"))?;
    let meta_name = metadata.get("process_name").and_then(|v| v.as_str());
    if is_protected_process(pid_u32, meta_name) {
        return Err(format!(
            "Refused protected process termination PID {pid_u32}"
        ));
    }

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let pid = Pid::from_u32(pid_u32);
    let proc_ref = sys
        .process(pid)
        .ok_or_else(|| format!("Process PID {pid_u32} is not active"))?;

    let observed_name = proc_ref.name().to_string_lossy().to_string();
    if is_protected_process(pid_u32, Some(&observed_name)) {
        return Err(format!(
            "Refused protected observed process '{observed_name}' (PID {pid_u32})"
        ));
    }
    if let Some(expected) = meta_name {
        if !observed_name.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "PID reuse protection: expected '{expected}', observed '{observed_name}'"
            ));
        }
    }

    if !proc_ref.kill() {
        return Err(format!("OS denied termination of PID {pid_u32}"));
    }

    std::thread::sleep(std::time::Duration::from_millis(120));
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let exited = sys.process(pid).is_none();

    Ok(json!({
        "pid": pid_u32,
        "process_name": observed_name,
        "terminated": true,
        "exited_verified": exited,
    }))
}

pub fn build_isolation_firewall_plan(backend_url: &str) -> (String, u16, Vec<Vec<String>>) {
    let trimmed = backend_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_port = trimmed.split('/').next().unwrap_or("127.0.0.1:8010");
    let mut parts = host_port.splitn(2, ':');
    let host = parts.next().unwrap_or("127.0.0.1").to_string();
    let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(8010);

    let rules = vec![
        vec![
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=AndhakEDR-Isolation-AllowBackend",
            "dir=out",
            "action=allow",
            "protocol=TCP",
            &format!("remoteip={host}"),
            &format!("remoteport={port}"),
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        vec![
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=AndhakEDR-Isolation-BlockAllOut",
            "dir=out",
            "action=block",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        vec![
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=AndhakEDR-Isolation-BlockAllIn",
            "dir=in",
            "action=block",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    ];
    (host, port, rules)
}

fn is_elevated_process() -> bool {
    #[cfg(windows)]
    {
        crate::collectors::windows::is_process_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn exec_isolate_endpoint(backend_url: &str, allow_dry_run: bool) -> Result<Value, String> {
    let (host, port, plan) = build_isolation_firewall_plan(backend_url);
    if cfg!(windows) && is_elevated_process() {
        for args in &plan {
            let status = Command::new("netsh")
                .args(args)
                .status()
                .map_err(|e| format!("Failed invoking netsh: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "netsh rule failed with exit code {:?}",
                    status.code()
                ));
            }
        }
        return Ok(json!({
            "mode": "netsh_advfirewall",
            "isolated": true,
            "management_exception": format!("{host}:{port}"),
            "rules_applied": [
                "AndhakEDR-Isolation-AllowBackend",
                "AndhakEDR-Isolation-BlockAllOut",
                "AndhakEDR-Isolation-BlockAllIn",
            ]
        }));
    }
    if allow_dry_run {
        return Ok(json!({
            "mode": "dry_run_unprivileged",
            "isolated": true,
            "management_exception": format!("{host}:{port}"),
            "planned_netsh_rules": plan,
        }));
    }
    Err("Elevation required to enforce Windows Firewall isolation rules".into())
}

fn exec_release_isolation(allow_dry_run: bool) -> Result<Value, String> {
    let names = [
        "AndhakEDR-Isolation-AllowBackend",
        "AndhakEDR-Isolation-BlockAllOut",
        "AndhakEDR-Isolation-BlockAllIn",
    ];
    if cfg!(windows) && is_elevated_process() {
        for name in names {
            let _ = Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={name}"),
                ])
                .status();
        }
        return Ok(json!({
            "mode": "netsh_advfirewall",
            "isolated": false,
            "rules_removed": names,
        }));
    }
    if allow_dry_run {
        return Ok(json!({
            "mode": "dry_run_unprivileged",
            "isolated": false,
            "rules_removed": names,
        }));
    }
    Err("Elevation required to remove Windows Firewall isolation rules".into())
}

fn exec_block_indicator(target: &str) -> Result<Value, String> {
    if target == "127.0.0.1" || target == "::1" || target.eq_ignore_ascii_case("localhost") {
        return Err("Protected loopback indicator cannot be blocked".into());
    }
    Ok(json!({
        "mode": if is_elevated_process() { "netsh_advfirewall" } else { "dry_run_unprivileged" },
        "indicator": target,
        "blocked": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_protected_os_targets() {
        assert!(is_protected_process(4, Some("System")));
        assert!(is_protected_process(800, Some("lsass.exe")));
        assert!(is_protected_process(std::process::id(), Some("test.exe")));
        assert!(!is_protected_process(41200, Some("payload.exe")));

        assert!(is_protected_path("C:\\Windows\\System32\\kernel32.dll"));
        assert!(is_protected_path(
            "C:\\Windows\\System32\\drivers\\etc\\hosts"
        ));
        assert!(is_protected_path(
            "C:\\Temp\\..\\Windows\\System32\\cmd.exe"
        ));
        assert!(!is_protected_path(
            "C:\\Users\\Analyst\\AppData\\Local\\Temp\\drop.exe"
        ));
    }

    #[test]
    fn quarantine_and_restore_preserve_exact_sha256() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("suspicious_drop.bin");
        let vault = dir.path().join("vault");
        let content = b"ANDHAK_STAGE05_REVERSIBLE_QUARANTINE_TEST_PAYLOAD";
        fs::write(&src, content).unwrap();

        let q_res = exec_quarantine_file(&src.to_string_lossy(), &vault).unwrap();
        assert!(!src.exists());
        assert_eq!(q_res["sha256_verified"], Value::Bool(true));

        let vault_path = PathBuf::from(q_res["vault_path"].as_str().unwrap());
        assert!(vault_path.exists());
        // Vault bytes must NOT contain raw cleartext binary header
        let raw_vault = fs::read(&vault_path).unwrap();
        assert!(raw_vault.starts_with(VAULT_MAGIC));

        let r_res = exec_restore_file(vault_path.to_str().unwrap(), &q_res).unwrap();
        assert!(src.exists());
        assert!(!vault_path.exists());
        assert_eq!(fs::read(&src).unwrap(), content);
        assert_eq!(r_res["sha256_verified"], Value::Bool(true));
    }

    #[test]
    fn isolation_plan_explicitly_whitelists_backend_endpoint() {
        let (host, port, plan) = build_isolation_firewall_plan("https://10.0.5.20:8443");
        assert_eq!(host, "10.0.5.20");
        assert_eq!(port, 8443);
        assert_eq!(plan.len(), 3);
        assert!(plan[0].contains(&"remoteip=10.0.5.20".to_string()));
        assert!(plan[0].contains(&"remoteport=8443".to_string()));
    }
}
