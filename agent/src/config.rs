use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub backend_url: String,
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub allow_insecure_loopback_http: bool,
    pub state_file: PathBuf,
    pub spool_db_path: PathBuf,
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<PathBuf>,
    #[serde(default = "default_exclusions")]
    pub exclusions: Vec<String>,
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_seconds: u64,
    #[serde(default = "default_process_poll_ms")]
    pub process_poll_ms: u64,
    #[serde(default = "default_network_poll_ms")]
    pub network_poll_ms: u64,
    #[serde(default = "default_system_poll_ms")]
    pub system_poll_ms: u64,
    #[serde(default = "default_batch_max")]
    pub batch_max_events: usize,
    #[serde(default = "default_flush_ms")]
    pub flush_interval_ms: u64,
    #[serde(default = "default_max_spool_events")]
    pub max_spool_events: usize,
    #[serde(default = "default_max_channel_capacity")]
    pub channel_capacity: usize,
}

fn default_watch_paths() -> Vec<PathBuf> {
    if cfg!(windows) {
        let mut paths = Vec::new();
        if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
            let temp = PathBuf::from(local_app).join("Temp");
            if temp.exists() {
                paths.push(temp);
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let downloads = PathBuf::from(profile).join("Downloads");
            if downloads.exists() {
                paths.push(downloads);
            }
        }
        paths
    } else {
        vec![PathBuf::from("/tmp")]
    }
}

fn default_exclusions() -> Vec<String> {
    vec![
        "*.tmp".into(),
        "*.log".into(),
        "*.etl".into(),
        "*agent-spool.sqlite3*".into(),
        "*andhak-edr.sqlite3*".into(),
    ]
}

fn default_heartbeat_secs() -> u64 {
    15
}
fn default_process_poll_ms() -> u64 {
    2000
}
fn default_network_poll_ms() -> u64 {
    5000
}
fn default_system_poll_ms() -> u64 {
    5000
}
fn default_batch_max() -> usize {
    100
}
fn default_flush_ms() -> u64 {
    2000
}
fn default_max_spool_events() -> usize {
    50_000
}
fn default_max_channel_capacity() -> usize {
    1024
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            backend_url: "https://127.0.0.1:8010".into(),
            ca_cert_path: None,
            allow_insecure_loopback_http: false,
            state_file: PathBuf::from(".local-data/agent-state.json"),
            spool_db_path: PathBuf::from(".local-data/agent-spool.sqlite3"),
            watch_paths: default_watch_paths(),
            exclusions: default_exclusions(),
            heartbeat_seconds: default_heartbeat_secs(),
            process_poll_ms: default_process_poll_ms(),
            network_poll_ms: default_network_poll_ms(),
            system_poll_ms: default_system_poll_ms(),
            batch_max_events: default_batch_max(),
            flush_interval_ms: default_flush_ms(),
            max_spool_events: default_max_spool_events(),
            channel_capacity: default_max_channel_capacity(),
        }
    }
}

impl AgentConfig {
    pub fn load(path: Option<&Path>) -> Result<Self, AgentError> {
        let mut cfg = if let Some(file) = path {
            let content = fs::read_to_string(file)?;
            toml::from_str::<AgentConfig>(&content)?
        } else {
            AgentConfig::default()
        };

        if let Ok(url) = std::env::var("ANDHAK_AGENT_BACKEND_URL") {
            if !url.trim().is_empty() {
                cfg.backend_url = url.trim().to_string();
            }
        }
        if let Ok(ca) = std::env::var("ANDHAK_AGENT_CA_CERT") {
            if !ca.trim().is_empty() {
                cfg.ca_cert_path = Some(PathBuf::from(ca.trim()));
            }
        }

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), AgentError> {
        let lower = self.backend_url.to_ascii_lowercase();
        let is_https = lower.starts_with("https://");
        let is_loopback_http = lower.starts_with("http://127.0.0.1")
            || lower.starts_with("http://localhost")
            || lower.starts_with("http://[::1]");
        if !is_https && !(self.allow_insecure_loopback_http && is_loopback_http) {
            return Err(AgentError::Config(
                "backend_url must use https:// (or explicit allow_insecure_loopback_http=true for loopback development)".into(),
            ));
        }
        if self.batch_max_events == 0 || self.batch_max_events > 500 {
            return Err(AgentError::Config(
                "batch_max_events must be between 1 and 500".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub endpoint_id: String,
    pub agent_token: String,
    pub credential_id: String,
    pub policy_version: u32,
}

impl AgentState {
    pub fn load(path: &Path) -> Result<Option<Self>, AgentError> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(path)?;
        let parsed = serde_json::from_str::<AgentState>(&raw)?;
        Ok(Some(parsed))
    }

    pub fn save(&self, path: &Path) -> Result<(), AgentError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_http_transport() {
        let cfg = AgentConfig {
            backend_url: "http://192.168.1.10:8010".into(),
            allow_insecure_loopback_http: true,
            ..AgentConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_https_and_explicit_loopback_http() {
        let https = AgentConfig::default();
        assert!(https.validate().is_ok());

        let loopback = AgentConfig {
            backend_url: "http://127.0.0.1:8010".into(),
            allow_insecure_loopback_http: true,
            ..AgentConfig::default()
        };
        assert!(loopback.validate().is_ok());
    }
}
