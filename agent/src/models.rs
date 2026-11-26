use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryOrigin {
    RealEndpoint,
    RecordedDemo,
    TestFixture,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryCategory {
    Process,
    Network,
    Filesystem,
    System,
    Sysmon,
    Fim,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SensorState {
    Ready,
    Partial,
    Unavailable,
    Pending,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Invalid,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorHealthMap {
    pub process: SensorState,
    pub network: SensorState,
    pub filesystem: SensorState,
    pub system: SensorState,
    pub sysmon: SensorState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub bootstrap_token: String,
    pub hostname: String,
    pub fqdn: Option<String>,
    pub os_family: String,
    pub os_version: String,
    pub architecture: String,
    pub agent_version: String,
    pub primary_ip: Option<String>,
    pub mac_address: Option<String>,
    pub elevated_sensor: bool,
    pub sysmon_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    pub policy_id: String,
    pub version: u32,
    pub heartbeat_seconds: u64,
    #[serde(default = "default_process_poll")]
    pub process_poll_ms: u64,
    #[serde(default = "default_network_poll")]
    pub network_poll_ms: u64,
    #[serde(default = "default_system_poll")]
    pub system_poll_ms: u64,
    pub batch_max_events: usize,
    pub flush_interval_ms: u64,
    #[serde(default)]
    pub fim_paths: Vec<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
}

fn default_process_poll() -> u64 {
    2000
}
fn default_network_poll() -> u64 {
    5000
}
fn default_system_poll() -> u64 {
    5000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub endpoint_id: String,
    pub agent_token: String,
    pub credential_id: String,
    pub policy: AgentPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub endpoint_id: String,
    pub agent_version: String,
    pub uptime_seconds: u64,
    pub cpu_percent: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_percent: f32,
    pub agent_rss_mb: f32,
    pub spool_queue_depth: u64,
    pub policy_version: u32,
    pub sensors: SensorHealthMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommand {
    pub action_id: String,
    pub action_type: String,
    pub target_value: String,
    #[serde(default)]
    pub target_metadata: serde_json::Value,
    pub issued_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub server_time: String,
    pub policy_update_available: bool,
    #[serde(default)]
    pub pending_commands: Vec<PendingCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAckRequest {
    pub success: bool,
    pub executed_at: Option<String>,
    pub verification: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandAckResponse {
    pub action_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPayload {
    pub process_guid: String,
    pub parent_process_guid: Option<String>,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub executable_path: String,
    pub command_line: String,
    pub user_context: String,
    pub sha256: Option<String>,
    pub signature_status: SignatureStatus,
    pub signer_subject: Option<String>,
    pub started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPayload {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub process_guid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPayload {
    pub file_path: String,
    pub previous_path: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub signature_status: SignatureStatus,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPayload {
    pub cpu_percent: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_percent: f32,
    pub agent_rss_mb: f32,
    pub os_version: String,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEventIn {
    pub event_id: String,
    pub telemetry_origin: TelemetryOrigin,
    pub category: TelemetryCategory,
    pub event_type: String,
    pub severity: Severity,
    pub occurred_at: String,
    pub dedup_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FilesystemPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPayload>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchRequest {
    pub batch_id: String,
    pub endpoint_id: String,
    pub sent_at: String,
    pub events: Vec<TelemetryEventIn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatchResponse {
    pub batch_id: String,
    pub accepted: usize,
    pub duplicate_skipped: usize,
    pub ingested_at: String,
}

pub fn compute_dedup_hash(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for (idx, part) in parts.iter().enumerate() {
        if idx > 0 {
            hasher.update(b"|");
        }
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

pub fn make_process_guid(endpoint_id: &str, pid: u32, started_secs: u64) -> String {
    format!("{endpoint_id}-{pid}-{started_secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_hash_is_deterministic_and_sensitive_to_order() {
        let a = compute_dedup_hash(&["process", "100", "notepad.exe"]);
        let b = compute_dedup_hash(&["process", "100", "notepad.exe"]);
        let c = compute_dedup_hash(&["process", "101", "notepad.exe"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }
}
