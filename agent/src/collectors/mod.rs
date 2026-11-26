pub mod filesystem;
#[cfg(not(windows))]
pub mod portable_fallback;
#[cfg(windows)]
pub mod windows;

use std::collections::HashMap;

use serde::Serialize;

use crate::error::AgentError;
use crate::models::{SensorState, TelemetryEventIn};

#[derive(Debug, Clone, Serialize)]
pub struct HostMetadata {
    pub hostname: String,
    pub fqdn: Option<String>,
    pub os_family: String,
    pub os_version: String,
    pub architecture: String,
    pub primary_ip: Option<String>,
    pub mac_address: Option<String>,
    pub elevated_sensor: bool,
}

#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    pub cpu_percent: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub disk_used_percent: f32,
    pub agent_rss_mb: f32,
}

/// Portable telemetry collector interfaces so Linux and macOS backends can be added cleanly.
pub trait ProcessCollector: Send + Sync {
    fn collect_delta(&mut self, endpoint_id: &str) -> Result<Vec<TelemetryEventIn>, AgentError>;
    fn active_process_map(&self) -> HashMap<u32, (String, String)>;
    fn health(&self) -> SensorState;
}

pub trait NetworkCollector: Send + Sync {
    fn collect_sockets(
        &mut self,
        endpoint_id: &str,
        process_map: &HashMap<u32, (String, String)>,
    ) -> Result<Vec<TelemetryEventIn>, AgentError>;
    fn health(&self) -> SensorState;
}

pub trait SystemCollector: Send + Sync {
    fn collect_metrics(
        &mut self,
        endpoint_id: &str,
        uptime_seconds: u64,
    ) -> Result<(SystemSnapshot, TelemetryEventIn), AgentError>;
    fn host_metadata(&mut self) -> HostMetadata;
    fn health(&self) -> SensorState;
}

pub trait EventLogCollector: Send + Sync {
    fn probe_available(&self) -> bool;
    fn collect_new(&mut self, endpoint_id: &str) -> Result<Vec<TelemetryEventIn>, AgentError>;
    fn health(&self) -> SensorState;
}
