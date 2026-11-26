use std::collections::{HashMap, HashSet};

use chrono::Utc;
use sysinfo::{Disks, Networks, ProcessesToUpdate, System, Users};
use uuid::Uuid;

use crate::collectors::{
    EventLogCollector, HostMetadata, NetworkCollector, ProcessCollector, SystemCollector,
    SystemSnapshot,
};
use crate::error::AgentError;
use crate::models::{
    compute_dedup_hash, make_process_guid, ProcessPayload, SensorState, Severity, SignatureStatus,
    SystemPayload, TelemetryCategory, TelemetryEventIn, TelemetryOrigin,
};

pub struct PortableProcessCollector {
    sys: System,
    users: Users,
    known_pids: HashSet<u32>,
    guid_map: HashMap<u32, (String, String)>,
}

impl Default for PortableProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl PortableProcessCollector {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
            users: Users::new_with_refreshed_list(),
            known_pids: HashSet::new(),
            guid_map: HashMap::new(),
        }
    }
}

impl ProcessCollector for PortableProcessCollector {
    fn collect_delta(&mut self, endpoint_id: &str) -> Result<Vec<TelemetryEventIn>, AgentError> {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        self.users.refresh();

        let mut events = Vec::new();
        let mut current = HashSet::new();

        for (pid, proc_info) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            current.insert(pid_u32);
            let name = proc_info.name().to_string_lossy().to_string();
            let guid = make_process_guid(endpoint_id, pid_u32, proc_info.start_time());
            self.guid_map.insert(pid_u32, (name.clone(), guid.clone()));

            if self.known_pids.contains(&pid_u32) {
                continue;
            }
            let ppid = proc_info.parent().map(|p| p.as_u32()).unwrap_or(0);
            let parent_guid = self.guid_map.get(&ppid).map(|(_, g)| g.clone());
            let exe_path = proc_info
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let cmd = proc_info
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let user_ctx = proc_info
                .user_id()
                .and_then(|uid| self.users.get_user_by_id(uid))
                .map(|u| u.name().to_string())
                .unwrap_or_default();
            let sha256 = proc_info
                .exe()
                .and_then(crate::collectors::filesystem::sha256_file);
            let started_at = chrono::DateTime::from_timestamp(proc_info.start_time() as i64, 0)
                .unwrap_or_else(Utc::now)
                .to_rfc3339();
            let dedup_hash = compute_dedup_hash(&["process", "process_start", &guid]);

            events.push(TelemetryEventIn {
                event_id: format!("proc-{}", Uuid::new_v4()),
                telemetry_origin: TelemetryOrigin::RealEndpoint,
                category: TelemetryCategory::Process,
                event_type: "process_start".into(),
                severity: Severity::Info,
                occurred_at: Utc::now().to_rfc3339(),
                dedup_hash,
                process: Some(ProcessPayload {
                    process_guid: guid,
                    parent_process_guid: parent_guid,
                    pid: pid_u32,
                    ppid,
                    name,
                    executable_path: exe_path,
                    command_line: cmd,
                    user_context: user_ctx,
                    sha256,
                    signature_status: SignatureStatus::Unknown,
                    signer_subject: None,
                    started_at,
                }),
                network: None,
                filesystem: None,
                system: None,
                extra: serde_json::json!({}),
            });
        }

        self.known_pids = current;
        Ok(events)
    }

    fn active_process_map(&self) -> HashMap<u32, (String, String)> {
        self.guid_map.clone()
    }

    fn health(&self) -> SensorState {
        SensorState::Ready
    }
}

pub struct PortableNetworkCollector;

impl NetworkCollector for PortableNetworkCollector {
    fn collect_sockets(
        &mut self,
        _endpoint_id: &str,
        _process_map: &HashMap<u32, (String, String)>,
    ) -> Result<Vec<TelemetryEventIn>, AgentError> {
        Ok(Vec::new())
    }

    fn health(&self) -> SensorState {
        SensorState::Unavailable
    }
}

pub struct PortableSystemCollector {
    sys: System,
    disks: Disks,
    networks: Networks,
}

impl Default for PortableSystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl PortableSystemCollector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_cpu_usage();
        Self {
            sys,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
        }
    }
}

impl SystemCollector for PortableSystemCollector {
    fn collect_metrics(
        &mut self,
        endpoint_id: &str,
        uptime_seconds: u64,
    ) -> Result<(SystemSnapshot, TelemetryEventIn), AgentError> {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.disks.refresh(true);
        let cpu = self.sys.global_cpu_usage();
        let used_mb = self.sys.used_memory() / (1024 * 1024);
        let total_mb = self.sys.total_memory() / (1024 * 1024);
        let (tot_disk, avail_disk) = self.disks.list().iter().fold((0u64, 0u64), |(t, a), d| {
            (
                t.saturating_add(d.total_space()),
                a.saturating_add(d.available_space()),
            )
        });
        let disk_pct = if tot_disk > 0 {
            ((tot_disk - avail_disk) as f64 / tot_disk as f64 * 100.0) as f32
        } else {
            0.0
        };
        let rss_mb = sysinfo::get_current_pid()
            .ok()
            .and_then(|pid| {
                self.sys
                    .refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
                self.sys
                    .process(pid)
                    .map(|p| p.memory() as f32 / (1024.0 * 1024.0))
            })
            .unwrap_or(0.0);

        let os_version = System::long_os_version().unwrap_or_else(|| std::env::consts::OS.into());
        let now = Utc::now();
        let bucket = (now.timestamp() / 5).to_string();
        let evt = TelemetryEventIn {
            event_id: format!("sys-{}", Uuid::new_v4()),
            telemetry_origin: TelemetryOrigin::RealEndpoint,
            category: TelemetryCategory::System,
            event_type: "host_metrics".into(),
            severity: Severity::Info,
            occurred_at: now.to_rfc3339(),
            dedup_hash: compute_dedup_hash(&["system", endpoint_id, &bucket]),
            process: None,
            network: None,
            filesystem: None,
            system: Some(SystemPayload {
                cpu_percent: cpu,
                memory_used_mb: used_mb,
                memory_total_mb: total_mb,
                disk_used_percent: disk_pct,
                agent_rss_mb: rss_mb,
                os_version,
                uptime_seconds,
            }),
            extra: serde_json::json!({}),
        };
        Ok((
            SystemSnapshot {
                cpu_percent: cpu,
                memory_used_mb: used_mb,
                memory_total_mb: total_mb,
                disk_used_percent: disk_pct,
                agent_rss_mb: rss_mb,
            },
            evt,
        ))
    }

    fn host_metadata(&mut self) -> HostMetadata {
        self.networks.refresh(true);
        HostMetadata {
            hostname: System::host_name().unwrap_or_else(|| "unknown-host".into()),
            fqdn: None,
            os_family: std::env::consts::OS.into(),
            os_version: System::long_os_version().unwrap_or_else(|| std::env::consts::OS.into()),
            architecture: std::env::consts::ARCH.into(),
            primary_ip: None,
            mac_address: None,
            elevated_sensor: false,
        }
    }

    fn health(&self) -> SensorState {
        SensorState::Ready
    }
}

pub struct PortableEventLogCollector;

impl EventLogCollector for PortableEventLogCollector {
    fn probe_available(&self) -> bool {
        false
    }
    fn collect_new(&mut self, _endpoint_id: &str) -> Result<Vec<TelemetryEventIn>, AgentError> {
        Ok(Vec::new())
    }
    fn health(&self) -> SensorState {
        SensorState::Unavailable
    }
}
