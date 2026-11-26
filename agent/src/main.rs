use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use andhak_edr_agent::collectors::filesystem::FilesystemWatcher;
use andhak_edr_agent::collectors::{
    EventLogCollector, NetworkCollector, ProcessCollector, SystemCollector,
};
use andhak_edr_agent::config::{AgentConfig, AgentState};
use andhak_edr_agent::error::AgentError;
use andhak_edr_agent::models::{
    EnrollmentRequest, HeartbeatRequest, PendingCommand, SensorHealthMap, TelemetryEventIn,
};
use andhak_edr_agent::response::execute_command;
use andhak_edr_agent::spool::EventSpool;
use andhak_edr_agent::transport::{backoff_delay, BackendClient};

#[cfg(windows)]
use andhak_edr_agent::collectors::windows::{
    WindowsNetworkCollector as PlatformNetwork, WindowsProcessCollector as PlatformProcess,
    WindowsSysmonCollector as PlatformSysmon, WindowsSystemCollector as PlatformSystem,
};

#[cfg(not(windows))]
use andhak_edr_agent::collectors::portable_fallback::{
    PortableEventLogCollector as PlatformSysmon, PortableNetworkCollector as PlatformNetwork,
    PortableProcessCollector as PlatformProcess, PortableSystemCollector as PlatformSystem,
};

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "andhak-edr-agent",
    about = "ANDHAK EDR Endpoint Telemetry Sensor"
)]
struct Cli {
    #[arg(long, global = true, help = "Path to agent TOML configuration file")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Enroll this endpoint using a one-time operator bootstrap token
    Enroll {
        #[arg(long, help = "One-time bootstrap token issued by ANDHAK EDR backend")]
        token: String,
    },
    /// Report sensor readiness, local identity, and spool queue depth
    Status,
    /// Collect one real telemetry snapshot and optionally transmit to backend
    CollectOnce {
        #[arg(
            long,
            default_value_t = false,
            help = "Do not transmit to backend; print summary"
        )]
        dry_run: bool,
    },
    /// Run continuous endpoint monitoring, heartbeat, and TLS batch upload
    Run,
    /// Poll backend heartbeat once and execute/ack any approved response commands
    PollCommandsOnce,
}

#[tokio::main]
async fn main() {
    init_logging();
    if let Err(err) = run_cli().await {
        tracing::error!(error = %err, "ANDHAK EDR agent exited with error");
        std::process::exit(1);
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .json()
        .with_current_span(false)
        .init();
}

async fn run_cli() -> Result<(), AgentError> {
    let cli = Cli::parse();
    let cfg = AgentConfig::load(cli.config.as_deref())?;

    match cli.command {
        Commands::Enroll { token } => cmd_enroll(&cfg, &token).await,
        Commands::Status => cmd_status(&cfg),
        Commands::CollectOnce { dry_run } => cmd_collect_once(&cfg, dry_run).await,
        Commands::Run => cmd_run(cfg).await,
        Commands::PollCommandsOnce => cmd_poll_commands_once(&cfg).await,
    }
}

async fn cmd_enroll(cfg: &AgentConfig, bootstrap_token: &str) -> Result<(), AgentError> {
    let mut sys = PlatformSystem::new();
    let meta = sys.host_metadata();
    let sysmon = PlatformSysmon::new();
    let client = BackendClient::new(cfg)?;

    let req = EnrollmentRequest {
        bootstrap_token: bootstrap_token.to_string(),
        hostname: meta.hostname.clone(),
        fqdn: meta.fqdn,
        os_family: meta.os_family,
        os_version: meta.os_version,
        architecture: meta.architecture,
        agent_version: AGENT_VERSION.into(),
        primary_ip: meta.primary_ip,
        mac_address: meta.mac_address,
        elevated_sensor: meta.elevated_sensor,
        sysmon_available: sysmon.probe_available(),
    };

    let res = client.enroll(&req).await?;
    let state = AgentState {
        endpoint_id: res.endpoint_id.clone(),
        agent_token: res.agent_token,
        credential_id: res.credential_id.clone(),
        policy_version: res.policy.version,
    };
    state.save(&cfg.state_file)?;
    tracing::info!(
        endpoint_id = %res.endpoint_id,
        credential_id = %res.credential_id,
        state_file = %cfg.state_file.display(),
        "Endpoint enrolled successfully"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "enrolled": true,
            "endpoint_id": res.endpoint_id,
            "credential_id": res.credential_id,
            "policy_id": res.policy.policy_id,
            "policy_version": res.policy.version,
            "state_file": cfg.state_file
        }))?
    );
    Ok(())
}

fn cmd_status(cfg: &AgentConfig) -> Result<(), AgentError> {
    let mut sys = PlatformSystem::new();
    let meta = sys.host_metadata();
    let sysmon = PlatformSysmon::new();
    let spool = EventSpool::open(&cfg.spool_db_path, cfg.max_spool_events)?;
    let state = AgentState::load(&cfg.state_file)?;

    let status = serde_json::json!({
        "agent_version": AGENT_VERSION,
        "enrolled": state.is_some(),
        "endpoint_id": state.as_ref().map(|s| &s.endpoint_id),
        "backend_url": cfg.backend_url,
        "spool_queue_depth": spool.depth()?,
        "host": meta,
        "sensors": {
            "process": "ready",
            "network": if cfg!(windows) { "ready" } else { "unavailable" },
            "filesystem": if cfg.watch_paths.is_empty() { "unavailable" } else { "ready" },
            "system": "ready",
            "sysmon": sysmon.health(),
        }
    });
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

async fn cmd_collect_once(cfg: &AgentConfig, dry_run: bool) -> Result<(), AgentError> {
    let state = AgentState::load(&cfg.state_file)?;
    let endpoint_id = state
        .as_ref()
        .map(|s| s.endpoint_id.clone())
        .unwrap_or_else(|| "ep_unregistered_dryrun".into());

    let mut proc_col = PlatformProcess::new();
    let mut net_col = PlatformNetwork::new();
    let mut sys_col = PlatformSystem::new();
    let mut sysmon_col = PlatformSysmon::new();

    let mut events = proc_col.collect_delta(&endpoint_id)?;
    let proc_map = proc_col.active_process_map();
    events.extend(net_col.collect_sockets(&endpoint_id, &proc_map)?);
    let (_snap, sys_evt) = sys_col.collect_metrics(&endpoint_id, 0)?;
    events.push(sys_evt);
    events.extend(sysmon_col.collect_new(&endpoint_id)?);

    let spool = EventSpool::open(&cfg.spool_db_path, cfg.max_spool_events)?;
    let spooled = spool.enqueue(&events)?;

    let mut uploaded = 0usize;
    let mut duplicate_skipped = 0usize;
    if !dry_run {
        let creds = state.ok_or_else(|| {
            AgentError::Auth(
                "Agent is not enrolled; run `enroll --token ...` first or pass --dry-run".into(),
            )
        })?;
        let client = BackendClient::new(cfg)?;
        loop {
            let batch = spool.peek_batch(cfg.batch_max_events)?;
            if batch.is_empty() {
                break;
            }
            let row_ids: Vec<i64> = batch.iter().map(|(id, _)| *id).collect();
            let batch_events: Vec<TelemetryEventIn> = batch.into_iter().map(|(_, e)| e).collect();
            let batch_id = format!("batch-{}", Uuid::new_v4());
            match client
                .send_batch(
                    &creds.endpoint_id,
                    &creds.agent_token,
                    &batch_id,
                    batch_events,
                )
                .await?
            {
                Ok(resp) => {
                    uploaded += resp.accepted;
                    duplicate_skipped += resp.duplicate_skipped;
                    spool.ack_sent(&row_ids)?;
                }
                Err(wait) => {
                    tracing::warn!(?wait, "Backend requested backpressure during collect-once");
                    break;
                }
            }
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "endpoint_id": endpoint_id,
            "collected_events": events.len(),
            "spooled_new": spooled,
            "uploaded": uploaded,
            "duplicate_skipped": duplicate_skipped,
            "remaining_spool_depth": spool.depth()?,
            "dry_run": dry_run,
        }))?
    );
    Ok(())
}

async fn cmd_run(cfg: AgentConfig) -> Result<(), AgentError> {
    let mut creds = AgentState::load(&cfg.state_file)?.ok_or_else(|| {
        AgentError::Auth(
            "Agent state not found; run `andhak-edr-agent enroll --token <TOKEN>` first.".into(),
        )
    })?;
    let spool = EventSpool::open(&cfg.spool_db_path, cfg.max_spool_events)?;
    let client = BackendClient::new(&cfg)?;

    let mut proc_col = PlatformProcess::new();
    let mut net_col = PlatformNetwork::new();
    let mut sys_col = PlatformSystem::new();
    let mut sysmon_col = PlatformSysmon::new();
    let mut fs_watcher = FilesystemWatcher::start(&cfg.watch_paths, &cfg.exclusions)?;

    let (tx, mut rx) = mpsc::channel::<TelemetryEventIn>(cfg.channel_capacity);
    let started = Instant::now();

    // Perform initial baseline sweep before entering the reactive select loop so initial
    // binary hashing/Authenticode checks do not delay subsequent filesystem/flush ticks.
    if let Ok(initial_procs) = proc_col.collect_delta(&creds.endpoint_id) {
        let _ = spool.enqueue(&initial_procs);
    }
    let initial_map = proc_col.active_process_map();
    if let Ok(initial_nets) = net_col.collect_sockets(&creds.endpoint_id, &initial_map) {
        let _ = spool.enqueue(&initial_nets);
    }

    let mut proc_tick = tokio::time::interval(Duration::from_millis(cfg.process_poll_ms));
    let mut net_tick = tokio::time::interval(Duration::from_millis(cfg.network_poll_ms));
    let mut fs_tick = tokio::time::interval(Duration::from_millis(300));
    let mut flush_tick = tokio::time::interval(Duration::from_millis(cfg.flush_interval_ms));
    let mut hb_tick = tokio::time::interval(Duration::from_secs(cfg.heartbeat_seconds));

    let mut retry_attempt = 0u32;
    let mut next_upload_allowed = Instant::now();
    let mut latest_snap = sys_col
        .collect_metrics(&creds.endpoint_id, 0)
        .map(|(s, _)| s)
        .unwrap_or(andhak_edr_agent::collectors::SystemSnapshot {
            cpu_percent: 0.0,
            memory_used_mb: 0,
            memory_total_mb: 0,
            disk_used_percent: 0.0,
            agent_rss_mb: 0.0,
        });

    tracing::info!(
        endpoint_id = %creds.endpoint_id,
        backend_url = %cfg.backend_url,
        "ANDHAK EDR sensor loop started"
    );

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("Shutdown signal received; draining and flushing spool");
                while let Ok(evt) = rx.try_recv() {
                    let _ = spool.enqueue(&[evt]);
                }
                flush_pending(&client, &spool, &creds, cfg.batch_max_events).await;
                break;
            }
            Some(evt) = rx.recv() => {
                let mut batch = vec![evt];
                while batch.len() < 64 {
                    match rx.try_recv() {
                        Ok(more) => batch.push(more),
                        Err(_) => break,
                    }
                }
                if let Err(err) = spool.enqueue(&batch) {
                    tracing::error!(error = %err, "Failed to spool telemetry batch");
                }
            }
            _ = proc_tick.tick() => {
                match proc_col.collect_delta(&creds.endpoint_id) {
                    Ok(evts) => enqueue_channel(&tx, evts),
                    Err(err) => tracing::warn!(error = %err, "Process collection error"),
                }
            }
            _ = net_tick.tick() => {
                let map = proc_col.active_process_map();
                match net_col.collect_sockets(&creds.endpoint_id, &map) {
                    Ok(evts) => enqueue_channel(&tx, evts),
                    Err(err) => tracing::warn!(error = %err, "Network collection error"),
                }
                if let Ok(evts) = sysmon_col.collect_new(&creds.endpoint_id) {
                    enqueue_channel(&tx, evts);
                }
            }
            _ = fs_tick.tick() => {
                let evts = fs_watcher.drain_events();
                enqueue_channel(&tx, evts);
            }
            _ = hb_tick.tick() => {
                let uptime = started.elapsed().as_secs();
                if let Ok((snap, sys_evt)) = sys_col.collect_metrics(&creds.endpoint_id, uptime) {
                    latest_snap = snap;
                    enqueue_channel(&tx, vec![sys_evt]);
                }
                let depth = spool.depth().unwrap_or(0);
                let hb = HeartbeatRequest {
                    endpoint_id: creds.endpoint_id.clone(),
                    agent_version: AGENT_VERSION.into(),
                    uptime_seconds: uptime,
                    cpu_percent: latest_snap.cpu_percent,
                    memory_used_mb: latest_snap.memory_used_mb,
                    memory_total_mb: latest_snap.memory_total_mb,
                    disk_used_percent: latest_snap.disk_used_percent,
                    agent_rss_mb: latest_snap.agent_rss_mb,
                    spool_queue_depth: depth,
                    policy_version: creds.policy_version,
                    sensors: SensorHealthMap {
                        process: proc_col.health(),
                        network: net_col.health(),
                        filesystem: fs_watcher.health(),
                        system: sys_col.health(),
                        sysmon: sysmon_col.health(),
                    },
                };
                match client.heartbeat(&creds.endpoint_id, &creds.agent_token, &hb).await {
                    Ok(resp) => {
                        if resp.policy_update_available {
                            if let Ok(pol) = client.fetch_policy(&creds.endpoint_id, &creds.agent_token).await {
                                creds.policy_version = pol.version;
                                let _ = creds.save(&cfg.state_file);
                                tracing::info!(policy_version = pol.version, "Updated local policy metadata");
                            }
                        }
                        if !resp.pending_commands.is_empty() {
                            execute_pending_commands(&cfg, &client, &creds, &resp.pending_commands)
                                .await;
                        }
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "Heartbeat failed; retaining local sensor operation");
                    }
                }
            }
            _ = flush_tick.tick() => {
                if Instant::now() < next_upload_allowed {
                    continue;
                }
                if let Ok(batch) = spool.peek_batch(cfg.batch_max_events) {
                    if batch.is_empty() {
                        continue;
                    }
                    let row_ids: Vec<i64> = batch.iter().map(|(id, _)| *id).collect();
                    let events: Vec<TelemetryEventIn> = batch.into_iter().map(|(_, e)| e).collect();
                    let batch_id = format!("batch-{}", Uuid::new_v4());
                    match client.send_batch(&creds.endpoint_id, &creds.agent_token, &batch_id, events).await {
                        Ok(Ok(res)) => {
                            retry_attempt = 0;
                            let _ = spool.ack_sent(&row_ids);
                            tracing::debug!(
                                accepted = res.accepted,
                                dup = res.duplicate_skipped,
                                "Uploaded telemetry batch"
                            );
                        }
                        Ok(Err(hint)) => {
                            retry_attempt += 1;
                            let delay = backoff_delay(retry_attempt, hint);
                            next_upload_allowed = Instant::now() + delay;
                            tracing::warn!(delay_secs = delay.as_secs(), "Backend backpressure; backing off");
                        }
                        Err(err) => {
                            retry_attempt += 1;
                            let delay = backoff_delay(retry_attempt, None);
                            next_upload_allowed = Instant::now() + delay;
                            tracing::warn!(
                                error = %err,
                                delay_secs = delay.as_secs(),
                                "Upload failed; will retry from spool"
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn enqueue_channel(tx: &mpsc::Sender<TelemetryEventIn>, events: Vec<TelemetryEventIn>) {
    for evt in events {
        if let Err(err) = tx.try_send(evt) {
            tracing::warn!(error = %err, "Telemetry channel full; dropping oldest pressure overflow");
            break;
        }
    }
}

async fn flush_pending(
    client: &BackendClient,
    spool: &EventSpool,
    creds: &AgentState,
    batch_max: usize,
) {
    for _ in 0..5 {
        let Ok(batch) = spool.peek_batch(batch_max) else {
            break;
        };
        if batch.is_empty() {
            break;
        }
        let ids: Vec<i64> = batch.iter().map(|(id, _)| *id).collect();
        let events: Vec<TelemetryEventIn> = batch.into_iter().map(|(_, e)| e).collect();
        let batch_id = format!("flush-{}", Uuid::new_v4());
        if let Ok(Ok(_)) = client
            .send_batch(&creds.endpoint_id, &creds.agent_token, &batch_id, events)
            .await
        {
            let _ = spool.ack_sent(&ids);
        } else {
            break;
        }
    }
}

async fn execute_pending_commands(
    cfg: &AgentConfig,
    client: &BackendClient,
    creds: &AgentState,
    commands: &[PendingCommand],
) -> usize {
    let mut handled = 0usize;
    for cmd in commands {
        let ack = execute_command(cfg, cmd);
        tracing::info!(
            action_id = %cmd.action_id,
            action_type = %cmd.action_type,
            success = ack.success,
            "Executed response command"
        );
        match client
            .ack_command(&creds.endpoint_id, &creds.agent_token, &cmd.action_id, &ack)
            .await
        {
            Ok(resp) => {
                handled += 1;
                tracing::info!(action_id = %resp.action_id, status = %resp.status, "Acknowledged response command");
            }
            Err(err) => {
                tracing::error!(action_id = %cmd.action_id, error = %err, "Failed acknowledging response command");
            }
        }
    }
    handled
}

async fn cmd_poll_commands_once(cfg: &AgentConfig) -> Result<(), AgentError> {
    let creds = AgentState::load(&cfg.state_file)?.ok_or_else(|| {
        AgentError::Auth("Agent is not enrolled; run `enroll --token ...` first".into())
    })?;
    let client = BackendClient::new(cfg)?;
    let mut sys_col = PlatformSystem::new();
    let (snap, _) = sys_col.collect_metrics(&creds.endpoint_id, 1)?;
    let spool = EventSpool::open(&cfg.spool_db_path, cfg.max_spool_events)?;
    let depth = spool.depth().unwrap_or(0);
    let sysmon_col = PlatformSysmon::new();

    let hb = HeartbeatRequest {
        endpoint_id: creds.endpoint_id.clone(),
        agent_version: AGENT_VERSION.into(),
        uptime_seconds: 1,
        cpu_percent: snap.cpu_percent,
        memory_used_mb: snap.memory_used_mb,
        memory_total_mb: snap.memory_total_mb,
        disk_used_percent: snap.disk_used_percent,
        agent_rss_mb: snap.agent_rss_mb,
        spool_queue_depth: depth,
        policy_version: creds.policy_version,
        sensors: SensorHealthMap {
            process: andhak_edr_agent::models::SensorState::Ready,
            network: if cfg!(windows) {
                andhak_edr_agent::models::SensorState::Ready
            } else {
                andhak_edr_agent::models::SensorState::Unavailable
            },
            filesystem: if cfg.watch_paths.is_empty() {
                andhak_edr_agent::models::SensorState::Unavailable
            } else {
                andhak_edr_agent::models::SensorState::Ready
            },
            system: andhak_edr_agent::models::SensorState::Ready,
            sysmon: sysmon_col.health(),
        },
    };
    let resp = client
        .heartbeat(&creds.endpoint_id, &creds.agent_token, &hb)
        .await?;
    let handled = execute_pending_commands(cfg, &client, &creds, &resp.pending_commands).await;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "commands_received": resp.pending_commands.len(),
            "commands_acknowledged": handled,
        }))?
    );
    Ok(())
}
