-- ============================================================================
-- ANDHAK EDR — Canonical Relational Database Schema (Stage 01 Contract)
-- Primary local target: SQLite 3.45+ (WAL mode, PRAGMA foreign_keys = ON)
-- Production parity target: PostgreSQL 16+ (identical table/column semantics)
-- Note: Timestamps are stored as UTC ISO-8601 TEXT in SQLite (TIMESTAMPTZ in PG).
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. RBAC Analyst Users
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'responder', 'analyst', 'readonly_demo')),
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

-- ----------------------------------------------------------------------------
-- 2. Endpoint Inventory & Agent Credentials
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    fqdn TEXT,
    os_family TEXT NOT NULL CHECK (os_family IN ('windows', 'linux', 'macos')),
    os_version TEXT NOT NULL,
    architecture TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    primary_ip TEXT,
    mac_address TEXT,
    status TEXT NOT NULL CHECK (status IN ('online', 'degraded', 'offline', 'isolated', 'decommissioned')),
    isolation_state TEXT NOT NULL DEFAULT 'none' CHECK (isolation_state IN ('none', 'isolating', 'isolated', 'releasing')),
    posture_score INTEGER NOT NULL DEFAULT 100 CHECK (posture_score BETWEEN 0 AND 100),
    policy_id TEXT,
    policy_version INTEGER NOT NULL DEFAULT 1,
    sysmon_available INTEGER NOT NULL DEFAULT 0,
    elevated_sensor INTEGER NOT NULL DEFAULT 0,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture')),
    enrolled_at TEXT NOT NULL,
    last_heartbeat_at TEXT,
    last_metrics_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status, last_heartbeat_at DESC);
CREATE INDEX IF NOT EXISTS idx_endpoints_hostname ON endpoints(hostname);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL REFERENCES users(user_id),
    expires_at TEXT NOT NULL,
    used_at TEXT,
    used_by_endpoint_id TEXT REFERENCES endpoints(endpoint_id)
);

CREATE TABLE IF NOT EXISTS agent_credentials (
    credential_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    key_version INTEGER NOT NULL DEFAULT 1,
    revoked INTEGER NOT NULL DEFAULT 0,
    issued_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_creds_endpoint ON agent_credentials(endpoint_id, revoked);

-- ----------------------------------------------------------------------------
-- 3. Policies & Baseline Configuration
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    version INTEGER NOT NULL DEFAULT 1,
    fim_paths_json TEXT NOT NULL DEFAULT '[]',
    exclusions_json TEXT NOT NULL DEFAULT '[]',
    collection_intervals_json TEXT NOT NULL DEFAULT '{}',
    intel_external_enabled INTEGER NOT NULL DEFAULT 0,
    allow_file_upload INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS retention_policies (
    domain TEXT PRIMARY KEY,
    retention_days INTEGER NOT NULL CHECK (retention_days >= 1),
    updated_at TEXT NOT NULL
);

-- ----------------------------------------------------------------------------
-- 4. Normalized Endpoint Telemetry
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture')),
    category TEXT NOT NULL CHECK (category IN ('process', 'network', 'filesystem', 'system', 'sysmon', 'fim')),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    occurred_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    process_guid TEXT,
    pid INTEGER,
    ppid INTEGER,
    process_name TEXT,
    executable_path TEXT,
    sha256 TEXT,
    command_line TEXT,
    user_context TEXT,
    signature_status TEXT,
    source_ip TEXT,
    source_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    protocol TEXT,
    file_path TEXT,
    dedup_hash TEXT NOT NULL,
    raw_payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_telemetry_endpoint_time ON telemetry_events(endpoint_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_category_time ON telemetry_events(category, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_sha256 ON telemetry_events(sha256);
CREATE INDEX IF NOT EXISTS idx_telemetry_process_guid ON telemetry_events(process_guid);
CREATE INDEX IF NOT EXISTS idx_telemetry_dest_ip ON telemetry_events(dest_ip);
CREATE UNIQUE INDEX IF NOT EXISTS idx_telemetry_dedup ON telemetry_events(endpoint_id, dedup_hash);

CREATE TABLE IF NOT EXISTS process_executions (
    process_guid TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    parent_process_guid TEXT,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    process_name TEXT NOT NULL,
    executable_path TEXT NOT NULL,
    command_line TEXT NOT NULL DEFAULT '',
    user_context TEXT NOT NULL DEFAULT '',
    sha256 TEXT,
    signature_status TEXT NOT NULL DEFAULT 'unknown',
    signer_subject TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture'))
);
CREATE INDEX IF NOT EXISTS idx_proc_endpoint_started ON process_executions(endpoint_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_proc_parent ON process_executions(parent_process_guid);

CREATE TABLE IF NOT EXISTS network_sockets (
    socket_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    process_guid TEXT,
    pid INTEGER,
    process_name TEXT,
    protocol TEXT NOT NULL,
    local_addr TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_addr TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture'))
);
CREATE INDEX IF NOT EXISTS idx_sockets_endpoint_obs ON network_sockets(endpoint_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_sockets_remote ON network_sockets(remote_addr, remote_port);

-- ----------------------------------------------------------------------------
-- 5. File Integrity Monitoring (FIM) & Static Malware Analysis
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fim_baselines (
    baseline_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    policy_id TEXT NOT NULL REFERENCES policies(policy_id),
    file_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    signature_status TEXT NOT NULL DEFAULT 'unknown',
    signer_subject TEXT,
    modified_at TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    UNIQUE(endpoint_id, file_path)
);

CREATE TABLE IF NOT EXISTS fim_events (
    fim_event_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    change_type TEXT NOT NULL CHECK (change_type IN ('created', 'modified', 'deleted', 'renamed', 'signature_changed')),
    baseline_sha256 TEXT,
    observed_sha256 TEXT,
    baseline_signature TEXT,
    observed_signature TEXT,
    authorized INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    detected_at TEXT NOT NULL,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture'))
);
CREATE INDEX IF NOT EXISTS idx_fim_events_endpoint_time ON fim_events(endpoint_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS malware_analyses (
    analysis_id TEXT PRIMARY KEY,
    endpoint_id TEXT REFERENCES endpoints(endpoint_id) ON DELETE SET NULL,
    file_name TEXT NOT NULL,
    file_path TEXT,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    file_type TEXT NOT NULL DEFAULT 'unknown',
    yara_matches_json TEXT NOT NULL DEFAULT '[]',
    ember_score REAL CHECK (ember_score IS NULL OR (ember_score >= 0.0 AND ember_score <= 1.0)),
    ember_model_version TEXT,
    ember_provenance TEXT,
    signature_status TEXT NOT NULL DEFAULT 'unknown',
    signer_subject TEXT,
    ioc_reputation_json TEXT NOT NULL DEFAULT '{}',
    verdict TEXT NOT NULL CHECK (verdict IN ('clean', 'suspicious', 'malicious', 'unknown')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    analyzed_at TEXT NOT NULL,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture'))
);
CREATE INDEX IF NOT EXISTS idx_malware_sha256 ON malware_analyses(sha256);

-- ----------------------------------------------------------------------------
-- 6. Threat Intelligence & Detection Alerts
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    ioc_id TEXT PRIMARY KEY,
    value TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kind TEXT NOT NULL CHECK (kind IN ('ip', 'domain', 'url', 'file_hash')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    source TEXT NOT NULL DEFAULT 'local',
    description TEXT NOT NULL DEFAULT '',
    mitre_tags_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_iocs_kind_value ON iocs(kind, value);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('yara_x', 'ember', 'fim', 'behavioral', 'ioc', 'sysmon')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    description TEXT NOT NULL,
    mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
    license TEXT NOT NULL DEFAULT 'MIT',
    attribution TEXT NOT NULL DEFAULT 'ANDHAK EDR',
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    detection_source TEXT NOT NULL CHECK (detection_source IN ('yara_x', 'ember', 'fim', 'behavioral', 'ioc', 'sysmon')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    process_guid TEXT,
    pid INTEGER,
    process_name TEXT,
    file_sha256 TEXT,
    evidence_event_ids_json TEXT NOT NULL DEFAULT '[]',
    evidence_summary TEXT NOT NULL,
    mitre_tactics_json TEXT NOT NULL DEFAULT '[]',
    mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
    recommended_actions_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    incident_id TEXT,
    dedup_key TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_endpoint_time ON alerts(endpoint_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_status ON alerts(severity, status);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key, detected_at DESC);

-- ----------------------------------------------------------------------------
-- 7. Incident Correlation, Forensics & Deterministic Investigation
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'contained', 'resolved', 'closed')),
    root_process_guid TEXT,
    mitre_tactics_json TEXT NOT NULL DEFAULT '[]',
    mitre_techniques_json TEXT NOT NULL DEFAULT '[]',
    alert_count INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    telemetry_origin TEXT NOT NULL DEFAULT 'real_endpoint'
        CHECK (telemetry_origin IN ('real_endpoint', 'recorded_demo', 'test_fixture'))
);
CREATE INDEX IF NOT EXISTS idx_incidents_status_time ON incidents(status, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS deterministic_investigations (
    investigation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    engine_mode TEXT NOT NULL DEFAULT 'deterministic_rules_v1',
    summary_narrative TEXT NOT NULL,
    timeline_json TEXT NOT NULL DEFAULT '[]',
    process_tree_json TEXT NOT NULL DEFAULT '{}',
    mitre_evidence_json TEXT NOT NULL DEFAULT '[]',
    false_positive_checks_json TEXT NOT NULL DEFAULT '[]',
    recommended_runbook_json TEXT NOT NULL DEFAULT '[]',
    cited_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS forensic_bundles (
    bundle_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    collected_by TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    bundle_json TEXT NOT NULL,
    collected_at TEXT NOT NULL
);

-- ----------------------------------------------------------------------------
-- 8. Controlled Response, Quarantine & Tamper-Evident Audit Log
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS response_actions (
    action_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    incident_id TEXT REFERENCES incidents(incident_id) ON DELETE SET NULL,
    action_type TEXT NOT NULL CHECK (
        action_type IN (
            'isolate_endpoint', 'release_isolation',
            'terminate_process', 'quarantine_file', 'restore_file',
            'block_network_indicator', 'push_policy'
        )
    ),
    target_value TEXT NOT NULL,
    target_metadata_json TEXT NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN (
            'pending_approval', 'approved', 'rejected', 'dispatched',
            'executed', 'failed', 'rolled_back'
        )
    ),
    requested_by TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    approved_by TEXT,
    decided_at TEXT,
    decision_note TEXT,
    executed_at TEXT,
    verification_json TEXT NOT NULL DEFAULT '{}',
    rollback_action_id TEXT,
    soc_approval_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_responses_status_time ON response_actions(status, requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_responses_endpoint ON response_actions(endpoint_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS quarantine_vault (
    quarantine_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    action_id TEXT NOT NULL REFERENCES response_actions(action_id),
    original_path TEXT NOT NULL,
    vault_path TEXT NOT NULL,
    sha256_before TEXT NOT NULL,
    sha256_after TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('quarantined', 'restored', 'purged')),
    quarantined_at TEXT NOT NULL,
    restored_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

-- ----------------------------------------------------------------------------
-- 9. ANDHAK SOC Bridge Sync Log
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS soc_bridge_sync_log (
    sync_id TEXT PRIMARY KEY,
    direction TEXT NOT NULL CHECK (direction IN ('edr_to_soc', 'soc_to_edr')),
    entity_type TEXT NOT NULL CHECK (entity_type IN ('event', 'alert', 'ioc', 'response', 'heartbeat')),
    entity_id TEXT NOT NULL,
    soc_reference_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'synced', 'failed')),
    detail TEXT NOT NULL DEFAULT '',
    synced_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_soc_sync_status ON soc_bridge_sync_log(status, synced_at DESC);
