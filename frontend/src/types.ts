export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type TelemetryOrigin = "real_endpoint" | "recorded_demo" | "test_fixture";
export type Role = "admin" | "responder" | "analyst" | "readonly_demo";

export type ViewId =
  | "overview"
  | "endpoints"
  | "endpoint-detail"
  | "telemetry"
  | "detections"
  | "integrity"
  | "malware"
  | "hunting"
  | "attack-graph"
  | "investigation"
  | "responses"
  | "management";

export interface HealthInfo {
  status: string;
  service: string;
  version: string;
  mode: "live" | "demo";
  database_path: string;
}

export interface UserSession {
  user_id: string;
  username: string;
  display_name: string;
  role: Role;
}

export interface EndpointSummary {
  endpoint_id: string;
  hostname: string;
  fqdn?: string | null;
  os_family: string;
  os_version: string;
  architecture: string;
  agent_version: string;
  primary_ip?: string | null;
  status: "online" | "degraded" | "offline" | "isolated" | "decommissioned";
  isolation_state: "none" | "isolating" | "isolated" | "releasing";
  posture_score: number;
  policy_version: number;
  sysmon_available: number | boolean;
  elevated_sensor: number | boolean;
  telemetry_origin: TelemetryOrigin;
  enrolled_at: string;
  last_heartbeat_at?: string | null;
  last_metrics: {
    cpu_percent?: number;
    memory_used_mb?: number;
    memory_total_mb?: number;
    disk_used_percent?: number;
    agent_rss_mb?: number;
    spool_queue_depth?: number;
    sensors?: Record<string, string>;
  };
}

export interface TelemetryEvent {
  event_id: string;
  endpoint_id: string;
  telemetry_origin: TelemetryOrigin;
  category: string;
  event_type: string;
  severity: Severity;
  occurred_at: string;
  ingested_at: string;
  process_guid?: string | null;
  pid?: number | null;
  ppid?: number | null;
  process_name?: string | null;
  executable_path?: string | null;
  sha256?: string | null;
  command_line?: string | null;
  user_context?: string | null;
  signature_status?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  protocol?: string | null;
  file_path?: string | null;
}

export interface AlertRecord {
  alert_id: string;
  endpoint_id: string;
  rule_id: string;
  rule_name: string;
  detection_source: string;
  severity: Severity;
  confidence: number;
  risk_score: number;
  process_guid?: string | null;
  pid?: number | null;
  process_name?: string | null;
  file_sha256?: string | null;
  evidence_event_ids: string[];
  evidence_summary: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  recommended_actions: string[];
  status: "open" | "investigating" | "resolved" | "false_positive";
  incident_id?: string | null;
  detected_at: string;
  telemetry_origin: TelemetryOrigin;
}

export interface IncidentRecord {
  incident_id: string;
  title: string;
  endpoint_id: string;
  severity: Severity;
  confidence: number;
  risk_score: number;
  status: "open" | "contained" | "resolved" | "closed";
  root_process_guid?: string | null;
  mitre_tactics: string[];
  mitre_techniques: string[];
  alert_count: number;
  first_seen_at: string;
  last_seen_at: string;
  telemetry_origin: TelemetryOrigin;
}

export interface ProcessTreeNode {
  process_guid: string;
  parent_process_guid?: string | null;
  pid: number;
  ppid: number;
  process_name: string;
  executable_path: string;
  command_line: string;
  user_context: string;
  sha256?: string | null;
  signature_status: string;
  signer_subject?: string | null;
  started_at: string;
  alerts: Array<{
    alert_id: string;
    rule_id: string;
    rule_name: string;
    severity: Severity;
    confidence: number;
  }>;
  network_connections: Array<{
    socket_id: string;
    protocol: string;
    remote_addr: string;
    remote_port: number;
    state: string;
  }>;
  children: ProcessTreeNode[];
}

export interface InvestigationReport {
  investigation_id: string;
  incident_id: string;
  engine_mode: string;
  summary_narrative: string;
  false_positive_checks: Array<{ check: string; status: string; detail: string }>;
  recommended_runbook: Array<{
    priority: number;
    action_type: string;
    target: string;
    process_name?: string;
    rationale: string;
    requires_approval: boolean;
  }>;
  cited_evidence_ids: string[];
  created_at: string;
}

export interface IncidentDetail extends IncidentRecord {
  endpoint: EndpointSummary | null;
  alerts: AlertRecord[];
  process_tree: ProcessTreeNode[];
  process_count: number;
  graph: {
    nodes: Array<{
      id: string;
      type?: string;
      position: { x: number; y: number };
      data: Record<string, unknown>;
    }>;
    edges: Array<{
      id: string;
      source: string;
      target: string;
      label?: string;
    }>;
  };
  timeline: Array<{
    timestamp: string;
    entry_type: string;
    id: string;
    severity: Severity;
    source: string;
    title: string;
    detail: string;
    process_name?: string | null;
    pid?: number | null;
    mitre_techniques: string[];
  }>;
  mitre_evidence: Array<{
    technique_id: string;
    tactic: string;
    technique_name: string;
    supporting_alert_ids: string[];
    supporting_event_ids: string[];
    supporting_rules: string[];
  }>;
  latest_investigation: InvestigationReport | null;
  forensic_bundles: Array<{
    bundle_id: string;
    collected_by: string;
    manifest_sha256: string;
    collected_at: string;
  }>;
}

export interface OverviewData {
  mode: "live" | "demo";
  kpis: {
    endpoints_total: number;
    endpoints_online: number;
    endpoints_isolated: number;
    endpoints_degraded: number;
    telemetry_events_total: number;
    alerts_open: number;
    alerts_critical: number;
    alerts_high: number;
    incidents_open: number;
    pending_approvals: number;
    quarantined_files: number;
  };
  severity_breakdown: Array<{ severity: Severity; count: number }>;
  source_breakdown: Array<{ source: string; count: number }>;
  top_mitre_techniques: Array<{ technique_id: string; count: number }>;
  alert_timeline: Array<{ bucket: string; alerts: number }>;
  telemetry_origins: Record<string, number>;
  websocket_subscribers: Record<string, number>;
  endpoints: EndpointSummary[];
  recent_alerts: AlertRecord[];
  recent_incidents: IncidentRecord[];
}

export interface ResponseAction {
  action_id: string;
  endpoint_id: string;
  incident_id?: string | null;
  action_type: string;
  target_value: string;
  reason: string;
  status: string;
  requested_by: string;
  requested_at: string;
  approved_by?: string | null;
  decided_at?: string | null;
  decision_note?: string | null;
  executed_at?: string | null;
  rollback_action_id?: string | null;
  soc_approval_id?: string | null;
  target_metadata: Record<string, unknown>;
  verification: Record<string, unknown>;
}

export interface QuarantineItem {
  quarantine_id: string;
  endpoint_id: string;
  action_id: string;
  original_path: string;
  vault_path: string;
  sha256_before: string;
  sha256_after: string;
  size_bytes: number;
  status: "quarantined" | "restored" | "purged";
  quarantined_at: string;
  restored_at?: string | null;
}

export interface AuditLogEntry {
  seq: number;
  audit_id: string;
  actor_id: string;
  actor_role: string;
  action: string;
  resource_type: string;
  resource_id: string;
  detail: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
  created_at: string;
}

export interface MalwareAnalysis {
  analysis_id: string;
  endpoint_id?: string | null;
  file_name: string;
  file_path?: string | null;
  sha256: string;
  size_bytes: number;
  file_type: string;
  yara_matches: Array<Record<string, unknown>>;
  ember_score?: number | null;
  ember_model_version?: string | null;
  ember_provenance?: string | null;
  signature_status: string;
  signer_subject?: string | null;
  ioc_reputation: Record<string, unknown>;
  verdict: string;
  confidence: number;
  analyzed_at: string;
  telemetry_origin: TelemetryOrigin;
}

export interface FimBaseline {
  baseline_id: string;
  endpoint_id: string;
  file_path: string;
  sha256: string;
  size_bytes: number;
  signature_status: string;
  modified_at: string;
  captured_at: string;
}

export interface FimEvent {
  fim_event_id: string;
  endpoint_id: string;
  file_path: string;
  change_type: string;
  baseline_sha256?: string | null;
  observed_sha256?: string | null;
  baseline_signature?: string | null;
  observed_signature?: string | null;
  severity: Severity;
  detected_at: string;
  telemetry_origin: TelemetryOrigin;
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  source: string;
  severity: Severity;
  description: string;
  mitre_techniques: string[];
  license: string;
  attribution: string;
  enabled: number;
}

export interface IocRecord {
  ioc_id: string;
  value: string;
  kind: "ip" | "domain" | "url" | "file_hash";
  severity: Severity;
  source: string;
  description: string;
  mitre_tags: string[];
  created_at: string;
}

export interface EndpointDetail {
  endpoint: EndpointSummary;
  processes: Array<Record<string, unknown>>;
  network_sockets: Array<Record<string, unknown>>;
  telemetry_events: TelemetryEvent[];
  alerts: AlertRecord[];
  fim_baselines: FimBaseline[];
  fim_events: FimEvent[];
  responses: ResponseAction[];
  quarantine: QuarantineItem[];
}
