import type {
  AlertRecord,
  AuditLogEntry,
  DetectionRule,
  EndpointDetail,
  EndpointSummary,
  FimBaseline,
  FimEvent,
  HealthInfo,
  IncidentDetail,
  IncidentRecord,
  InvestigationReport,
  IocRecord,
  MalwareAnalysis,
  OverviewData,
  QuarantineItem,
  ResponseAction,
  TelemetryEvent,
  UserSession,
} from "./types";

export class ApiError extends Error {
  status: number;
  code?: string;
  isOffline: boolean;

  constructor(message: string, status: number, code?: string, isOffline = false) {
    super(message);
    this.status = status;
    this.code = code;
    this.isOffline = isOffline;
  }
}

let authToken: string | null = null;

export function setAuthToken(token: string | null): void {
  authToken = token;
}

export function getAuthToken(): string | null {
  return authToken;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has("Content-Type") && init.body && typeof init.body === "string") {
    headers.set("Content-Type", "application/json");
  }
  if (authToken) {
    headers.set("Authorization", `Bearer ${authToken}`);
  }

  let res: Response;
  try {
    res = await fetch(path, { ...init, headers });
  } catch {
    throw new ApiError(
      "Unable to reach ANDHAK EDR backend API. Check local server connection.",
      0,
      "BACKEND_OFFLINE",
      true,
    );
  }

  const text = await res.text();
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    parsed = null;
  }

  if (!res.ok) {
    const errObj = parsed?.error as Record<string, unknown> | undefined;
    const msg =
      (errObj?.message as string | undefined) ||
      (parsed?.detail as string | undefined) ||
      `HTTP ${res.status}`;
    const code = errObj?.code as string | undefined;
    throw new ApiError(msg, res.status, code, false);
  }
  return parsed as T;
}

export const edrApi = {
  health: () => request<HealthInfo>("/api/v1/health"),
  login: (username: string, password: string) =>
    request<{ access_token: string; expires_at: string; user: UserSession }>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<UserSession>("/api/v1/auth/me"),
  overview: () => request<OverviewData>("/api/v1/overview"),
  endpoints: () => request<{ items: EndpointSummary[]; total: number }>("/api/v1/endpoints"),
  endpointDetail: (id: string) => request<EndpointDetail>(`/api/v1/endpoints/${id}`),
  telemetryEvents: (params: Record<string, string>) => {
    const q = new URLSearchParams(params).toString();
    return request<{ items: TelemetryEvent[]; total: number }>(
      `/api/v1/telemetry/events${q ? `?${q}` : ""}`,
    );
  },
  alerts: (params: Record<string, string> = {}) => {
    const q = new URLSearchParams(params).toString();
    return request<{ items: AlertRecord[]; total: number }>(
      `/api/v1/detections/alerts${q ? `?${q}` : ""}`,
    );
  },
  patchAlertStatus: (alertId: string, status: AlertRecord["status"]) =>
    request<AlertRecord>(`/api/v1/detections/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  rules: () => request<{ items: DetectionRule[]; total: number }>("/api/v1/detections/rules"),
  fimStatus: (endpointId?: string) =>
    request<{ baselines: FimBaseline[]; events: FimEvent[] }>(
      `/api/v1/fim/status${endpointId ? `?endpoint_id=${encodeURIComponent(endpointId)}` : ""}`,
    ),
  createFimBaseline: (endpointId: string, directory: string, recursive = true) =>
    request<Record<string, unknown>>("/api/v1/fim/baselines", {
      method: "POST",
      body: JSON.stringify({ endpoint_id: endpointId, directory, recursive }),
    }),
  malwareAnalyses: () =>
    request<{ items: MalwareAnalysis[]; total: number }>("/api/v1/malware/analyses"),
  scanMalware: (payload: {
    file_name: string;
    content_base64: string;
    endpoint_id?: string;
    file_path?: string;
    telemetry_origin?: string;
  }) =>
    request<MalwareAnalysis>("/api/v1/malware/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  iocs: () => request<{ items: IocRecord[]; total: number }>("/api/v1/intel/iocs"),
  addIoc: (value: string, severity: string, description: string) =>
    request<IocRecord>("/api/v1/intel/iocs", {
      method: "POST",
      body: JSON.stringify({ value, severity, description }),
    }),
  huntingSearch: (params: Record<string, string>) => {
    const clean = Object.fromEntries(Object.entries(params).filter(([, v]) => v.trim() !== ""));
    const q = new URLSearchParams(clean).toString();
    return request<{ items: TelemetryEvent[]; total: number }>(
      `/api/v1/hunting/search${q ? `?${q}` : ""}`,
    );
  },
  incidents: () => request<{ items: IncidentRecord[]; total: number }>("/api/v1/incidents"),
  incidentDetail: (incidentId: string) => request<IncidentDetail>(`/api/v1/incidents/${incidentId}`),
  investigateIncident: (incidentId: string) =>
    request<InvestigationReport>(`/api/v1/incidents/${incidentId}/investigate`, {
      method: "POST",
    }),
  collectForensics: (incidentId: string) =>
    request<{
      bundle_id: string;
      manifest_sha256: string;
      collected_at: string;
      bundle: Record<string, unknown>;
    }>(`/api/v1/incidents/${incidentId}/forensics`, {
      method: "POST",
      body: JSON.stringify({ collected_by: "edr_console_operator" }),
    }),
  responses: () => request<{ items: ResponseAction[]; total: number }>("/api/v1/responses"),
  proposeResponse: (payload: {
    endpoint_id: string;
    incident_id?: string | null;
    action_type: string;
    target_value: string;
    target_metadata?: Record<string, unknown>;
    reason: string;
  }) =>
    request<ResponseAction>("/api/v1/responses", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  decideResponse: (actionId: string, decision: "approve" | "reject", note: string) =>
    request<ResponseAction>(`/api/v1/responses/${actionId}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, note }),
    }),
  rollbackResponse: (actionId: string, reason: string) =>
    request<ResponseAction>(`/api/v1/responses/${actionId}/rollback`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  quarantine: () => request<{ items: QuarantineItem[]; total: number }>("/api/v1/quarantine"),
  audit: () =>
    request<{
      items: AuditLogEntry[];
      total: number;
      chain_verification: { valid: boolean; total_entries: number; head_hash?: string | null };
    }>("/api/v1/audit"),
  policies: () =>
    request<{ policy: Record<string, unknown>; retention: Record<string, number> }>(
      "/api/v1/policies",
    ),
  updatePolicies: (payload: Record<string, unknown>) =>
    request<{ policy: Record<string, unknown>; retention: Record<string, number> }>(
      "/api/v1/policies",
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  issueEnrollmentToken: (description: string) =>
    request<{ bootstrap_token: string; token_id: string; expires_at: string }>(
      "/api/v1/agent/enrollment-tokens",
      { method: "POST", body: JSON.stringify({ description, ttl_hours: 24 }) },
    ),
  socBridgeStatus: () => request<Record<string, unknown>>("/api/v1/soc-bridge/status"),
  socBridgeEvents: () =>
    request<{ items: Array<Record<string, unknown>>; total: number }>("/api/v1/soc-bridge/events"),
  socBridgeSync: () => request<Record<string, unknown>>("/api/v1/soc-bridge/sync", { method: "POST" }),
};

export type WsConnState = "connecting" | "connected" | "reconnecting" | "offline";

export function connectEdrWebSocket(
  channel: "telemetry" | "alerts" | "responses",
  onFrame: (frame: Record<string, unknown>) => void,
  onState: (state: WsConnState) => void,
): () => void {
  let closed = false;
  let ws: WebSocket | null = null;
  let retryTimer: number | null = null;
  let pingTimer: number | null = null;
  let attempt = 0;

  const open = () => {
    if (closed) return;
    onState(attempt === 0 ? "connecting" : "reconnecting");
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/ws/${channel}`;
    try {
      ws = new WebSocket(url);
    } catch {
      onState("offline");
      return;
    }

    ws.onopen = () => {
      attempt = 0;
      onState("connected");
      pingTimer = window.setInterval(() => {
        if (ws?.readyState === WebSocket.OPEN) {
          ws.send("ping");
        }
      }, 15000);
    };

    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data as string) as Record<string, unknown>;
        onFrame(data);
      } catch {
        // Ignore malformed frame safely
      }
    };

    ws.onclose = () => {
      if (pingTimer !== null) {
        window.clearInterval(pingTimer);
        pingTimer = null;
      }
      if (closed) return;
      attempt += 1;
      onState(attempt > 3 ? "offline" : "reconnecting");
      const delay = Math.min(10000, 1000 * Math.pow(2, Math.min(attempt, 3)));
      retryTimer = window.setTimeout(open, delay);
    };
  };

  open();
  return () => {
    closed = true;
    if (retryTimer !== null) window.clearTimeout(retryTimer);
    if (pingTimer !== null) window.clearInterval(pingTimer);
    ws?.close();
  };
}
