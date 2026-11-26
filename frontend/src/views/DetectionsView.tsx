import { useEffect, useState } from "react";
import { edrApi } from "../api";
import { OriginBadge, SeverityBadge, StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { AlertRecord, DetectionRule } from "../types";

export function DetectionsView({
  onSelectIncident,
  refreshTick,
}: {
  onSelectIncident: (incidentId: string) => void;
  refreshTick: number;
}) {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [sevFilter, setSevFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    const params: Record<string, string> = {};
    if (sevFilter) params.severity = sevFilter;
    Promise.all([edrApi.alerts(params), edrApi.rules()])
      .then(([aRes, rRes]) => {
        setAlerts(aRes.items);
        setRules(rRes.items);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load detections"))
      .finally(() => setLoading(false));
  };

  useEffect(load, [sevFilter, refreshTick]);

  const setStatus = async (alertId: string, status: AlertRecord["status"]) => {
    try {
      await edrApi.patchAlertStatus(alertId, status);
      load();
    } catch {
      // Handled gracefully
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">Detection Center</h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            Multi-engine alerts keeping Severity, Confidence, and Risk Score strictly independent.
          </p>
        </div>

        <div>
          <label htmlFor="det-sev" className="block text-xs font-mono text-[#9A9CA6] mb-1">
            Severity filter
          </label>
          <select
            id="det-sev"
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value)}
            className="edr-input"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      <DataTable
        caption="Detection Alerts Queue"
        rows={alerts}
        loading={loading}
        error={error}
        rowKey={(a) => a.alert_id}
        columns={[
          {
            key: "rule",
            label: "Rule / Engine",
            render: (a) => (
              <div>
                <div className="font-mono font-semibold text-xs text-[#E8E7E3]">
                  [{a.rule_id}] {a.rule_name}
                </div>
                <div className="text-[11px] font-mono text-[#9A9CA6]">
                  Engine: {a.detection_source} · {a.mitre_techniques.join(", ") || "unmapped"}
                </div>
              </div>
            ),
          },
          { key: "sev", label: "Severity", render: (a) => <SeverityBadge severity={a.severity} /> },
          {
            key: "score",
            label: "Conf / Risk",
            render: (a) => (
              <span className="font-mono text-xs">
                {(a.confidence * 100).toFixed(0)}% / {a.risk_score}
              </span>
            ),
          },
          {
            key: "evidence",
            label: "Evidence Summary",
            render: (a) => <span className="text-xs">{a.evidence_summary}</span>,
          },
          { key: "origin", label: "Origin", render: (a) => <OriginBadge origin={a.telemetry_origin} /> },
          { key: "status", label: "Status", render: (a) => <StatusPill status={a.status} /> },
          {
            key: "actions",
            label: "Triage",
            render: (a) => (
              <div className="flex flex-wrap gap-1.5">
                {a.incident_id && (
                  <button
                    type="button"
                    onClick={() => onSelectIncident(a.incident_id!)}
                    className="px-2 py-1 rounded border border-[#A92532] text-[11px] font-mono text-[#FF949C] hover:bg-[#A92532] hover:text-white"
                  >
                    Incident
                  </button>
                )}
                {a.status === "open" && (
                  <button
                    type="button"
                    onClick={() => setStatus(a.alert_id, "investigating")}
                    className="px-2 py-1 rounded border border-[#303139] text-[11px] font-mono hover:border-[#A92532]"
                  >
                    Investigate
                  </button>
                )}
                {a.status !== "resolved" && (
                  <button
                    type="button"
                    onClick={() => setStatus(a.alert_id, "resolved")}
                    className="px-2 py-1 rounded border border-[#303139] text-[11px] font-mono hover:border-emerald-600"
                  >
                    Resolve
                  </button>
                )}
              </div>
            ),
          },
        ]}
      />

      <DataTable
        caption="Active Detection Rules & Provenance"
        rows={rules}
        loading={loading}
        rowKey={(r) => r.rule_id}
        columns={[
          { key: "id", label: "Rule ID", render: (r) => <span className="font-mono">{r.rule_id}</span> },
          { key: "name", label: "Name", render: (r) => r.name },
          { key: "src", label: "Engine", render: (r) => <span className="font-mono">{r.source}</span> },
          { key: "sev", label: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
          {
            key: "lic",
            label: "License / Attribution",
            render: (r) => (
              <span className="text-xs text-[#9A9CA6]">
                {r.license} · {r.attribution}
              </span>
            ),
          },
        ]}
      />
    </div>
  );
}
