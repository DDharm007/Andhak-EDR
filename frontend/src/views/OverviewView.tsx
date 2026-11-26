import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AlertTriangle, Laptop, ShieldAlert, ShieldCheck } from "lucide-react";
import { edrApi } from "../api";
import { OriginBadge, SeverityBadge, StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { OverviewData, ViewId } from "../types";

export function OverviewView({
  onSelectEndpoint,
  onSelectIncident,
  onNavigate,
  refreshTick,
}: {
  onSelectEndpoint: (id: string) => void;
  onSelectIncident: (id: string) => void;
  onNavigate: (view: ViewId) => void;
  refreshTick: number;
}) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    edrApi
      .overview()
      .then((res) => {
        if (active) {
          setData(res);
          setError(null);
        }
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : "Failed to load overview");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [refreshTick]);

  const severityColors: Record<string, string> = {
    critical: "#D63A46",
    high: "#A92532",
    medium: "#D97706",
    low: "#64748B",
    info: "#475569",
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">Fleet Posture Overview</h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            Real-time endpoint telemetry, multi-engine detections, correlated incidents, and
            containment state.
          </p>
        </div>
        {data && (
          <div className="flex flex-wrap items-center gap-2">
            {Object.entries(data.telemetry_origins).map(([origin, count]) => (
              <div key={origin} className="flex items-center gap-1.5 text-xs font-mono">
                <OriginBadge origin={origin} />
                <span className="text-[#9A9CA6]">({count})</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {error && (
        <div
          role="alert"
          className="rounded border border-[#D63A46] bg-[#D63A46]/15 p-3 text-sm text-[#FF9CA4]"
        >
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4">
          <div className="flex items-center justify-between text-xs font-mono text-[#9A9CA6]">
            <span>ENDPOINTS ONLINE</span>
            <Laptop className="w-4 h-4 text-[#E8E7E3]" aria-hidden="true" />
          </div>
          <div className="mt-2 text-2xl font-mono font-semibold text-[#E8E7E3]">
            {loading ? "--" : `${data?.kpis.endpoints_online ?? 0} / ${data?.kpis.endpoints_total ?? 0}`}
          </div>
          <div className="mt-1 text-xs text-[#9A9CA6]">
            Isolated: {data?.kpis.endpoints_isolated ?? 0} · Degraded:{" "}
            {data?.kpis.endpoints_degraded ?? 0}
          </div>
        </div>

        <div className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4">
          <div className="flex items-center justify-between text-xs font-mono text-[#9A9CA6]">
            <span>OPEN ALERTS</span>
            <ShieldAlert className="w-4 h-4 text-[#D63A46]" aria-hidden="true" />
          </div>
          <div className="mt-2 text-2xl font-mono font-semibold text-[#FF949C]">
            {loading ? "--" : (data?.kpis.alerts_open ?? 0)}
          </div>
          <div className="mt-1 text-xs text-[#9A9CA6]">
            Critical: {data?.kpis.alerts_critical ?? 0} · High: {data?.kpis.alerts_high ?? 0}
          </div>
        </div>

        <div className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4">
          <div className="flex items-center justify-between text-xs font-mono text-[#9A9CA6]">
            <span>CORRELATED INCIDENTS</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" aria-hidden="true" />
          </div>
          <div className="mt-2 text-2xl font-mono font-semibold text-[#E8E7E3]">
            {loading ? "--" : (data?.kpis.incidents_open ?? 0)}
          </div>
          <div className="mt-1 text-xs text-[#9A9CA6]">
            Events stored: {data?.kpis.telemetry_events_total ?? 0}
          </div>
        </div>

        <div className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4">
          <div className="flex items-center justify-between text-xs font-mono text-[#9A9CA6]">
            <span>RESPONSE & VAULT</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-2 text-2xl font-mono font-semibold text-[#E8E7E3]">
            {loading ? "--" : `${data?.kpis.pending_approvals ?? 0} pending`}
          </div>
          <div className="mt-1 text-xs text-[#9A9CA6]">
            Quarantined files: {data?.kpis.quarantined_files ?? 0}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <section className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4">
          <h2 className="text-sm font-semibold text-[#E8E7E3] mb-3">
            Detections by Severity & Engine
          </h2>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.severity_breakdown ?? []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#252730" />
                <XAxis dataKey="severity" stroke="#9A9CA6" fontSize={12} />
                <YAxis stroke="#9A9CA6" fontSize={12} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#1D1E24",
                    borderColor: "#303139",
                    color: "#E8E7E3",
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {(data?.severity_breakdown ?? []).map((entry) => (
                    <Cell
                      key={entry.severity}
                      fill={severityColors[entry.severity] ?? "#64748B"}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4">
          <h2 className="text-sm font-semibold text-[#E8E7E3] mb-3">
            Top MITRE ATT&amp;CK Techniques Observed
          </h2>
          {data?.top_mitre_techniques && data.top_mitre_techniques.length > 0 ? (
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.top_mitre_techniques} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#252730" />
                  <XAxis type="number" stroke="#9A9CA6" fontSize={12} allowDecimals={false} />
                  <YAxis dataKey="technique_id" type="category" stroke="#E8E7E3" fontSize={11} width={86} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#1D1E24",
                      borderColor: "#303139",
                      color: "#E8E7E3",
                    }}
                  />
                  <Bar dataKey="count" fill="#A92532" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-sm text-[#9A9CA6] py-16 text-center">
              No MITRE ATT&amp;CK techniques triggered yet.
            </p>
          )}
        </section>
      </div>

      <DataTable
        caption="Recent Correlated Incidents"
        rows={data?.recent_incidents ?? []}
        loading={loading}
        rowKey={(r) => r.incident_id}
        emptyMessage="No correlated incidents recorded yet."
        columns={[
          {
            key: "id",
            label: "Incident",
            render: (inc) => (
              <button
                type="button"
                onClick={() => {
                  onSelectIncident(inc.incident_id);
                  onNavigate("investigation");
                }}
                className="font-mono text-xs text-[#FF949C] hover:underline text-left"
              >
                {inc.title}
              </button>
            ),
          },
          {
            key: "sev",
            label: "Severity",
            render: (inc) => <SeverityBadge severity={inc.severity} />,
          },
          {
            key: "risk",
            label: "Risk / Conf",
            render: (inc) => (
              <span className="font-mono text-xs">
                {inc.risk_score}/100 ({(inc.confidence * 100).toFixed(0)}%)
              </span>
            ),
          },
          {
            key: "alerts",
            label: "Alerts",
            render: (inc) => <span className="font-mono">{inc.alert_count}</span>,
          },
          {
            key: "origin",
            label: "Origin",
            render: (inc) => <OriginBadge origin={inc.telemetry_origin} />,
          },
          {
            key: "status",
            label: "Status",
            render: (inc) => <StatusPill status={inc.status} />,
          },
        ]}
      />

      <DataTable
        caption="Enrolled Endpoints Snapshot"
        rows={data?.endpoints ?? []}
        loading={loading}
        rowKey={(e) => e.endpoint_id}
        emptyMessage="No endpoints enrolled. Provision an enrollment token under Agents & SOC."
        columns={[
          {
            key: "host",
            label: "Hostname",
            render: (e) => (
              <button
                type="button"
                onClick={() => {
                  onSelectEndpoint(e.endpoint_id);
                  onNavigate("endpoint-detail");
                }}
                className="font-mono text-[#E8E7E3] font-semibold hover:text-[#FF949C] hover:underline"
              >
                {e.hostname}
              </button>
            ),
          },
          { key: "os", label: "OS", render: (e) => <span>{e.os_version}</span> },
          { key: "status", label: "Status", render: (e) => <StatusPill status={e.status} /> },
          {
            key: "sysmon",
            label: "Sysmon",
            render: (e) => (
              <span className="font-mono text-xs text-[#9A9CA6]">
                {e.sysmon_available ? "ready" : "unavailable"}
              </span>
            ),
          },
          { key: "origin", label: "Origin", render: (e) => <OriginBadge origin={e.telemetry_origin} /> },
        ]}
      />
    </div>
  );
}
