import { useEffect, useState } from "react";
import { edrApi } from "../api";
import { OriginBadge, SeverityBadge, StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { EndpointDetail } from "../types";

export function EndpointDetailView({
  endpointId,
  onSelectEndpoint,
  onGoResponses,
}: {
  endpointId: string | null;
  onSelectEndpoint: (id: string) => void;
  onGoResponses: () => void;
}) {
  const [detail, setDetail] = useState<EndpointDetail | null>(null);
  const [endpoints, setEndpoints] = useState<Array<{ endpoint_id: string; hostname: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  useEffect(() => {
    edrApi
      .endpoints()
      .then((res) => {
        setEndpoints(res.items);
        if (!endpointId && res.items.length > 0) {
          onSelectEndpoint(res.items[0].endpoint_id);
        }
      })
      .catch(() => {});
  }, [endpointId, onSelectEndpoint]);

  useEffect(() => {
    if (!endpointId) return;
    setLoading(true);
    edrApi
      .endpointDetail(endpointId)
      .then((d) => {
        setDetail(d);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load endpoint"))
      .finally(() => setLoading(false));
  }, [endpointId]);

  const handleProposeIsolation = async () => {
    if (!detail) return;
    setActionMsg(null);
    try {
      const res = await edrApi.proposeResponse({
        endpoint_id: detail.endpoint.endpoint_id,
        action_type: "isolate_endpoint",
        target_value: detail.endpoint.endpoint_id,
        reason: "Initiated from Endpoint Detail posture view",
      });
      setActionMsg(
        `Isolation proposal ${res.action_id} queued (${res.status}). Review in Response Center.`,
      );
    } catch (err) {
      setActionMsg(err instanceof Error ? err.message : "Failed to propose isolation");
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">Endpoint Deep Inspection</h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            Running process genealogy, live sockets, FIM baseline drift, and containment actions.
          </p>
        </div>

        <div className="flex items-end gap-2">
          <div>
            <label htmlFor="ep-picker" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Selected endpoint
            </label>
            <select
              id="ep-picker"
              value={endpointId ?? ""}
              onChange={(e) => onSelectEndpoint(e.target.value)}
              className="edr-input"
            >
              {endpoints.length === 0 && <option value="">No enrolled endpoints</option>}
              {endpoints.map((ep) => (
                <option key={ep.endpoint_id} value={ep.endpoint_id}>
                  {ep.hostname} ({ep.endpoint_id})
                </option>
              ))}
            </select>
          </div>

          {detail && (
            <button
              type="button"
              onClick={handleProposeIsolation}
              className="px-3 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white"
            >
              Propose Isolation
            </button>
          )}
        </div>
      </div>

      {actionMsg && (
        <div
          role="status"
          aria-live="polite"
          className="rounded border border-[#303139] bg-[#1D1E24] p-3 text-sm flex items-center justify-between"
        >
          <span>{actionMsg}</span>
          <button
            type="button"
            onClick={onGoResponses}
            className="text-xs font-mono text-[#FF949C] underline"
          >
            Open Response Center
          </button>
        </div>
      )}

      {error && (
        <div role="alert" className="rounded border border-[#D63A46] bg-[#D63A46]/15 p-3 text-sm">
          {error}
        </div>
      )}

      {detail && (
        <>
          <div className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <div className="text-xs font-mono text-[#9A9CA6]">HOST</div>
              <div className="font-mono font-semibold text-[#E8E7E3] mt-1">
                {detail.endpoint.hostname}
              </div>
              <div className="mt-1">
                <OriginBadge origin={detail.endpoint.telemetry_origin} />
              </div>
            </div>
            <div>
              <div className="text-xs font-mono text-[#9A9CA6]">SENSOR &amp; SYSMON</div>
              <div className="text-sm mt-1">
                <StatusPill status={detail.endpoint.status} />{" "}
                <span className="font-mono text-xs text-[#9A9CA6] ml-1">
                  Sysmon: {detail.endpoint.sysmon_available ? "ready" : "unavailable"}
                </span>
              </div>
            </div>
            <div>
              <div className="text-xs font-mono text-[#9A9CA6]">HOST TELEMETRY</div>
              <div className="font-mono text-xs mt-1 text-[#E8E7E3]">
                CPU: {detail.endpoint.last_metrics?.cpu_percent?.toFixed(1) ?? "--"}% · RAM:{" "}
                {detail.endpoint.last_metrics?.memory_used_mb ?? "--"}/
                {detail.endpoint.last_metrics?.memory_total_mb ?? "--"} MB
              </div>
            </div>
            <div>
              <div className="text-xs font-mono text-[#9A9CA6]">ISOLATION STATE</div>
              <div className="mt-1">
                <StatusPill status={detail.endpoint.isolation_state} />
              </div>
            </div>
          </div>

          <DataTable
            caption="Recorded Process Executions"
            rows={detail.processes}
            loading={loading}
            rowKey={(p, idx) => String(p.process_guid ?? idx)}
            columns={[
              {
                key: "pid",
                label: "PID / PPID",
                render: (p) => (
                  <span className="font-mono text-xs">
                    {String(p.pid)} / {String(p.ppid)}
                  </span>
                ),
              },
              {
                key: "name",
                label: "Process",
                render: (p) => <span className="font-mono font-semibold">{String(p.process_name)}</span>,
              },
              {
                key: "sig",
                label: "Signature",
                render: (p) => <StatusPill status={String(p.signature_status)} />,
              },
              {
                key: "cmd",
                label: "Command Line",
                render: (p) => (
                  <span className="font-mono text-xs break-all">
                    {String(p.command_line || p.executable_path)}
                  </span>
                ),
              },
            ]}
          />

          <DataTable
            caption="Active Network Sockets"
            rows={detail.network_sockets}
            loading={loading}
            rowKey={(s, idx) => String(s.socket_id ?? idx)}
            columns={[
              {
                key: "proto",
                label: "Proto",
                render: (s) => <span className="font-mono uppercase">{String(s.protocol)}</span>,
              },
              {
                key: "proc",
                label: "Process (PID)",
                render: (s) => (
                  <span className="font-mono text-xs">
                    {String(s.process_name ?? "unknown")} ({String(s.pid ?? "--")})
                  </span>
                ),
              },
              {
                key: "local",
                label: "Local",
                render: (s) => (
                  <span className="font-mono text-xs">
                    {String(s.local_addr)}:{String(s.local_port)}
                  </span>
                ),
              },
              {
                key: "remote",
                label: "Remote",
                render: (s) => (
                  <span className="font-mono text-xs">
                    {String(s.remote_addr)}:{String(s.remote_port)}
                  </span>
                ),
              },
              { key: "state", label: "State", render: (s) => <StatusPill status={String(s.state)} /> },
            ]}
          />

          <DataTable
            caption="Endpoint Alerts"
            rows={detail.alerts}
            loading={loading}
            rowKey={(a) => a.alert_id}
            columns={[
              {
                key: "rule",
                label: "Rule",
                render: (a) => (
                  <span className="font-mono text-xs font-semibold">
                    {a.rule_id}: {a.rule_name}
                  </span>
                ),
              },
              { key: "sev", label: "Severity", render: (a) => <SeverityBadge severity={a.severity} /> },
              {
                key: "sum",
                label: "Summary",
                render: (a) => <span className="text-xs">{a.evidence_summary}</span>,
              },
              { key: "status", label: "Status", render: (a) => <StatusPill status={a.status} /> },
            ]}
          />
        </>
      )}
    </div>
  );
}
