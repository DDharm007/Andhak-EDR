import { useEffect, useState } from "react";
import { edrApi } from "../api";
import { OriginBadge, StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { EndpointSummary } from "../types";

export function EndpointsView({
  onOpenEndpoint,
  refreshTick,
}: {
  onOpenEndpoint: (endpointId: string) => void;
  refreshTick: number;
}) {
  const [items, setItems] = useState<EndpointSummary[]>([]);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    edrApi
      .endpoints()
      .then((res) => {
        setItems(res.items);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load endpoints"))
      .finally(() => setLoading(false));
  }, [refreshTick]);

  const filtered = items.filter((e) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return (
      e.hostname.toLowerCase().includes(q) ||
      e.endpoint_id.toLowerCase().includes(q) ||
      e.os_version.toLowerCase().includes(q) ||
      (e.primary_ip ?? "").toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">Endpoint Inventory</h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            Enrolled Rust sensors reporting live host telemetry, posture score, and isolation state.
          </p>
        </div>

        <search>
          <form onSubmit={(e) => e.preventDefault()} className="flex items-end gap-2">
            <div>
              <label htmlFor="ep-search" className="block text-xs font-mono text-[#9A9CA6] mb-1">
                Filter endpoints
              </label>
              <input
                id="ep-search"
                name="q"
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Hostname, IP, ID..."
                className="edr-input w-64"
              />
            </div>
          </form>
        </search>
      </div>

      <DataTable
        caption="Enrolled Endpoints"
        rows={filtered}
        loading={loading}
        error={error}
        rowKey={(e) => e.endpoint_id}
        columns={[
          {
            key: "hostname",
            label: "Hostname / ID",
            render: (e) => (
              <div>
                <button
                  type="button"
                  onClick={() => onOpenEndpoint(e.endpoint_id)}
                  className="font-mono font-semibold text-[#E8E7E3] hover:text-[#FF949C] hover:underline"
                >
                  {e.hostname}
                </button>
                <div className="font-mono text-[11px] text-[#9A9CA6]">{e.endpoint_id}</div>
              </div>
            ),
          },
          { key: "os", label: "Platform", render: (e) => `${e.os_version} (${e.architecture})` },
          {
            key: "ip",
            label: "Primary IP",
            render: (e) => <span className="font-mono">{e.primary_ip || "--"}</span>,
          },
          { key: "status", label: "Health", render: (e) => <StatusPill status={e.status} /> },
          {
            key: "isolation",
            label: "Isolation",
            render: (e) => <StatusPill status={e.isolation_state} />,
          },
          {
            key: "metrics",
            label: "CPU / Spool",
            render: (e) => (
              <span className="font-mono text-xs">
                {e.last_metrics?.cpu_percent !== undefined
                  ? `${e.last_metrics.cpu_percent.toFixed(1)}%`
                  : "--"}{" "}
                · Q:{e.last_metrics?.spool_queue_depth ?? 0}
              </span>
            ),
          },
          {
            key: "origin",
            label: "Origin",
            render: (e) => <OriginBadge origin={e.telemetry_origin} />,
          },
        ]}
      />
    </div>
  );
}
