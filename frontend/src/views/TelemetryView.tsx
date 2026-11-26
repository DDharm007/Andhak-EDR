import { useEffect, useState } from "react";
import { Pause, Play } from "lucide-react";
import { connectEdrWebSocket, edrApi } from "../api";
import { OriginBadge, SeverityBadge } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { TelemetryEvent } from "../types";

export function TelemetryView() {
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [category, setCategory] = useState("");
  const [origin, setOrigin] = useState("");
  const [livePaused, setLivePaused] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params: Record<string, string> = { limit: "120" };
    if (category) params.category = category;
    if (origin) params.origin = origin;
    edrApi
      .telemetryEvents(params)
      .then((res) => {
        setEvents(res.items);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load telemetry"))
      .finally(() => setLoading(false));
  }, [category, origin]);

  useEffect(() => {
    if (livePaused) return;
    return connectEdrWebSocket(
      "telemetry",
      (frame) => {
        if (frame.type === "telemetry.event" && frame.data) {
          const ev = frame.data as unknown as TelemetryEvent;
          setEvents((prev) => [ev, ...prev].slice(0, 150));
        }
      },
      () => {},
    );
  }, [livePaused]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">Live Telemetry Stream</h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            Real-time WebSocket feed (`/ws/telemetry`) and normalized SQLite event ledger.
          </p>
        </div>

        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="tel-cat" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Category
            </label>
            <select
              id="tel-cat"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="edr-input"
            >
              <option value="">All categories</option>
              <option value="process">Process</option>
              <option value="network">Network</option>
              <option value="filesystem">Filesystem</option>
              <option value="system">System</option>
              <option value="fim">FIM</option>
            </select>
          </div>
          <div>
            <label htmlFor="tel-org" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Telemetry origin
            </label>
            <select
              id="tel-org"
              value={origin}
              onChange={(e) => setOrigin(e.target.value)}
              className="edr-input"
            >
              <option value="">All origins</option>
              <option value="real_endpoint">REAL TELEMETRY</option>
              <option value="recorded_demo">RECORDED DEMO</option>
              <option value="test_fixture">TEST FIXTURE</option>
            </select>
          </div>
          <button
            type="button"
            onClick={() => setLivePaused((p) => !p)}
            aria-pressed={livePaused}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded border border-[#303139] bg-[#1D1E24] text-xs font-mono hover:border-[#A92532]"
          >
            {livePaused ? <Play className="w-3.5 h-3.5" aria-hidden="true" /> : <Pause className="w-3.5 h-3.5" aria-hidden="true" />}
            <span>{livePaused ? "Resume Stream" : "Pause Stream"}</span>
          </button>
        </div>
      </div>

      <DataTable
        caption="Endpoint Telemetry Events"
        rows={events}
        loading={loading}
        error={error}
        rowKey={(e, idx) => `${e.event_id}-${idx}`}
        columns={[
          {
            key: "ts",
            label: "Timestamp (UTC)",
            render: (e) => <span className="font-mono text-xs">{e.occurred_at.slice(0, 19)}</span>,
          },
          {
            key: "cat",
            label: "Category / Type",
            render: (e) => (
              <span className="font-mono text-xs">
                {e.category}:{e.event_type}
              </span>
            ),
          },
          { key: "sev", label: "Severity", render: (e) => <SeverityBadge severity={e.severity} /> },
          {
            key: "proc",
            label: "Process / Target",
            render: (e) => (
              <span className="font-mono text-xs break-all">
                {e.process_name
                  ? `${e.process_name} (${e.pid ?? "--"}) ${e.command_line || ""}`
                  : e.file_path || (e.dest_ip ? `${e.dest_ip}:${e.dest_port}` : e.endpoint_id)}
              </span>
            ),
          },
          { key: "origin", label: "Origin", render: (e) => <OriginBadge origin={e.telemetry_origin} /> },
        ]}
      />
    </div>
  );
}
