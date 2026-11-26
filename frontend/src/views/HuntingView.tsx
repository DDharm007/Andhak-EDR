import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { edrApi } from "../api";
import { OriginBadge, SeverityBadge } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { TelemetryEvent } from "../types";

export function HuntingView() {
  const [q, setQ] = useState("");
  const [process, setProcess] = useState("");
  const [ip, setIp] = useState("");
  const [sha256, setSha256] = useState("");
  const [origin, setOrigin] = useState("");
  const [rows, setRows] = useState<TelemetryEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const runSearch = async () => {
    setLoading(true);
    try {
      const res = await edrApi.huntingSearch({
        q,
        process,
        ip,
        sha256,
        origin,
        limit: "150",
      });
      setRows(res.items);
      setTotal(res.total);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Threat hunting query failed");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void runSearch();
  }, []);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runSearch();
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-[#E8E7E3]">Threat Hunting Search</h1>
        <p className="text-xs text-[#9A9CA6] mt-0.5">
          Query historical normalized telemetry by command line, process name, SHA-256, remote IP,
          or provenance.
        </p>
      </div>

      <search>
        <form
          onSubmit={onSubmit}
          className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 items-end"
        >
          <div className="lg:col-span-2">
            <label htmlFor="hunt-q" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Keyword / Command Line
            </label>
            <input
              id="hunt-q"
              name="q"
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="-EncodedCommand, Temp, hosts..."
              className="edr-input w-full font-mono"
            />
          </div>
          <div>
            <label htmlFor="hunt-proc" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Process
            </label>
            <input
              id="hunt-proc"
              name="process"
              value={process}
              onChange={(e) => setProcess(e.target.value)}
              placeholder="powershell"
              className="edr-input w-full font-mono"
            />
          </div>
          <div>
            <label htmlFor="hunt-ip" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Remote IP
            </label>
            <input
              id="hunt-ip"
              name="ip"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="203.0.113.55"
              className="edr-input w-full font-mono"
            />
          </div>
          <div>
            <label htmlFor="hunt-sha" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              SHA-256
            </label>
            <input
              id="hunt-sha"
              name="sha256"
              value={sha256}
              onChange={(e) => setSha256(e.target.value)}
              placeholder="Exact SHA-256..."
              className="edr-input w-full font-mono"
            />
          </div>
          <div className="flex gap-2">
            <select
              aria-label="Filter telemetry origin"
              value={origin}
              onChange={(e) => setOrigin(e.target.value)}
              className="edr-input flex-1"
            >
              <option value="">Any origin</option>
              <option value="real_endpoint">REAL</option>
              <option value="recorded_demo">DEMO</option>
              <option value="test_fixture">FIXTURE</option>
            </select>
            <button
              type="submit"
              className="px-4 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white min-h-[40px]"
            >
              Hunt
            </button>
          </div>
        </form>
      </search>

      <DataTable
        caption={`Hunting Results (${total} total matches)`}
        rows={rows}
        loading={loading}
        error={error}
        rowKey={(r) => r.event_id}
        columns={[
          { key: "ts", label: "Occurred", render: (r) => <span className="font-mono text-xs">{r.occurred_at.slice(0, 19)}</span> },
          { key: "cat", label: "Type", render: (r) => <span className="font-mono text-xs">{r.category}:{r.event_type}</span> },
          { key: "sev", label: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
          {
            key: "artifact",
            label: "Process / Artifact / Socket",
            render: (r) => (
              <div className="font-mono text-xs break-all">
                {r.process_name && <span className="font-semibold text-[#E8E7E3]">{r.process_name} </span>}
                <span>{r.command_line || r.file_path || (r.dest_ip ? `${r.dest_ip}:${r.dest_port}` : r.executable_path)}</span>
              </div>
            ),
          },
          { key: "origin", label: "Origin", render: (r) => <OriginBadge origin={r.telemetry_origin} /> },
        ]}
      />
    </div>
  );
}
