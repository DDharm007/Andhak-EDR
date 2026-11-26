import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { edrApi } from "../api";
import { OriginBadge, SeverityBadge } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { FimBaseline, FimEvent } from "../types";

export function IntegrityView() {
  const [baselines, setBaselines] = useState<FimBaseline[]>([]);
  const [events, setEvents] = useState<FimEvent[]>([]);
  const [endpointId, setEndpointId] = useState("");
  const [directory, setDirectory] = useState("C:\\Windows\\System32\\drivers\\etc");
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () => {
    edrApi
      .fimStatus()
      .then((res) => {
        setBaselines(res.baselines);
        setEvents(res.events);
      })
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const submitBaseline = async (e: FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);
    try {
      const res = await edrApi.createFimBaseline(endpointId.trim(), directory.trim(), true);
      setStatusMsg(`Captured baseline: ${JSON.stringify(res)}`);
      load();
    } catch (err) {
      setStatusMsg(err instanceof Error ? err.message : "Failed creating FIM baseline");
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-[#E8E7E3]">File Integrity Monitor (FIM)</h1>
        <p className="text-xs text-[#9A9CA6] mt-0.5">
          SHA-256 baseline enforcement, unauthorized file modifications, and Authenticode drift.
        </p>
      </div>

      <form
        onSubmit={submitBaseline}
        className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 flex flex-wrap items-end gap-3"
      >
        <div>
          <label htmlFor="fim-ep" className="block text-xs font-mono text-[#9A9CA6] mb-1">
            Endpoint ID *
          </label>
          <input
            id="fim-ep"
            name="endpoint_id"
            required
            value={endpointId}
            onChange={(e) => setEndpointId(e.target.value)}
            placeholder="ep_..."
            className="edr-input w-56 font-mono"
          />
        </div>
        <div className="flex-1 min-w-[260px]">
          <label htmlFor="fim-dir" className="block text-xs font-mono text-[#9A9CA6] mb-1">
            Monitored Directory Path *
          </label>
          <input
            id="fim-dir"
            name="directory"
            required
            value={directory}
            onChange={(e) => setDirectory(e.target.value)}
            className="edr-input w-full font-mono"
          />
        </div>
        <button
          type="submit"
          className="px-4 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white min-h-[40px]"
        >
          Capture Baseline
        </button>
      </form>

      {statusMsg && (
        <div role="status" aria-live="polite" className="rounded border border-[#303139] bg-[#1D1E24] p-3 text-xs font-mono">
          {statusMsg}
        </div>
      )}

      <DataTable
        caption="FIM Drift & Tamper Events"
        rows={events}
        loading={loading}
        rowKey={(e) => e.fim_event_id}
        columns={[
          { key: "ts", label: "Detected", render: (e) => <span className="font-mono text-xs">{e.detected_at.slice(0, 19)}</span> },
          { key: "chg", label: "Change", render: (e) => <span className="font-mono font-semibold">{e.change_type}</span> },
          { key: "sev", label: "Severity", render: (e) => <SeverityBadge severity={e.severity} /> },
          { key: "path", label: "File Path", render: (e) => <span className="font-mono text-xs break-all">{e.file_path}</span> },
          {
            key: "diff",
            label: "Baseline vs Observed SHA-256",
            render: (e) => (
              <div className="font-mono text-[11px] text-[#9A9CA6]">
                <div>Base: {e.baseline_sha256?.slice(0, 16) || "--"}</div>
                <div>Obsv: {e.observed_sha256?.slice(0, 16) || "--"}</div>
              </div>
            ),
          },
          { key: "org", label: "Origin", render: (e) => <OriginBadge origin={e.telemetry_origin} /> },
        ]}
      />

      <DataTable
        caption="Active SHA-256 Baselines"
        rows={baselines}
        loading={loading}
        rowKey={(b) => b.baseline_id}
        columns={[
          { key: "ep", label: "Endpoint", render: (b) => <span className="font-mono text-xs">{b.endpoint_id}</span> },
          { key: "path", label: "File Path", render: (b) => <span className="font-mono text-xs break-all">{b.file_path}</span> },
          { key: "sha", label: "Baseline SHA-256", render: (b) => <span className="font-mono text-xs">{b.sha256.slice(0, 24)}...</span> },
          { key: "sig", label: "Signature", render: (b) => <span className="font-mono text-xs">{b.signature_status}</span> },
        ]}
      />
    </div>
  );
}
