import { useEffect, useState } from "react";
import { Background, Controls, MiniMap, ReactFlow } from "@xyflow/react";
import type { Edge, Node } from "@xyflow/react";
import { edrApi } from "../api";
import { OriginBadge, SeverityBadge } from "../components/Badges";
import type { IncidentDetail, IncidentRecord } from "../types";

export function AttackGraphView({
  selectedIncidentId,
  onSelectIncident,
  onOpenInvestigation,
}: {
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onOpenInvestigation: (id: string) => void;
}) {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    edrApi
      .incidents()
      .then((res) => {
        setIncidents(res.items);
        if (!selectedIncidentId && res.items.length > 0) {
          onSelectIncident(res.items[0].incident_id);
        }
      })
      .finally(() => setLoading(false));
  }, [selectedIncidentId, onSelectIncident]);

  useEffect(() => {
    if (!selectedIncidentId) return;
    edrApi.incidentDetail(selectedIncidentId).then(setDetail).catch(() => setDetail(null));
  }, [selectedIncidentId]);

  const kindColor: Record<string, string> = {
    endpoint: "#3B82F6",
    process: "#A92532",
    alert: "#D63A46",
    network: "#F59E0B",
    file: "#10B981",
  };

  const rfNodes: Node[] = (detail?.graph.nodes ?? []).map((n) => {
    const kind = String(n.data.kind ?? n.type ?? "process");
    return {
      id: n.id,
      position: n.position,
      data: { label: String(n.data.label ?? n.id), ...n.data },
      style: {
        backgroundColor: "#17181D",
        color: "#E8E7E3",
        border: `1.5px solid ${kindColor[kind] ?? "#303139"}`,
        borderRadius: "6px",
        padding: "8px 10px",
        fontSize: "11px",
        fontFamily: "IBM Plex Mono, monospace",
        minWidth: 165,
      },
    };
  });

  const rfEdges: Edge[] = (detail?.graph.edges ?? []).map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: e.label === "TCP ESTABLISHED" || e.label === "spawned",
    style: { stroke: "#5C6070", strokeWidth: 1.5 },
    labelStyle: { fill: "#9A9CA6", fontSize: 10, fontFamily: "IBM Plex Mono, monospace" },
    labelBgStyle: { fill: "#101114" },
  }));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">Interactive Attack Graph</h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            React Flow attack provenance graph across endpoint, parent-child processes, alerts,
            files, and outbound sockets.
          </p>
        </div>

        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="graph-inc" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Incident
            </label>
            <select
              id="graph-inc"
              value={selectedIncidentId ?? ""}
              onChange={(e) => onSelectIncident(e.target.value)}
              className="edr-input"
            >
              {incidents.length === 0 && <option value="">No correlated incidents</option>}
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  [{inc.severity.toUpperCase()}] {inc.title}
                </option>
              ))}
            </select>
          </div>

          {detail && (
            <button
              type="button"
              onClick={() => onOpenInvestigation(detail.incident_id)}
              className="px-3 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white min-h-[40px]"
            >
              Deterministic Investigation
            </button>
          )}
        </div>
      </div>

      {detail && (
        <div className="flex flex-wrap items-center gap-3 text-xs font-mono bg-[#17181D] border border-[#303139] rounded p-3">
          <SeverityBadge severity={detail.severity} />
          <OriginBadge origin={detail.telemetry_origin} />
          <span>Risk: {detail.risk_score}/100</span>
          <span>Processes: {detail.process_count}</span>
          <span>MITRE: {detail.mitre_techniques.join(", ") || "none"}</span>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        <div className="xl:col-span-3 h-[520px] rounded-md border border-[#303139] bg-[#101114]">
          {loading ? (
            <div className="p-6 text-sm text-[#9A9CA6]">Loading attack graph...</div>
          ) : rfNodes.length === 0 ? (
            <div className="p-8 text-sm text-[#9A9CA6] text-center">
              Select a correlated incident with alerts to inspect its attack graph.
            </div>
          ) : (
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              fitView
              onNodeClick={(_, node) => setSelectedNode(node)}
            >
              <Background color="#24262E" gap={18} />
              <Controls />
              <MiniMap nodeColor={(n) => kindColor[String(n.data?.kind ?? "process")] ?? "#303139"} />
            </ReactFlow>
          )}
        </div>

        <aside className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 space-y-3">
          <h2 className="text-sm font-semibold text-[#E8E7E3]">Graph Node Inspector</h2>
          <div className="flex flex-wrap gap-1.5 text-[11px] font-mono">
            {Object.entries(kindColor).map(([k, hex]) => (
              <span
                key={k}
                className="px-2 py-0.5 rounded border"
                style={{ borderColor: hex, color: "#E8E7E3" }}
              >
                {k}
              </span>
            ))}
          </div>
          {selectedNode ? (
            <pre className="text-[11px] font-mono bg-[#101114] border border-[#303139] rounded p-3 overflow-auto max-h-96 whitespace-pre-wrap">
              {JSON.stringify(selectedNode.data, null, 2)}
            </pre>
          ) : (
            <p className="text-xs text-[#9A9CA6]">
              Click any node in the React Flow canvas to inspect PIDs, SHA-256 digests, alert rules,
              or network peer tuples.
            </p>
          )}
        </aside>
      </div>
    </div>
  );
}
