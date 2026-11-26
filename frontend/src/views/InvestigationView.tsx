import { useEffect, useState } from "react";
import { Archive, CheckCircle2, Terminal } from "lucide-react";
import { edrApi } from "../api";
import { OriginBadge, SeverityBadge, StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { IncidentDetail, IncidentRecord, InvestigationReport, ProcessTreeNode } from "../types";

function TreeBranch({ node, depth = 0 }: { node: ProcessTreeNode; depth?: number }) {
  return (
    <div style={{ marginLeft: `${depth * 18}px` }} className="border-l border-[#303139] pl-3 py-1.5">
      <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
        <span className="font-semibold text-[#E8E7E3]">
          {node.process_name} (PID {node.pid})
        </span>
        <StatusPill status={node.signature_status} />
        {node.alerts.length > 0 && (
          <span className="px-1.5 py-0.5 rounded bg-[#A92532] text-white text-[10px]">
            {node.alerts.length} alert(s)
          </span>
        )}
      </div>
      <div className="text-[11px] font-mono text-[#9A9CA6] break-all mt-0.5">
        {node.command_line || node.executable_path}
      </div>
      {node.children.map((ch) => (
        <TreeBranch key={ch.process_guid} node={ch} depth={depth + 1} />
      ))}
    </div>
  );
}

export function InvestigationView({
  selectedIncidentId,
  onSelectIncident,
  onOpenResponseCenter,
}: {
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onOpenResponseCenter: () => void;
}) {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [report, setReport] = useState<InvestigationReport | null>(null);
  const [bundleMsg, setBundleMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    edrApi.incidents().then((res) => {
      setIncidents(res.items);
      if (!selectedIncidentId && res.items.length > 0) {
        onSelectIncident(res.items[0].incident_id);
      }
    });
  }, [selectedIncidentId, onSelectIncident]);

  useEffect(() => {
    if (!selectedIncidentId) return;
    edrApi
      .incidentDetail(selectedIncidentId)
      .then((d) => {
        setDetail(d);
        setReport(d.latest_investigation);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load incident"));
  }, [selectedIncidentId]);

  const handleInvestigate = async () => {
    if (!selectedIncidentId) return;
    setError(null);
    try {
      const inv = await edrApi.investigateIncident(selectedIncidentId);
      setReport(inv);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed running investigation");
    }
  };

  const handleCollectBundle = async () => {
    if (!selectedIncidentId) return;
    setBundleMsg(null);
    try {
      const res = await edrApi.collectForensics(selectedIncidentId);
      setBundleMsg(
        `Sealed bundle ${res.bundle_id} | manifest SHA-256: ${res.manifest_sha256}`,
      );
    } catch (err) {
      setBundleMsg(err instanceof Error ? err.message : "Failed sealing forensic bundle");
    }
  };

  const handleProposeRunbookStep = async (actionType: string, target: string, procName?: string) => {
    if (!detail) return;
    try {
      const res = await edrApi.proposeResponse({
        endpoint_id: detail.endpoint_id,
        incident_id: detail.incident_id,
        action_type: actionType,
        target_value: target,
        target_metadata: procName ? { process_name: procName } : {},
        reason: `Recommended by deterministic triage report (${report?.investigation_id ?? detail.incident_id})`,
      });
      setBundleMsg(`Proposed ${res.action_type} (${res.action_id}) -> awaiting approval.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed proposing containment");
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">
            Deterministic Incident Investigation
          </h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            Evidence-cited rules &amp; templates (`deterministic_rules_v1`, Zero-AI per ADR-002).
            All findings reference stored alert/event IDs.
          </p>
        </div>

        <div className="flex flex-wrap items-end gap-2">
          <div>
            <label htmlFor="inv-inc" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Incident
            </label>
            <select
              id="inv-inc"
              value={selectedIncidentId ?? ""}
              onChange={(e) => onSelectIncident(e.target.value)}
              className="edr-input"
            >
              {incidents.length === 0 && <option value="">No incidents</option>}
              {incidents.map((inc) => (
                <option key={inc.incident_id} value={inc.incident_id}>
                  {inc.title}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            onClick={handleInvestigate}
            disabled={!selectedIncidentId}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white min-h-[40px]"
          >
            <Terminal className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Run Deterministic Triage</span>
          </button>

          <button
            type="button"
            onClick={handleCollectBundle}
            disabled={!selectedIncidentId}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded border border-[#303139] bg-[#1D1E24] hover:border-[#A92532] text-xs font-semibold min-h-[40px]"
          >
            <Archive className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Seal Forensic Bundle</span>
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="rounded border border-[#D63A46] bg-[#D63A46]/15 p-3 text-sm">
          {error}
        </div>
      )}

      {bundleMsg && (
        <div
          role="status"
          aria-live="polite"
          className="rounded border border-emerald-700 bg-emerald-950/50 p-3 text-xs font-mono flex items-center justify-between"
        >
          <span>{bundleMsg}</span>
          <button type="button" onClick={onOpenResponseCenter} className="underline text-[#E8E7E3]">
            View Response Center
          </button>
        </div>
      )}

      {detail && (
        <div className="space-y-5">
          {report && (
            <section className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={detail.severity} />
                  <OriginBadge origin={detail.telemetry_origin} />
                  <span className="font-mono text-xs text-[#9A9CA6]">
                    ENGINE: {report.engine_mode}
                  </span>
                </div>
                <span className="font-mono text-xs text-[#9A9CA6]">
                  Cited IDs: {report.cited_evidence_ids.length}
                </span>
              </div>

              <p className="text-sm text-[#E8E7E3] leading-relaxed">{report.summary_narrative}</p>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div>
                  <h2 className="text-xs font-mono uppercase text-[#9A9CA6] mb-2">
                    False-Positive &amp; Signature Hygiene Checks
                  </h2>
                  <ul className="space-y-2">
                    {report.false_positive_checks.map((fp, i) => (
                      <li
                        key={`${fp.check}-${i}`}
                        className="rounded border border-[#303139] bg-[#101114] p-2.5 text-xs"
                      >
                        <div className="flex items-center gap-2 font-mono mb-1">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />
                          <span className="font-semibold">{fp.check}</span>
                          <StatusPill status={fp.status} />
                        </div>
                        <p className="text-[#9A9CA6]">{fp.detail}</p>
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h2 className="text-xs font-mono uppercase text-[#9A9CA6] mb-2">
                    Approval-Gated Containment Runbook
                  </h2>
                  <ul className="space-y-2">
                    {report.recommended_runbook.map((rb, i) => (
                      <li
                        key={`${rb.action_type}-${i}`}
                        className="rounded border border-[#303139] bg-[#101114] p-2.5 text-xs flex items-center justify-between gap-3"
                      >
                        <div>
                          <div className="font-mono font-semibold text-[#E8E7E3]">
                            P{rb.priority}: {rb.action_type} ({rb.target})
                          </div>
                          <div className="text-[#9A9CA6]">{rb.rationale}</div>
                        </div>
                        <button
                          type="button"
                          onClick={() =>
                            handleProposeRunbookStep(rb.action_type, rb.target, rb.process_name)
                          }
                          className="shrink-0 px-2.5 py-1.5 rounded border border-[#A92532] text-[11px] font-mono hover:bg-[#A92532]"
                        >
                          Propose
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <section className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4">
              <h2 className="text-sm font-semibold text-[#E8E7E3] mb-3">
                Process Execution Tree ({detail.process_count} process nodes)
              </h2>
              {detail.process_tree.length === 0 ? (
                <p className="text-xs text-[#9A9CA6]">No process lineage linked.</p>
              ) : (
                detail.process_tree.map((root) => <TreeBranch key={root.process_guid} node={root} />)
              )}
            </section>

            <DataTable
              caption="Evidence-Backed MITRE ATT&CK Techniques"
              rows={detail.mitre_evidence}
              rowKey={(m) => m.technique_id}
              columns={[
                { key: "tech", label: "ID", render: (m) => <span className="font-mono font-semibold">{m.technique_id}</span> },
                { key: "tactic", label: "Tactic", render: (m) => m.tactic },
                { key: "name", label: "Technique", render: (m) => <span className="text-xs">{m.technique_name}</span> },
                {
                  key: "ev",
                  label: "Cited Evidence",
                  render: (m) => (
                    <span className="font-mono text-[11px] text-[#9A9CA6]">
                      {m.supporting_rules.join(", ")} ({m.supporting_event_ids.length} evt)
                    </span>
                  ),
                },
              ]}
            />
          </div>

          <DataTable
            caption="Chronological Attack Timeline (UTC)"
            rows={detail.timeline}
            rowKey={(t, i) => `${t.id}-${i}`}
            columns={[
              { key: "ts", label: "UTC Timestamp", render: (t) => <span className="font-mono text-xs">{t.timestamp.slice(0, 19)}</span> },
              { key: "type", label: "Kind", render: (t) => <StatusPill status={t.entry_type} /> },
              { key: "sev", label: "Severity", render: (t) => <SeverityBadge severity={t.severity} /> },
              { key: "title", label: "Event / Rule", render: (t) => <span className="font-mono text-xs font-semibold">{t.title}</span> },
              { key: "detail", label: "Detail", render: (t) => <span className="font-mono text-xs break-all">{t.detail}</span> },
            ]}
          />
        </div>
      )}
    </div>
  );
}
