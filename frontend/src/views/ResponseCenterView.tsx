import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { ShieldCheck, ShieldOff } from "lucide-react";
import { edrApi } from "../api";
import { ConfirmDialog, StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { AuditLogEntry, QuarantineItem, ResponseAction } from "../types";

export function ResponseCenterView({ refreshTick }: { refreshTick: number }) {
  const [responses, setResponses] = useState<ResponseAction[]>([]);
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [endpointId, setEndpointId] = useState("");
  const [actionType, setActionType] = useState("isolate_endpoint");
  const [targetValue, setTargetValue] = useState("");
  const [reason, setReason] = useState("");
  const [note, setNote] = useState("Verified operational impact");
  const [confirmState, setConfirmState] = useState<{
    open: boolean;
    title: string;
    message: string;
    action: (() => Promise<void>) | null;
  }>({ open: false, title: "", message: "", action: null });
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () => {
    Promise.all([edrApi.responses(), edrApi.quarantine(), edrApi.audit()])
      .then(([rRes, qRes, aRes]) => {
        setResponses(rRes.items);
        setQuarantine(qRes.items);
        setAuditLogs(aRes.items);
        setChainValid(aRes.chain_verification?.valid ?? null);
        setError(null);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Sign in to access Response Center"))
      .finally(() => setLoading(false));
  };

  useEffect(load, [refreshTick]);

  const handlePropose = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setStatusMsg(null);
    try {
      const res = await edrApi.proposeResponse({
        endpoint_id: endpointId.trim(),
        action_type: actionType,
        target_value: targetValue.trim() || endpointId.trim(),
        reason: reason.trim(),
      });
      setStatusMsg(`Queued action ${res.action_id} (${res.status}).`);
      setReason("");
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Proposal failed");
    }
  };

  const askDecision = (actionId: string, decision: "approve" | "reject") => {
    setConfirmState({
      open: true,
      title: `${decision === "approve" ? "Approve" : "Reject"} Containment Action?`,
      message: `Confirm ${decision} on ${actionId}. Approved actions dispatch directly to the endpoint sensor and append to the SHA-256 audit log.`,
      action: async () => {
        try {
          await edrApi.decideResponse(actionId, decision, note);
          setStatusMsg(`Recorded ${decision} for ${actionId}.`);
          load();
        } catch (err) {
          setError(err instanceof Error ? err.message : "Decision failed");
        }
      },
    });
  };

  const askRollback = (actionId: string) => {
    setConfirmState({
      open: true,
      title: "Initiate Controlled Rollback?",
      message: `Issue reversible recovery command (un-isolate endpoint or restore quarantined file) for ${actionId}?`,
      action: async () => {
        try {
          const rb = await edrApi.rollbackResponse(actionId, "Controlled recovery via Console");
          setStatusMsg(`Issued rollback ${rb.action_id} (${rb.action_type}).`);
          load();
        } catch (err) {
          setError(err instanceof Error ? err.message : "Rollback failed");
        }
      },
    });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E8E7E3]">
            Response, Quarantine &amp; Audit Center
          </h1>
          <p className="text-xs text-[#9A9CA6] mt-0.5">
            RBAC two-step containment approval, protected OS denylist enforcement, and SHA-256
            tamper-evident audit log.
          </p>
        </div>

        {chainValid !== null && (
          <div
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs font-mono font-semibold ${
              chainValid
                ? "border-emerald-700 bg-emerald-950/60 text-emerald-300"
                : "border-[#D63A46] bg-[#D63A46]/20 text-[#FF949C]"
            }`}
          >
            {chainValid ? <ShieldCheck className="w-4 h-4" aria-hidden="true" /> : <ShieldOff className="w-4 h-4" aria-hidden="true" />}
            <span>{chainValid ? "AUDIT SHA-256 CHAIN VERIFIED" : "AUDIT CHAIN BROKEN"}</span>
          </div>
        )}
      </div>

      {error && (
        <div role="alert" className="rounded border border-[#D63A46] bg-[#D63A46]/15 p-3 text-sm text-[#FF9CA4]">
          {error}
        </div>
      )}
      {statusMsg && (
        <div role="status" aria-live="polite" className="rounded border border-[#303139] bg-[#1D1E24] p-3 text-xs font-mono">
          {statusMsg}
        </div>
      )}

      <form
        onSubmit={handlePropose}
        className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 items-end"
      >
        <div>
          <label htmlFor="resp-ep" className="block text-xs font-mono text-[#9A9CA6] mb-1">
            Endpoint ID *
          </label>
          <input
            id="resp-ep"
            required
            value={endpointId}
            onChange={(e) => setEndpointId(e.target.value)}
            placeholder="ep_..."
            className="edr-input w-full font-mono"
          />
        </div>
        <div>
          <label htmlFor="resp-type" className="block text-xs font-mono text-[#9A9CA6] mb-1">
            Action Type
          </label>
          <select
            id="resp-type"
            value={actionType}
            onChange={(e) => setActionType(e.target.value)}
            className="edr-input w-full"
          >
            <option value="isolate_endpoint">Isolate Endpoint</option>
            <option value="quarantine_file">Quarantine File</option>
            <option value="terminate_process">Terminate Process</option>
            <option value="block_network_indicator">Block Network Indicator</option>
          </select>
        </div>
        <div>
          <label htmlFor="resp-tgt" className="block text-xs font-mono text-[#9A9CA6] mb-1">
            Target (PID / Path / Endpoint)
          </label>
          <input
            id="resp-tgt"
            value={targetValue}
            onChange={(e) => setTargetValue(e.target.value)}
            placeholder="PID, file path, or endpoint_id"
            className="edr-input w-full font-mono"
          />
        </div>
        <div>
          <label htmlFor="resp-rsn" className="block text-xs font-mono text-[#9A9CA6] mb-1">
            Justification *
          </label>
          <input
            id="resp-rsn"
            required
            minLength={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="C2 / dropper evidence..."
            className="edr-input w-full"
          />
        </div>
        <button
          type="submit"
          className="px-4 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white min-h-[40px]"
        >
          Propose Response
        </button>
      </form>

      <div className="flex items-center gap-3 text-xs">
        <label htmlFor="dec-note" className="font-mono text-[#9A9CA6]">
          Approval Note:
        </label>
        <input
          id="dec-note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          className="edr-input w-80 text-xs"
        />
      </div>

      <DataTable
        caption="Controlled Response Queue"
        rows={responses}
        loading={loading}
        rowKey={(r) => r.action_id}
        columns={[
          { key: "act", label: "Action", render: (r) => <span className="font-mono font-semibold">{r.action_type}</span> },
          { key: "tgt", label: "Target", render: (r) => <span className="font-mono text-xs break-all">{r.target_value}</span> },
          { key: "rsn", label: "Reason", render: (r) => <span className="text-xs">{r.reason}</span> },
          { key: "stat", label: "Status", render: (r) => <StatusPill status={r.status} /> },
          {
            key: "ctrl",
            label: "Approval / Rollback",
            render: (r) => (
              <div className="flex flex-wrap gap-1.5">
                {r.status === "pending_approval" && (
                  <>
                    <button
                      type="button"
                      onClick={() => askDecision(r.action_id, "approve")}
                      className="px-2 py-1 rounded bg-[#A92532] text-white text-[11px] font-mono"
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      onClick={() => askDecision(r.action_id, "reject")}
                      className="px-2 py-1 rounded border border-[#303139] text-[11px] font-mono"
                    >
                      Reject
                    </button>
                  </>
                )}
                {r.status === "executed" &&
                  (r.action_type === "isolate_endpoint" || r.action_type === "quarantine_file") &&
                  !r.rollback_action_id && (
                    <button
                      type="button"
                      onClick={() => askRollback(r.action_id)}
                      className="px-2 py-1 rounded border border-emerald-700 text-emerald-300 text-[11px] font-mono"
                    >
                      Rollback
                    </button>
                  )}
              </div>
            ),
          },
        ]}
      />

      <DataTable
        caption="Quarantine Vault"
        rows={quarantine}
        loading={loading}
        rowKey={(q) => q.quarantine_id}
        columns={[
          { key: "orig", label: "Original Path", render: (q) => <span className="font-mono text-xs break-all">{q.original_path}</span> },
          { key: "sha", label: "SHA-256 (Verified)", render: (q) => <span className="font-mono text-xs">{q.sha256_before.slice(0, 20)}...</span> },
          { key: "sz", label: "Bytes", render: (q) => <span className="font-mono text-xs">{q.size_bytes}</span> },
          { key: "st", label: "Vault Status", render: (q) => <StatusPill status={q.status} /> },
        ]}
      />

      <DataTable
        caption="SHA-256 Chained Security Audit Log"
        rows={auditLogs}
        loading={loading}
        rowKey={(a) => a.audit_id}
        columns={[
          { key: "seq", label: "#", render: (a) => <span className="font-mono text-xs">{a.seq}</span> },
          { key: "act", label: "Event", render: (a) => <span className="font-mono font-semibold text-xs">{a.action}</span> },
          { key: "actor", label: "Actor / Role", render: (a) => <span className="font-mono text-xs">{a.actor_id} ({a.actor_role})</span> },
          { key: "hash", label: "Entry Hash", render: (a) => <span className="font-mono text-[11px] text-[#9A9CA6]">{a.entry_hash.slice(0, 20)}...</span> },
          { key: "ts", label: "UTC Time", render: (a) => <span className="font-mono text-xs">{a.created_at.slice(0, 19)}</span> },
        ]}
      />

      <ConfirmDialog
        open={confirmState.open}
        title={confirmState.title}
        message={confirmState.message}
        confirmLabel="Confirm Action"
        onConfirm={() => {
          const fn = confirmState.action;
          setConfirmState((prev) => ({ ...prev, open: false, action: null }));
          if (fn) void fn();
        }}
        onCancel={() => setConfirmState((prev) => ({ ...prev, open: false, action: null }))}
      />
    </div>
  );
}
