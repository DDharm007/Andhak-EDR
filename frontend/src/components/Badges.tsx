import { useEffect, useId, useRef } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  FlaskConical,
  Info,
  Radio,
  ShieldAlert,
  Video,
} from "lucide-react";
import type { Severity, TelemetryOrigin } from "../types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const styles: Record<Severity, { cls: string; label: string; Icon: typeof AlertOctagon }> = {
    critical: {
      cls: "bg-[#D63A46]/20 text-[#FF8891] border-[#D63A46]/60",
      label: "CRITICAL",
      Icon: AlertOctagon,
    },
    high: {
      cls: "bg-[#A92532]/25 text-[#F4A2A9] border-[#A92532]/70",
      label: "HIGH",
      Icon: ShieldAlert,
    },
    medium: {
      cls: "bg-amber-900/35 text-amber-300 border-amber-600/60",
      label: "MEDIUM",
      Icon: AlertTriangle,
    },
    low: {
      cls: "bg-slate-800 text-slate-200 border-slate-600",
      label: "LOW",
      Icon: Info,
    },
    info: {
      cls: "bg-zinc-800 text-zinc-300 border-zinc-600",
      label: "INFO",
      Icon: Info,
    },
  };
  const cfg = styles[severity] ?? styles.info;
  const { Icon } = cfg;
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[11px] font-mono font-semibold ${cfg.cls}`}
    >
      <Icon className="w-3 h-3" aria-hidden="true" />
      <span>{cfg.label}</span>
    </span>
  );
}

export function OriginBadge({ origin }: { origin: TelemetryOrigin | string }) {
  if (origin === "real_endpoint") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-emerald-600/60 bg-emerald-950/60 text-emerald-300 text-[11px] font-mono font-semibold">
        <Radio className="w-3 h-3" aria-hidden="true" />
        <span>REAL TELEMETRY</span>
      </span>
    );
  }
  if (origin === "recorded_demo") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-amber-500/60 bg-amber-950/50 text-amber-200 text-[11px] font-mono font-semibold">
        <Video className="w-3 h-3" aria-hidden="true" />
        <span>RECORDED DEMO</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-zinc-500 bg-zinc-900 text-zinc-200 text-[11px] font-mono font-semibold">
      <FlaskConical className="w-3 h-3" aria-hidden="true" />
      <span>TEST FIXTURE</span>
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const good = new Set(["online", "resolved", "executed", "valid", "restored", "corroborated"]);
  const bad = new Set(["isolated", "invalid", "failed", "elevated_suspicion"]);
  const cls = good.has(status)
    ? "border-emerald-700 bg-emerald-950/50 text-emerald-300"
    : bad.has(status)
      ? "border-[#D63A46] bg-[#D63A46]/20 text-[#FF949C]"
      : "border-[#303139] bg-[#1D1E24] text-[#E8E7E3]";
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[11px] font-mono ${cls}`}
    >
      {good.has(status) && <CheckCircle2 className="w-3 h-3" aria-hidden="true" />}
      <span>{status}</span>
    </span>
  );
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel,
  danger = true,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const dlg = ref.current;
    if (!dlg) return;
    if (open && !dlg.open) {
      dlg.showModal();
    } else if (!open && dlg.open) {
      dlg.close();
    }
  }, [open]);

  return (
    <dialog
      ref={ref}
      className="edr-dialog"
      aria-labelledby={titleId}
      onClose={() => {
        const dlg = ref.current;
        if (!dlg) return;
        const val = dlg.returnValue;
        dlg.returnValue = "";
        if (val === "confirm") {
          onConfirm();
        } else {
          onCancel();
        }
      }}
    >
      <h1 id={titleId} className="text-base font-semibold text-[#E8E7E3] mb-2">
        {title}
      </h1>
      <p className="text-sm text-[#9A9CA6] mb-5">{message}</p>
      <form method="dialog" className="flex justify-end gap-3">
        <button
          type="submit"
          value="cancel"
          autoFocus
          className="px-4 py-2 rounded border border-[#303139] bg-[#1D1E24] text-sm font-medium text-[#E8E7E3] hover:bg-[#272932]"
        >
          Cancel
        </button>
        <button
          type="submit"
          value="confirm"
          className={`px-4 py-2 rounded text-sm font-semibold text-white ${
            danger ? "bg-[#A92532] hover:bg-[#D63A46]" : "bg-emerald-700 hover:bg-emerald-600"
          }`}
        >
          {confirmLabel}
        </button>
      </form>
    </dialog>
  );
}
