import type { ReactNode } from "react";
import {
  Activity,
  Cpu,
  FileCheck2,
  GitFork,
  HardDrive,
  Laptop,
  LayoutDashboard,
  Lock,
  Radio,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  WifiOff,
} from "lucide-react";
import type { HealthInfo, UserSession, ViewId } from "../types";
import type { WsConnState } from "../api";

export interface NavItem {
  id: ViewId;
  label: string;
  section: string;
  Icon: typeof Activity;
}

export const NAV_ITEMS: NavItem[] = [
  { id: "overview", label: "Overview", section: "Fleet", Icon: LayoutDashboard },
  { id: "endpoints", label: "Endpoints", section: "Fleet", Icon: Laptop },
  { id: "endpoint-detail", label: "Endpoint Details", section: "Fleet", Icon: Cpu },
  { id: "telemetry", label: "Live Telemetry", section: "Monitoring", Icon: Activity },
  { id: "detections", label: "Detection Center", section: "Detection", Icon: ShieldAlert },
  { id: "integrity", label: "Integrity Monitor", section: "Detection", Icon: FileCheck2 },
  { id: "malware", label: "Malware Analysis", section: "Detection", Icon: HardDrive },
  { id: "hunting", label: "Threat Hunting", section: "Investigation", Icon: Search },
  { id: "attack-graph", label: "Attack Graph", section: "Investigation", Icon: GitFork },
  { id: "investigation", label: "Investigation", section: "Investigation", Icon: Terminal },
  { id: "responses", label: "Response Center", section: "Control", Icon: ShieldCheck },
  { id: "management", label: "Agents & SOC", section: "Control", Icon: Settings2 },
];

export function Shell({
  activeView,
  onNavigate,
  health,
  wsState,
  user,
  onLogout,
  children,
}: {
  activeView: ViewId;
  onNavigate: (view: ViewId) => void;
  health: HealthInfo | null;
  wsState: WsConnState;
  user: UserSession | null;
  onLogout: () => void;
  children: ReactNode;
}) {
  const wsBadge =
    wsState === "connected"
      ? { label: "WS LIVE", cls: "border-emerald-700 text-emerald-300 bg-emerald-950/60" }
      : wsState === "reconnecting" || wsState === "connecting"
        ? { label: "WS RECONNECTING", cls: "border-amber-600 text-amber-300 bg-amber-950/50" }
        : { label: "WS OFFLINE", cls: "border-[#D63A46] text-[#FF949C] bg-[#D63A46]/20" };

  return (
    <div className="min-h-screen bg-[#101114] text-[#E8E7E3] flex flex-col lg:flex-row">
      <a href="#main-content" className="skip-link visually-hidden">
        Skip to main content
      </a>

      <aside className="w-full lg:w-64 shrink-0 bg-[#17181D] border-b lg:border-b-0 lg:border-r border-[#303139] flex flex-col">
        <div className="p-4 border-b border-[#303139] flex items-center gap-3">
          <img
            src="/andhak-logo.png"
            alt="ANDHAK"
            className="w-10 h-10 object-contain brand-mark-img shrink-0"
          />
          <div>
            <div className="text-sm font-bold tracking-[0.14em] text-[#E8E7E3]">ANDHAK EDR</div>
            <div className="text-[11px] font-mono text-[#9A9CA6]">Detect. Investigate. Respond.</div>
          </div>
        </div>

        <nav aria-label="Primary EDR console" className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {NAV_ITEMS.map(({ id, label, Icon }) => {
            const active = activeView === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => onNavigate(id)}
                aria-current={active ? "page" : undefined}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-sm font-medium transition-colors ${
                  active
                    ? "bg-[#A92532] text-white"
                    : "text-[#E8E7E3] hover:bg-[#1D1E24] text-left"
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                <span className="truncate">{label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-3 border-t border-[#303139] text-xs space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[#9A9CA6] font-mono">MODE</span>
            <span
              className={`px-2 py-0.5 rounded font-mono font-semibold border ${
                health?.mode === "demo"
                  ? "border-amber-600 bg-amber-950/60 text-amber-200"
                  : "border-[#303139] bg-[#1D1E24] text-[#E8E7E3]"
              }`}
            >
              {health?.mode === "demo" ? "READ-ONLY DEMO" : "LOCAL LIVE"}
            </span>
          </div>
          {user ? (
            <div className="flex items-center justify-between gap-2 pt-1 border-t border-[#24262E]">
              <div className="truncate">
                <div className="font-mono text-[#E8E7E3] truncate">{user.username}</div>
                <div className="font-mono text-[11px] text-[#9A9CA6] uppercase">{user.role}</div>
              </div>
              <button
                type="button"
                onClick={onLogout}
                className="px-2 py-1 rounded border border-[#303139] bg-[#1D1E24] text-[11px] font-mono hover:border-[#A92532]"
              >
                Sign out
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => onNavigate("management")}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded border border-[#303139] bg-[#1D1E24] font-mono text-xs hover:border-[#A92532]"
            >
              <Lock className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Operator Sign-In</span>
            </button>
          )}
        </div>
      </aside>

      <div className="flex-1 min-w-0 flex flex-col">
        <header className="px-5 py-3 bg-[#17181D] border-b border-[#303139] flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-mono text-[#9A9CA6]">
            <span>ENGINE</span>
            <span className="text-[#E8E7E3]">ZERO-AI DETERMINISTIC</span>
            <span aria-hidden="true">·</span>
            <span>DB</span>
            <span className="text-[#E8E7E3]">LOCAL SQLITE WAL</span>
          </div>
          <div className="flex items-center gap-2">
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-mono font-semibold ${wsBadge.cls}`}
            >
              {wsState === "offline" ? (
                <WifiOff className="w-3 h-3" aria-hidden="true" />
              ) : (
                <Radio className="w-3 h-3" aria-hidden="true" />
              )}
              <span>{wsBadge.label}</span>
            </span>
          </div>
        </header>

        <main id="main-content" className="flex-1 p-5 space-y-5 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
