import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Eye, EyeOff, RefreshCw } from "lucide-react";
import { edrApi } from "../api";
import { StatusPill } from "../components/Badges";
import { DataTable } from "../components/DataTable";
import type { UserSession } from "../types";

export function ManagementView({
  user,
  onSignedIn,
}: {
  user: UserSession | null;
  onSignedIn: (token: string, user: UserSession) => void;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [authMsg, setAuthMsg] = useState<string | null>(null);

  const [tokenDesc, setTokenDesc] = useState("Windows Workstation Enrollment");
  const [issuedToken, setIssuedToken] = useState<Record<string, string> | null>(null);

  const [policy, setPolicy] = useState<Record<string, unknown> | null>(null);
  const [retention, setRetention] = useState<Record<string, number>>({});
  const [socStatus, setSocStatus] = useState<Record<string, unknown> | null>(null);
  const [socEvents, setSocEvents] = useState<Array<Record<string, unknown>>>([]);
  const [syncResult, setSyncResult] = useState<string | null>(null);

  const loadConfigAndSoc = () => {
    if (user) {
      edrApi
        .policies()
        .then((res) => {
          setPolicy(res.policy);
          setRetention(res.retention);
        })
        .catch(() => {});
    }
    Promise.all([edrApi.socBridgeStatus(), edrApi.socBridgeEvents()])
      .then(([st, ev]) => {
        setSocStatus(st);
        setSocEvents(ev.items);
      })
      .catch(() => {});
  };

  useEffect(loadConfigAndSoc, [user]);

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    setAuthMsg(null);
    try {
      const res = await edrApi.login(username.trim(), password);
      setPassword("");
      onSignedIn(res.access_token, res.user);
      setAuthMsg(`Signed in as ${res.user.username} (${res.user.role}).`);
    } catch (err) {
      setAuthMsg(err instanceof Error ? err.message : "Authentication failed");
    }
  };

  const handleIssueToken = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const tok = await edrApi.issueEnrollmentToken(tokenDesc);
      setIssuedToken(tok);
    } catch (err) {
      setAuthMsg(err instanceof Error ? err.message : "Failed issuing token");
    }
  };

  const handleSocSync = async () => {
    setSyncResult(null);
    try {
      const res = await edrApi.socBridgeSync();
      setSyncResult(
        `SOC Reachable: ${String(res.soc_reachable)} · Normalized: ${String(res.events_normalized)} · Pulled IOCs: ${String(res.iocs_pulled)} · Pushed IOCs: ${String(res.iocs_pushed)} (${String(res.detail)})`,
      );
      loadConfigAndSoc();
    } catch (err) {
      setSyncResult(err instanceof Error ? err.message : "SOC sync blocked");
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-[#E8E7E3]">
          Agent Provisioning, RBAC &amp; ANDHAK SOC Bridge
        </h1>
        <p className="text-xs text-[#9A9CA6] mt-0.5">
          Authenticate operator sessions, issue single-use enrollment tokens, configure policies, and
          synchronize with ANDHAK SOC.
        </p>
      </div>

      {authMsg && (
        <div role="status" aria-live="polite" className="rounded border border-[#303139] bg-[#1D1E24] p-3 text-xs font-mono">
          {authMsg}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <form
          onSubmit={handleLogin}
          className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 space-y-3"
        >
          <h2 className="text-sm font-semibold text-[#E8E7E3]">Operator Sign-In (Argon2id + JWT)</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label htmlFor="auth-user" className="block text-xs font-mono text-[#9A9CA6] mb-1">
                Username *
              </label>
              <input
                id="auth-user"
                name="username"
                required
                autoComplete="username"
                autoCorrect="off"
                autoCapitalize="none"
                spellCheck={false}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="edr-input w-full font-mono"
              />
            </div>
            <div>
              <label htmlFor="auth-pass" className="block text-xs font-mono text-[#9A9CA6] mb-1">
                Password *
              </label>
              <div className="flex gap-1.5">
                <input
                  id="auth-pass"
                  name="password"
                  type={showPw ? "text" : "password"}
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="edr-input w-full font-mono"
                />
                <button
                  type="button"
                  onClick={() => setShowPw((s) => !s)}
                  aria-pressed={showPw}
                  aria-label={showPw ? "Hide password" : "Show password"}
                  className="px-2.5 rounded border border-[#303139] bg-[#1D1E24]"
                >
                  {showPw ? <EyeOff className="w-4 h-4" aria-hidden="true" /> : <Eye className="w-4 h-4" aria-hidden="true" />}
                </button>
              </div>
            </div>
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white"
          >
            Sign In
          </button>
        </form>

        <form
          onSubmit={handleIssueToken}
          className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 space-y-3"
        >
          <h2 className="text-sm font-semibold text-[#E8E7E3]">
            One-Time Agent Enrollment Token
          </h2>
          <div>
            <label htmlFor="tok-desc" className="block text-xs font-mono text-[#9A9CA6] mb-1">
              Endpoint Description
            </label>
            <input
              id="tok-desc"
              value={tokenDesc}
              onChange={(e) => setTokenDesc(e.target.value)}
              className="edr-input w-full"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded border border-[#A92532] bg-[#1D1E24] hover:bg-[#A92532] text-xs font-semibold text-white"
          >
            Issue Bootstrap Token
          </button>
          {issuedToken && (
            <div className="rounded border border-[#303139] bg-[#101114] p-2.5 text-xs font-mono break-all">
              <div>Token: {issuedToken.bootstrap_token}</div>
              <div className="text-[#9A9CA6] mt-1">
                CLI: andhak-edr-agent.exe enroll --token {issuedToken.bootstrap_token}
              </div>
            </div>
          )}
        </form>
      </div>

      {policy && (
        <section className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 space-y-2 text-xs font-mono">
          <h2 className="text-sm font-semibold text-[#E8E7E3]">Active Policy &amp; Retention</h2>
          <div>
            Policy: {String(policy.name)} (v{String(policy.version)}) · External Intel:{" "}
            {String(policy.intel_external_enabled)} · File Upload:{" "}
            {String(policy.allow_file_upload)}
          </div>
          <div className="text-[#9A9CA6]">
            Retention (days): {JSON.stringify(retention)}
          </div>
        </section>
      )}

      <section className="edr-panel rounded-md border border-[#303139] bg-[#17181D] p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-[#E8E7E3]">
              ANDHAK SOC Integration Bridge ({String(socStatus?.soc_base_url ?? "127.0.0.1:8000")})
            </h2>
            <p className="text-xs text-[#9A9CA6]">
              Normalized <code className="font-mono text-[#E8E7E3]">edr-*</code> event export,
              bidirectional IOC sync, and HMAC containment fulfillment.
            </p>
          </div>
          <button
            type="button"
            onClick={handleSocSync}
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded bg-[#A92532] hover:bg-[#D63A46] text-xs font-semibold text-white"
          >
            <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Sync with ANDHAK SOC</span>
          </button>
        </div>

        {syncResult && (
          <div role="status" aria-live="polite" className="rounded border border-[#303139] bg-[#101114] p-2.5 text-xs font-mono">
            {syncResult}
          </div>
        )}

        <DataTable
          caption="SOC-Normalized EDR Events Preview"
          rows={socEvents.slice(0, 10)}
          rowKey={(e, i) => String(e.event_id ?? i)}
          columns={[
            { key: "id", label: "SOC Event ID", render: (e) => <span className="font-mono text-xs">{String(e.event_id)}</span> },
            { key: "src", label: "Source System", render: (e) => <span className="font-mono text-xs">{String(e.source_system)}</span> },
            { key: "ep", label: "Endpoint", render: (e) => <span className="font-mono text-xs">{String(e.endpoint)}</span> },
            { key: "sev", label: "Severity", render: (e) => <StatusPill status={String(e.severity)} /> },
            { key: "sum", label: "Summary", render: (e) => <span className="text-xs">{String(e.summary)}</span> },
          ]}
        />
      </section>
    </div>
  );
}
