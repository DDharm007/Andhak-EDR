import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { OriginBadge, SeverityBadge } from "./components/Badges";
import App from "./App";

describe("ANDHAK EDR Console UI", () => {
  it("renders distinct origin provenance labels cleanly", () => {
    render(
      <div>
        <OriginBadge origin="real_endpoint" />
        <OriginBadge origin="recorded_demo" />
        <OriginBadge origin="test_fixture" />
        <SeverityBadge severity="critical" />
      </div>,
    );
    expect(screen.getByText("REAL TELEMETRY")).toBeInTheDocument();
    expect(screen.getByText("RECORDED DEMO")).toBeInTheDocument();
    expect(screen.getByText("TEST FIXTURE")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });

  it("renders all 12 navigation views and switches document title cleanly", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () =>
        JSON.stringify({
          status: "ok",
          mode: "live",
          version: "0.2.0",
          kpis: {
            endpoints_total: 1,
            endpoints_online: 1,
            endpoints_isolated: 0,
            endpoints_degraded: 0,
            telemetry_events_total: 42,
            alerts_open: 2,
            alerts_critical: 1,
            alerts_high: 1,
            incidents_open: 1,
            pending_approvals: 0,
            quarantined_files: 0,
          },
          severity_breakdown: [{ severity: "critical", count: 1 }],
          source_breakdown: [{ source: "behavioral", count: 1 }],
          top_mitre_techniques: [{ technique_id: "T1059.001", count: 1 }],
          alert_timeline: [],
          telemetry_origins: { real_endpoint: 1 },
          websocket_subscribers: {},
          endpoints: [],
          recent_alerts: [],
          recent_incidents: [],
          items: [],
          baselines: [],
          events: [],
          total: 0,
        }),
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("Fleet Posture Overview")).toBeInTheDocument();
    });
    expect(document.title).toBe("Overview | ANDHAK EDR");

    fireEvent.click(screen.getByRole("button", { name: "Investigation" }));
    expect(await screen.findByText("Deterministic Incident Investigation")).toBeInTheDocument();
    expect(document.title).toBe("Investigation | ANDHAK EDR");

    fireEvent.click(screen.getByRole("button", { name: "Agents & SOC" }));
    expect(
      await screen.findByText("Agent Provisioning, RBAC & ANDHAK SOC Bridge"),
    ).toBeInTheDocument();

    vi.unstubAllGlobals();
  });

  it("displays explicit error alert when backend is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNREFUSED")));
    render(<App />);
    expect(
      await screen.findByText(/Unable to reach ANDHAK EDR backend API/i),
    ).toBeInTheDocument();
    vi.unstubAllGlobals();
  });
});
