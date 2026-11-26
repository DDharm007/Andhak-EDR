import { useEffect, useState } from "react";
import { connectEdrWebSocket, edrApi, setAuthToken } from "./api";
import type { WsConnState } from "./api";
import { NAV_ITEMS, Shell } from "./components/Shell";
import type { HealthInfo, UserSession, ViewId } from "./types";
import { AttackGraphView } from "./views/AttackGraphView";
import { DetectionsView } from "./views/DetectionsView";
import { EndpointDetailView } from "./views/EndpointDetailView";
import { EndpointsView } from "./views/EndpointsView";
import { HuntingView } from "./views/HuntingView";
import { IntegrityView } from "./views/IntegrityView";
import { InvestigationView } from "./views/InvestigationView";
import { MalwareView } from "./views/MalwareView";
import { ManagementView } from "./views/ManagementView";
import { OverviewView } from "./views/OverviewView";
import { ResponseCenterView } from "./views/ResponseCenterView";
import { TelemetryView } from "./views/TelemetryView";

const INITIAL_VIEW_PARAM = new URLSearchParams(window.location.search).get("view");
const VALID_VIEWS = new Set<ViewId>(NAV_ITEMS.map((n) => n.id));

export function App() {
  const [activeView, setActiveView] = useState<ViewId>(
    INITIAL_VIEW_PARAM && VALID_VIEWS.has(INITIAL_VIEW_PARAM as ViewId)
      ? (INITIAL_VIEW_PARAM as ViewId)
      : "overview",
  );
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [wsState, setWsState] = useState<WsConnState>("connecting");
  const [user, setUser] = useState<UserSession | null>(null);
  const [selectedEndpointId, setSelectedEndpointId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    const label = NAV_ITEMS.find((n) => n.id === activeView)?.label ?? "Overview";
    document.title = `${label} | ANDHAK EDR`;
  }, [activeView]);

  useEffect(() => {
    edrApi.health().then(setHealth).catch(() => {});
  }, []);

  useEffect(() => {
    return connectEdrWebSocket(
      "alerts",
      (frame) => {
        if (frame.type === "alert.created" || frame.type === "incident.updated") {
          setRefreshTick((t) => t + 1);
        }
      },
      setWsState,
    );
  }, []);

  const handleSignedIn = (token: string, session: UserSession) => {
    setAuthToken(token);
    setUser(session);
    setRefreshTick((t) => t + 1);
  };

  const handleLogout = () => {
    setAuthToken(null);
    setUser(null);
    setRefreshTick((t) => t + 1);
  };

  return (
    <Shell
      activeView={activeView}
      onNavigate={setActiveView}
      health={health}
      wsState={wsState}
      user={user}
      onLogout={handleLogout}
    >
      {activeView === "overview" && (
        <OverviewView
          refreshTick={refreshTick}
          onSelectEndpoint={setSelectedEndpointId}
          onSelectIncident={setSelectedIncidentId}
          onNavigate={setActiveView}
        />
      )}
      {activeView === "endpoints" && (
        <EndpointsView
          refreshTick={refreshTick}
          onOpenEndpoint={(id) => {
            setSelectedEndpointId(id);
            setActiveView("endpoint-detail");
          }}
        />
      )}
      {activeView === "endpoint-detail" && (
        <EndpointDetailView
          endpointId={selectedEndpointId}
          onSelectEndpoint={setSelectedEndpointId}
          onGoResponses={() => setActiveView("responses")}
        />
      )}
      {activeView === "telemetry" && <TelemetryView />}
      {activeView === "detections" && (
        <DetectionsView
          refreshTick={refreshTick}
          onSelectIncident={(incId) => {
            setSelectedIncidentId(incId);
            setActiveView("investigation");
          }}
        />
      )}
      {activeView === "integrity" && <IntegrityView />}
      {activeView === "malware" && <MalwareView />}
      {activeView === "hunting" && <HuntingView />}
      {activeView === "attack-graph" && (
        <AttackGraphView
          selectedIncidentId={selectedIncidentId}
          onSelectIncident={setSelectedIncidentId}
          onOpenInvestigation={(incId) => {
            setSelectedIncidentId(incId);
            setActiveView("investigation");
          }}
        />
      )}
      {activeView === "investigation" && (
        <InvestigationView
          selectedIncidentId={selectedIncidentId}
          onSelectIncident={setSelectedIncidentId}
          onOpenResponseCenter={() => setActiveView("responses")}
        />
      )}
      {activeView === "responses" && <ResponseCenterView refreshTick={refreshTick} />}
      {activeView === "management" && (
        <ManagementView user={user} onSignedIn={handleSignedIn} />
      )}
    </Shell>
  );
}

export default App;
