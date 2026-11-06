import { useMemo, useState } from "react";
import type { FormEvent } from "react";
import {
  clearPrivilegedSessionOnRequestFailure,
  requestGatewayJson,
  resolveGatewayOrigin,
} from "./gatewaySecurity";

type Page = "overview" | "agents" | "policies" | "audit";
type Overview = {
  active_agents: number;
  policy_rules: number;
  resource_invocations_started: number;
  resource_executions_succeeded: number;
  audit_event_count: number;
  decisions: Record<string, number>;
};
type Agent = { agent_id: string; is_admin: boolean; active: boolean; credential_count: number };
type Policy = {
  policy_id: string;
  name: string;
  description: string;
  outcome: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  priority: number;
  enabled: boolean;
  risk_level: string;
  target_agents: string[];
  target_roles: string[];
  target_tools: string[];
  target_actions: string[];
  target_resources: string[];
  conditions: Record<string, unknown>;
};
type AuditEvent = {
  event_id: string;
  agent_id: string;
  tool_name: string;
  action: string;
  resource: string;
  decision: string;
  policy_id: string | null;
  execution_status: string;
  error_type: string | null;
  timestamp: number;
};
type DashboardData = { overview: Overview; agents: Agent[]; policies: Policy[]; events: AuditEvent[] };
type Connection = { token: string };
type GatewayStatus = "unavailable" | "checking" | "connected";

const GATEWAY_ORIGIN = resolveGatewayOrigin(import.meta.env.VITE_AGENTGUARD_API_ORIGIN, {
  production: import.meta.env.PROD,
  approvedHostnames: import.meta.env.VITE_AGENTGUARD_ALLOWED_API_HOSTS,
});

const NAV: { id: Page; label: string; mark: string }[] = [
  { id: "overview", label: "Overview", mark: "◫" },
  { id: "agents", label: "Agents", mark: "◉" },
  { id: "policies", label: "Policies", mark: "◇" },
  { id: "audit", label: "Audit log", mark: "≋" },
];

function App() {
  const [page, setPage] = useState<Page>("overview");
  const [token, setToken] = useState("");
  const [connection, setConnection] = useState<Connection | null>(null);
  const [data, setData] = useState<DashboardData | null>(null);
  const [gatewayStatus, setGatewayStatus] = useState<GatewayStatus>("unavailable");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [auditQuery, setAuditQuery] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("ALL");

  const loadDashboard = async (target: Connection) => {
    setLoading(true);
    setGatewayStatus("checking");
    setError("");
    try {
      const [overview, agentResponse, policyResponse, auditResponse] = await Promise.all([
        requestGatewayJson<Overview>(GATEWAY_ORIGIN, target.token, "/api/overview"),
        requestGatewayJson<{ agents: Agent[] }>(GATEWAY_ORIGIN, target.token, "/api/agents"),
        requestGatewayJson<{ policies: Policy[] }>(GATEWAY_ORIGIN, target.token, "/api/policies"),
        requestGatewayJson<{ events: AuditEvent[] }>(GATEWAY_ORIGIN, target.token, "/api/audit?limit=250"),
      ]);
      setData({ overview, agents: agentResponse.agents, policies: policyResponse.policies, events: auditResponse.events });
      setConnection(target);
      setGatewayStatus("connected");
      setLastUpdated(new Date());
    } catch (caught) {
      setGatewayStatus("unavailable");
      clearPrivilegedSessionOnRequestFailure(() => {
        setData(null);
        setConnection(null);
        setToken("");
        setLastUpdated(null);
      });
      setError(caught instanceof Error ? caught.message : "Could not load AgentGuard data.");
      throw caught;
    } finally {
      setLoading(false);
    }
  };

  const connect = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      if (!GATEWAY_ORIGIN.origin) throw new Error(GATEWAY_ORIGIN.error ?? "Gateway origin is not configured.");
      const target = { token: token.trim() };
      if (!target.token) throw new Error("Enter an admin bearer credential.");
      await loadDashboard(target);
      setToken("");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not connect to AgentGuard.");
    }
  };

  const refresh = () => {
    if (connection) void loadDashboard(connection).catch(() => undefined);
  };

  const filteredEvents = useMemo(() => {
    if (!data) return [];
    const needle = auditQuery.trim().toLowerCase();
    return data.events.filter((event) => {
      const matchesDecision = decisionFilter === "ALL" || event.decision === decisionFilter;
      const searchable = `${event.agent_id} ${event.tool_name} ${event.resource} ${event.policy_id ?? ""}`.toLowerCase();
      return matchesDecision && (!needle || searchable.includes(needle));
    });
  }, [data, auditQuery, decisionFilter]);

  if (!connection || !data) {
    return (
      <main className="connect-shell">
        <div className="connect-card">
          <div className="brand-lockup"><span className="brand-mark">A</span><span>AGENT<span className="brand-accent">GUARD</span></span></div>
          <div className="connect-art" aria-hidden="true"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="core-shield">✓</div><span className="orbit-dot dot-a"/><span className="orbit-dot dot-b"/><span className="orbit-dot dot-c"/></div>
          <div className="eyebrow">CONTROL PLANE / LOCAL REGISTRY</div>
          <h1>Govern every<br/><span>tool call.</span></h1>
          <p className="connect-copy">Connect to your AgentGuard gateway with an admin credential. Data comes directly from the protected service.</p>
          <form className="connect-form" onSubmit={connect}>
            <div className="configured-gateway"><span>TRUSTED GATEWAY ORIGIN</span><code>{GATEWAY_ORIGIN.origin ?? "Not configured"}</code></div>
            <label>Admin bearer credential<input value={token} onChange={(event) => setToken(event.target.value)} type="password" placeholder="Paste the token shown once at issuance" autoComplete="off"/></label>
            <button className="button-primary" disabled={loading || !GATEWAY_ORIGIN.origin}>{loading ? <><span className="spinner"/> Connecting…</> : <>Connect to gateway <span>→</span></>}</button>
          </form>
          {(error || GATEWAY_ORIGIN.error) && <div className="error-banner" role="alert"><span>!</span>{error || GATEWAY_ORIGIN.error}</div>}
          <div className="connect-foot">Credential stays in this tab's memory and is cleared when you disconnect.</div>
        </div>
        <aside className="connect-side"><div className="side-grid"/><div className="side-content"><span className="side-kicker">ZERO-TRUST GOVERNANCE</span><h2>Agents move fast.<br/>Access stays governed.</h2><p>Identify → Authorize → Analyze → Decide → Execute → Audit</p><div className="side-note"><span>⌁</span><div><strong>Live policy enforcement</strong><small>Only gateway-routed calls are governed.</small></div></div></div><div className="side-version">AGENTGUARD CONSOLE <span>·</span> LOCAL PROTOTYPE</div></aside>
      </main>
    );
  }

  const overview = data.overview;
  const decisionTotal = Object.values(overview.decisions).reduce((sum, value) => sum + value, 0);

  return (
    <div className="app-frame">
      <aside className="sidebar">
        <div className="brand-lockup"><span className="brand-mark">A</span><span>AGENT<span className="brand-accent">GUARD</span></span></div>
        <div className="workspace-label">WORKSPACE <span>⌄</span></div>
        <div className="workspace-card"><span className="workspace-avatar">N</span><div><strong>Northstar Labs</strong><small>Security workspace</small></div><span className="workspace-menu">···</span></div>
        <div className="nav-label">GOVERNANCE</div>
        <nav className="main-nav" aria-label="Dashboard sections">{NAV.map((item) => <button key={item.id} className={`nav-item ${page === item.id ? "active" : ""}`} onClick={() => setPage(item.id)}><span className="nav-mark">{item.mark}</span>{item.label}{item.id === "audit" && overview.audit_event_count > 0 && <span className="nav-count">{overview.audit_event_count}</span>}</button>)}</nav>
        <div className="sidebar-spacer"/>
        <div className="pipeline-card"><div className="pipeline-icon">⌁</div><div className="pipeline-label">ENFORCEMENT PIPELINE</div><div className="pipeline-flow">Identify <span>→</span> Decide <span>→</span> Audit</div><div className="pipeline-caption">Every protected call, governed.</div></div>
        <div className="profile-row"><div className="profile-avatar">AG</div><div className="profile-copy"><strong>Workspace admin</strong><small>{gatewayStatus === "connected" ? GATEWAY_ORIGIN.origin : "Gateway unavailable"}</small></div><button className="logout-button" onClick={() => { setConnection(null); setData(null); setToken(""); setLastUpdated(null); setGatewayStatus("unavailable"); setError(""); }} aria-label="Disconnect admin session">↗</button></div>
      </aside>

      <main className="main-panel">
        <header className="topbar"><div className="breadcrumb">AgentGuard <span>/</span> <strong>{NAV.find((item) => item.id === page)?.label}</strong></div><div className="top-actions"><span className="live-status"><i/> GATEWAY {gatewayStatus.toUpperCase()} <code title={GATEWAY_ORIGIN.origin ?? "Gateway origin not configured"}>{GATEWAY_ORIGIN.origin ?? "origin missing"}</code></span><button className="icon-button" onClick={refresh} disabled={loading} aria-label="Refresh data">↻</button><button className="admin-chip"><span>SA</span> Admin</button></div></header>
        {error && <div className="inline-error" role="alert">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
        <div className="page-wrap">
          <div className="page-heading"><div><div className="eyebrow">GOVERNANCE / {page.toUpperCase()}</div><h1>{page === "overview" ? "Security overview" : page === "agents" ? "Connected agents" : page === "policies" ? "Policy registry" : "Audit trail"}</h1><p>{page === "overview" ? "A live view of the access decisions protecting your data." : page === "agents" ? "Identities and credential status from the active registry." : page === "policies" ? "Deterministic rules currently loaded by the gateway." : "Persistent policy decisions and protected resource outcomes."}</p></div><div className="heading-actions"><span className="updated-label">{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : "Live data"}</span><button className="button-secondary" onClick={refresh} disabled={loading}><span className={loading ? "spin" : ""}>↻</span> Refresh</button></div></div>

          {page === "overview" && <OverviewPage overview={overview} agents={data.agents} events={data.events.slice(0, 6)} onViewAudit={() => setPage("audit")}/>}
          {page === "agents" && <AgentsPage agents={data.agents}/>}
          {page === "policies" && <PoliciesPage policies={data.policies}/>}
          {page === "audit" && <AuditPage events={filteredEvents} total={overview.audit_event_count} query={auditQuery} onQuery={setAuditQuery} decision={decisionFilter} onDecision={setDecisionFilter}/>}
          <footer className="page-footer"><span>AgentGuard governance console</span><span>Registry auth <i/> Persistent audit <i/> {decisionTotal} recorded decisions</span></footer>
        </div>
      </main>
    </div>
  );
}

function OverviewPage({ overview, agents, events, onViewAudit }: { overview: Overview; agents: Agent[]; events: AuditEvent[]; onViewAudit: () => void }) {
  const decisions = [
    { name: "Allowed", key: "ALLOW", color: "mint" },
    { name: "Denied", key: "DENY", color: "rose" },
    { name: "Pending approval", key: "REQUIRE_APPROVAL", color: "amber" },
  ];
  const allowedCount = overview.decisions.ALLOW ?? 0;
  const deniedCount = overview.decisions.DENY ?? 0;
  const approvalCount = overview.decisions.REQUIRE_APPROVAL ?? 0;
  const total = Math.max(1, Object.values(overview.decisions).reduce((sum, value) => sum + value, 0));
  return <>
    <section className="metrics-grid">
      <MetricCard label="Active agents" value={overview.active_agents} detail="With an active credential" icon="◉" tone="blue"/>
      <MetricCard label="Policy rules" value={overview.policy_rules} detail="Loaded by the gateway" icon="◇" tone="violet"/>
      <MetricCard label="Resource calls" value={overview.resource_invocations_started} detail="Entered the protected CRM" icon="↗" tone="mint"/>
      <MetricCard label="Successful calls" value={overview.resource_executions_succeeded} detail="Completed CRM operations" icon="✓" tone="amber"/>
    </section>
    <section className="overview-grid">
      <div className="panel decision-panel"><div className="panel-heading"><div><span className="panel-kicker">POLICY OUTCOMES</span><h2>Decision distribution</h2></div><span className="panel-period">ALL RECORDED</span></div><div className="decision-content"><div className="donut-wrap"><div className="donut" style={{ background: `conic-gradient(var(--mint) 0 ${allowedCount / total * 100}%, var(--rose) ${allowedCount / total * 100}% ${(allowedCount + deniedCount) / total * 100}%, var(--amber) ${(allowedCount + deniedCount) / total * 100}% ${(allowedCount + deniedCount + approvalCount) / total * 100}%, var(--line) ${(allowedCount + deniedCount + approvalCount) / total * 100}% 100%)` }}><div><strong>{overview.audit_event_count}</strong><small>events</small></div></div></div><div className="decision-legend">{decisions.map((item) => { const count = overview.decisions[item.key] ?? 0; return <div className="legend-row" key={item.key}><span className={`legend-dot ${item.color}`}/><span>{item.name}</span><strong>{count}</strong><small>{Math.round(count / total * 100)}%</small></div>; })}<p>Counts come from the persistent audit table. No synthetic events are shown.</p></div></div></div>
      <div className="panel agents-panel"><div className="panel-heading"><div><span className="panel-kicker">IDENTITIES</span><h2>Agent registry</h2></div><span className="count-pill">{agents.length} registered</span></div><div className="compact-list">{agents.length === 0 ? <EmptyState message="No agent credentials are registered."/> : agents.slice(0, 5).map((agent, index) => <div className="compact-agent" key={agent.agent_id}><span className={`agent-glyph glyph-${index % 4}`}>{agent.agent_id.slice(0, 1).toUpperCase()}</span><div className="compact-agent-copy"><strong>{agent.agent_id}</strong><small>{agent.is_admin ? "Administrator" : "Connected agent"}</small></div><span className={`state-pill ${agent.active ? "state-live" : "state-off"}`}><i/>{agent.active ? "Active" : "Revoked"}</span></div>)}</div><div className="panel-bottom-note"><span className="shield-mini">✓</span> Identity is derived from the verified bearer credential.</div></div>
    </section>
    <section className="panel activity-panel"><div className="panel-heading"><div><span className="panel-kicker">LATEST ACTIVITY</span><h2>Recent audit events</h2></div><button className="text-button" onClick={onViewAudit}>View full audit <span>→</span></button></div><AuditTable events={events} compact/></section>
    <div className="prototype-note"><span>i</span><div><strong>Prototype authentication boundary</strong><p>AgentGuard governs calls routed through this gateway. Registry bearer credentials are a local hackathon prototype, not OAuth or enterprise SSO.</p></div></div>
  </>;
}

function MetricCard({ label, value, detail, icon, tone }: { label: string; value: number; detail: string; icon: string; tone: string }) {
  return <article className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value.toLocaleString()}</div><div className="metric-detail">{detail}</div><div className={`metric-spark ${tone}`}><span/><span/><span/><span/><span/><span/><span/><span/></div></article>;
}

function AgentsPage({ agents }: { agents: Agent[] }) {
  return <section className="panel full-panel"><div className="panel-heading"><div><span className="panel-kicker">TRUSTED IDENTITIES</span><h2>Agent credentials</h2></div><span className="count-pill">{agents.length} agents</span></div>{agents.length === 0 ? <EmptyState message="No agents have been provisioned yet."/> : <div className="table-scroll"><table><thead><tr><th>AGENT</th><th>ROLE</th><th>STATUS</th><th>CREDENTIALS</th></tr></thead><tbody>{agents.map((agent, index) => <tr key={agent.agent_id}><td><span className={`table-agent-glyph glyph-${index % 4}`}>{agent.agent_id.slice(0, 1).toUpperCase()}</span><strong>{agent.agent_id}</strong></td><td>{agent.is_admin ? <span className="role-admin">Administrator</span> : <span className="role-agent">Agent</span>}</td><td><span className={`state-pill ${agent.active ? "state-live" : "state-off"}`}><i/>{agent.active ? "Active" : "Revoked"}</span></td><td>{agent.credential_count}</td></tr>)}</tbody></table></div>}<div className="panel-bottom-note"><span className="shield-mini">✓</span> Raw bearer credentials are never displayed or stored in this registry.</div></section>;
}

function PoliciesPage({ policies }: { policies: Policy[] }) {
  return <div className="policies-grid">{policies.length === 0 ? <section className="panel full-panel"><EmptyState message="No policy rules are loaded."/></section> : policies.map((policy) => <article className="panel policy-card" key={policy.policy_id}><div className="policy-top"><span className={`outcome-pill outcome-${policy.outcome.toLowerCase()}`}>{policy.outcome.replace("_", " ")}</span><span className={`enabled-state ${policy.enabled ? "" : "disabled"}`}><i/>{policy.enabled ? "Enabled" : "Disabled"}</span></div><h2>{policy.name}</h2><p className="policy-description">{policy.description}</p><div className="policy-meta"><span>PRIORITY <strong>{policy.priority}</strong></span><span>RISK <strong className={`risk-${policy.risk_level.toLowerCase()}`}>{policy.risk_level}</strong></span></div><div className="policy-scope"><div><small>TOOLS</small><div>{policy.target_tools.map((tool) => <span className="scope-tag" key={tool}>{tool}</span>)}</div></div><div><small>RESOURCES</small><div>{policy.target_resources.map((resource) => <span className="scope-tag" key={resource}>{resource}</span>)}</div></div></div>{Object.keys(policy.conditions).length > 0 && <div className="condition-box"><small>CONDITIONS</small><code>{JSON.stringify(policy.conditions)}</code></div>}<div className="policy-id">{policy.policy_id}</div></article>)}</div>;
}

function AuditPage({ events, total, query, onQuery, decision, onDecision }: { events: AuditEvent[]; total: number; query: string; onQuery: (value: string) => void; decision: string; onDecision: (value: string) => void }) {
  return <section className="panel full-panel"><div className="panel-heading"><div><span className="panel-kicker">PERSISTENT RECORDS</span><h2>Policy and execution history</h2></div><span className="count-pill">{total} total events</span></div><div className="audit-filters"><label className="search-box"><span>⌕</span><input value={query} onChange={(event) => onQuery(event.target.value)} placeholder="Search agent, tool, resource…"/></label><select value={decision} onChange={(event) => onDecision(event.target.value)} aria-label="Filter by policy decision"><option value="ALL">All decisions</option><option value="ALLOW">Allowed</option><option value="DENY">Denied</option><option value="REQUIRE_APPROVAL">Approval required</option></select></div><AuditTable events={events}/><div className="audit-footnote">Showing up to the latest 250 records returned by the gateway. Request values and credentials are excluded from audit storage.</div></section>;
}

function AuditTable({ events, compact = false }: { events: AuditEvent[]; compact?: boolean }) {
  if (events.length === 0) return <EmptyState message="No audit events match this view."/>;
  return <div className={`table-scroll ${compact ? "compact-table" : ""}`}><table><thead><tr><th>TIME</th><th>AGENT</th><th>TOOL</th><th>RESOURCE</th><th>DECISION</th><th>EXECUTION</th></tr></thead><tbody>{events.map((event) => <tr key={event.event_id}><td className="time-cell">{new Date(event.timestamp * 1000).toLocaleString()}</td><td className="agent-cell">{event.agent_id}</td><td><code className="tool-code">{event.tool_name}</code></td><td className="resource-cell">{event.resource}</td><td><span className={`outcome-pill outcome-${event.decision.toLowerCase()}`}>{event.decision.replace("_", " ")}</span></td><td><span className={`execution-label exec-${event.execution_status.toLowerCase()}`}><i/>{event.execution_status.replace("_", " ")}{event.error_type ? ` · ${event.error_type}` : ""}</span></td></tr>)}</tbody></table></div>;
}

function EmptyState({ message }: { message: string }) { return <div className="empty-state"><span>⌁</span><p>{message}</p></div>; }

export default App;
