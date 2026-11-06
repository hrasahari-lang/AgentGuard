import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { GatewayOriginConfig } from "./gatewaySecurity";
import {
  callAgentTool,
  classifyToolResult,
  closeAgentGateway,
  connectAgentGateway,
  decisionFromAudit,
  digestRequestId,
  safeAgentError,
  validateCustomerId,
  validateExportInput,
  validateSearchInput,
} from "./agentPlaygroundClient";
import type {
  AgentMcpConnection,
  PlaygroundAuditEvent,
  PlaygroundDecision,
} from "./agentPlaygroundClient";

type DashboardAuditRefresh = () => Promise<{ events: PlaygroundAuditEvent[] } | null>;
type OperationView = {
  toolName: string;
  decision: PlaygroundDecision;
  executionStatus: string;
  response: string;
};

type Props = {
  gateway: GatewayOriginConfig;
  refreshDashboard: DashboardAuditRefresh;
};

const POLICY_DECISIONS = new Set(["ALLOW", "DENY", "REQUIRE_APPROVAL"]);

export default function AgentPlayground({ gateway, refreshDashboard }: Props) {
  const [demoToken, setDemoToken] = useState("");
  const [connection, setConnection] = useState<AgentMcpConnection | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [refreshNotice, setRefreshNotice] = useState("");
  const [operation, setOperation] = useState<OperationView | null>(null);
  const [query, setQuery] = useState("");
  const [searchLimit, setSearchLimit] = useState("10");
  const [customerId, setCustomerId] = useState("");
  const [exportFormat, setExportFormat] = useState("json");
  const [exportLimit, setExportLimit] = useState("100");
  const activeClient = useRef<AgentMcpConnection["client"] | null>(null);
  const activeBearerToken = useRef("");

  useEffect(() => () => {
    const client = activeClient.current;
    activeClient.current = null;
    activeBearerToken.current = "";
    void closeAgentGateway(client);
  }, []);

  const connect = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setRefreshNotice("");
    const token = demoToken.trim();
    setBusy(true);
    try {
      const next = await connectAgentGateway(gateway, token);
      const previous = activeClient.current;
      activeClient.current = next.client;
      activeBearerToken.current = token;
      setConnection(next);
      setDemoToken("");
      setOperation(null);
      await closeAgentGateway(previous);
    } catch (caught) {
      setError(safeAgentError(caught, token));
    } finally {
      setBusy(false);
    }
  };

  const disconnect = () => {
    const client = activeClient.current;
    activeClient.current = null;
    activeBearerToken.current = "";
    setConnection(null);
    setDemoToken("");
    setOperation(null);
    setError("");
    setRefreshNotice("");
    void closeAgentGateway(client);
  };

  const runOperation = async (toolName: string, args: Record<string, unknown>) => {
    if (!connection) {
      setError("Connect the demo agent before running a protected tool.");
      return;
    }
    if (!connection.tools.some((tool) => tool.name === toolName)) {
      setError(`The connected gateway did not advertise ${toolName}.`);
      return;
    }

    setBusy(true);
    setError("");
    setRefreshNotice("");
    setOperation(null);
    const requestId = globalThis.crypto.randomUUID();
    let toolResult: Awaited<ReturnType<typeof callAgentTool>> | null = null;
    let requestError: unknown = null;
    let refreshedAudit: { events: PlaygroundAuditEvent[] } | null = null;

    try {
      toolResult = await callAgentTool(connection.client, toolName, {
        ...args,
        request_id: requestId,
      });
    } catch (caught) {
      requestError = caught;
    }

    try {
      refreshedAudit = await refreshDashboard();
    } catch {
      setRefreshNotice("The MCP operation finished, but dashboard overview and audit could not be refreshed.");
    }

    const auditDigest = await digestRequestId(requestId).catch(() => "");
    const auditEvent = auditDigest
      ? decisionFromAudit(refreshedAudit?.events ?? [], auditDigest)
      : undefined;
    const auditedDecision = auditEvent && POLICY_DECISIONS.has(auditEvent.decision)
      ? auditEvent.decision as PlaygroundDecision
      : null;
    const decision = auditedDecision
      ?? (toolResult ? classifyToolResult(toolResult) : "UNKNOWN");
    const response = toolResult
      ? JSON.stringify(toolResult, null, 2)
      : safeAgentError(requestError, activeBearerToken.current);

    setOperation({
      toolName,
      decision,
      executionStatus: auditEvent?.execution_status ?? (toolResult && !toolResult.isError ? "SUCCEEDED" : "UNCONFIRMED"),
      response,
    });
    if (requestError && isAuthenticationFailure(requestError)) {
      const client = activeClient.current;
      activeClient.current = null;
      activeBearerToken.current = "";
      setConnection(null);
      setDemoToken("");
      void closeAgentGateway(client);
      setError("The demo-agent credential was rejected. Reconnect with an active agent token.");
    } else if (requestError) {
      setError(safeAgentError(requestError, activeBearerToken.current));
    }
    setBusy(false);
  };

  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      void runOperation("search_customer_records", validateSearchInput(query, Number(searchLimit)));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Search inputs are invalid.");
    }
  };

  const submitCustomer = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      void runOperation("get_customer", validateCustomerId(customerId));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Customer ID is invalid.");
    }
  };

  const submitExport = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      void runOperation("export_customer_records", validateExportInput(exportFormat, Number(exportLimit)));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Export inputs are invalid.");
    }
  };

  const hasTool = (name: string) => connection?.tools.some((tool) => tool.name === name) ?? false;

  return (
    <>
      <section className="panel full-panel playground-connection">
        <div className="panel-heading">
          <div><span className="panel-kicker">AUTHENTICATED MCP CLIENT</span><h2>Demo agent connection</h2></div>
          <span className={`state-pill ${connection ? "state-live" : "state-off"}`}><i/>{connection ? "Connected" : "Not connected"}</span>
        </div>
        <form className="playground-connect-form" onSubmit={connect}>
          <label>Demo-agent bearer token
            <input
              type="password"
              value={demoToken}
              onChange={(event) => setDemoToken(event.target.value)}
              placeholder={connection ? "Credential held in memory while connected" : "Enter the separately provisioned demo-agent token"}
              autoComplete="off"
              spellCheck={false}
              disabled={busy || Boolean(connection)}
              aria-label="Demo-agent bearer token"
            />
          </label>
          {connection
            ? <button className="button-secondary" type="button" onClick={disconnect} disabled={busy}>Disconnect demo agent</button>
            : <button className="button-primary" type="submit" disabled={busy || !gateway.origin || !demoToken.trim()}>{busy ? <><span className="spinner"/> Connecting…</> : <>Connect demo agent <span>→</span></>}</button>}
        </form>
        <p className="playground-note">The token is kept in component memory, sent only to the configured gateway, and cleared when disconnected or when you leave this page.</p>
        {connection && <div className="playground-tools" aria-label="Tools discovered from AgentGuard">
          <strong>Tools discovered from the gateway</strong>
          {connection.tools.length === 0
            ? <span className="tool-discovery-empty">No tools were advertised.</span>
            : connection.tools.map((tool) => <div className="playground-tool" key={tool.name}><code>{tool.name}</code><span>{tool.description || "No description supplied."}</span></div>)}
        </div>}
        {error && <div className="error-banner playground-error" role="alert"><span>!</span>{error}</div>}
        {refreshNotice && <div className="playground-refresh-notice" role="status">{refreshNotice}</div>}
        {!gateway.origin && <div className="error-banner playground-error" role="alert"><span>!</span>{gateway.error ?? "Trusted gateway origin is not configured."}</div>}
      </section>

      <div className="playground-grid">
        <section className="panel playground-card">
          <div className="panel-heading"><div><span className="panel-kicker">READ / SEARCH</span><h2>Search customer records</h2></div><span className="playground-index">01</span></div>
          <form className="playground-form" onSubmit={submitSearch}>
            <label>Search term<input value={query} onChange={(event) => setQuery(event.target.value)} maxLength={120} placeholder="Company, email, or customer ID" disabled={!connection || busy}/></label>
            <label>Maximum records<input type="number" value={searchLimit} min={1} max={100} step={1} onChange={(event) => setSearchLimit(event.target.value)} disabled={!connection || busy}/></label>
            <button className="button-primary" type="submit" disabled={!connection || busy || !hasTool("search_customer_records")}>{busy ? "Working…" : "Run search"}</button>
          </form>
        </section>

        <section className="panel playground-card">
          <div className="panel-heading"><div><span className="panel-kicker">READ / RESOURCE SCOPE</span><h2>Retrieve a customer</h2></div><span className="playground-index">02</span></div>
          <form className="playground-form" onSubmit={submitCustomer}>
            <label>Customer ID<input value={customerId} onChange={(event) => setCustomerId(event.target.value)} maxLength={64} placeholder="e.g. CUST-101" disabled={!connection || busy}/></label>
            <p className="playground-field-note">The gateway applies the authenticated agent’s resource scope.</p>
            <button className="button-primary" type="submit" disabled={!connection || busy || !hasTool("get_customer")}>{busy ? "Working…" : "Retrieve record"}</button>
          </form>
        </section>

        <section className="panel playground-card playground-export">
          <div className="panel-heading"><div><span className="panel-kicker">POLICY-CONTROLLED</span><h2>Attempt customer export</h2></div><span className="playground-index">03</span></div>
          <form className="playground-form export-form" onSubmit={submitExport}>
            <label>Format<select value={exportFormat} onChange={(event) => setExportFormat(event.target.value)} disabled={!connection || busy}><option value="json">JSON</option><option value="csv">CSV</option></select></label>
            <label>Requested records<input type="number" value={exportLimit} min={1} max={1000} step={1} onChange={(event) => setExportLimit(event.target.value)} disabled={!connection || busy}/></label>
            <button className="button-secondary" type="submit" disabled={!connection || busy || !hasTool("export_customer_records")}>{busy ? "Checking policy…" : "Submit to policy engine"}</button>
          </form>
          <p className="playground-field-note">The gateway decides ALLOW, DENY, or REQUIRE_APPROVAL. This page cannot approve a request.</p>
        </section>
      </div>

      {operation && <section className="panel full-panel playground-result" aria-live="polite">
        <div className="panel-heading">
          <div><span className="panel-kicker">LIVE MCP RESPONSE</span><h2>{operation.toolName}</h2></div>
          <span className={`outcome-pill outcome-${operation.decision.toLowerCase()}`}>{operation.decision.replace("_", " ")}</span>
        </div>
        <div className="playground-execution">Execution status: <strong>{operation.executionStatus.replaceAll("_", " ")}</strong></div>
        <pre className="playground-response">{operation.response}</pre>
      </section>}
    </>
  );
}

function isAuthenticationFailure(error: unknown): boolean {
  if (!error || typeof error !== "object" || !("status" in error)) return false;
  return error.status === 401 || error.status === 403;
}
