# AgentGuard

AgentGuard is a BYOA (Bring Your Own Agent) governance gateway. Existing compatible agents connect to its MCP Streamable HTTP endpoint; AgentGuard authenticates each request, evaluates deterministic policy, executes permitted operations against a synthetic CRM, and records decisions and execution outcomes.

**Governed path:** Identify → Authorize → Analyze → Decide → Execute → Audit.

AgentGuard governs only tool calls routed through its gateway. It does not intercept arbitrary agent activity or provide production OAuth/SSO.

## Current vertical slice

- MCP Python SDK **2.3.0**, pinned in `requirements.txt`.
- Bearer tokens are generated locally, stored only as SHA-256 hashes, verified before MCP request handling, and revocable.
- Server-side agent identity comes only from the credential registry. Tool arguments cannot grant identity or admin status.
- `search_customer_records`, `get_customer`, and `export_customer_records` use the existing scoped SQLite CRM repository.
- `ALLOW` executes only after the decision is persisted. `DENY` and `REQUIRE_APPROVAL` are audited and never call the CRM repository. Human approval workflow is not implemented yet.
- Audit records separate policy decisions from execution outcomes and omit request values and credentials.

The local credential registry is a hackathon prototype, not an OAuth authorization server. Do not expose it as enterprise authentication or claim it controls bypass paths.

## Run locally (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:AGENTGUARD_DB_PATH = "backend/data/agentguard.db"
.\.venv\Scripts\python.exe -m backend.app.provision_agent issue agent_sales_1
.\.venv\Scripts\python.exe -m backend.app.run_gateway
```

The credential command displays the raw token once. Configure an MCP client to call `http://127.0.0.1:8000/mcp` and send it as `Authorization: Bearer <token>`. Keep the token private; revoke it with:

```powershell
.\.venv\Scripts\python.exe -m backend.app.provision_agent revoke agent_sales_1
```

The database persists in `backend/data/agentguard.db` by default. Override the path with `AGENTGUARD_DB_PATH`.

### Run the managed MCP task agent

With the gateway running, use a separate terminal and the token issued for the agent identity:

```powershell
$env:AGENTGUARD_TOKEN = "<provisioned agent token>"
$env:AGENTGUARD_MCP_URL = "http://127.0.0.1:8000/mcp"
.\.venv\Scripts\python.exe -m demo.managed_agent --query "Acme"
```

The client discovers and calls `search_customer_records` through the authenticated MCP gateway. It has no CRM database access. It prints a request ID before the call; provide `--request-id <id>` when a stable key is needed. After a connection error or unclear result, inspect the audit before retrying.

### Admin dashboard

In a second terminal, start the Vite dashboard:

```powershell
cd frontend
npm ci
npm run dev
```

Open the local URL printed by Vite, enter the gateway origin and an admin bearer token, then connect. The dashboard reads overview counts, agents, policies, and audit events from the authenticated backend API. It does not fabricate metrics. Keep admin tokens private; the UI holds the token in memory for the current tab session.

For a local demo admin credential, run `python -m backend.app.provision_agent issue demo_admin --admin` from the repository root in a terminal where the database path matches the running gateway. Copy the one-time token into the dashboard; do not commit or share it.

The Agent playground page accepts a separate demo-agent token. It connects to the configured gateway's /mcp endpoint with the official TypeScript MCP SDK v2, discovers the gateway's tools, and allows scoped search, customer retrieval, and a policy-controlled export attempt. The demo credential is held in component memory and sent only to the MCP endpoint; it is not an admin credential and is not stored in browser storage. Each tool call refreshes the dashboard overview and audit rows. DENY and REQUIRE_APPROVAL remain gateway outcomes; the playground cannot approve or bypass them.

## Verify

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

HTTP integration tests exercise authenticated MCP calls, token rejection and revocation, resource scoping, `ALLOW`/`DENY`/`REQUIRE_APPROVAL`, audit failure closure, and invocation counters. They require the pinned SDK and its Uvicorn dependency.

## Current limitations

- The admin control-plane views remain read-only; the Agent playground invokes existing MCP tools only. Approval UI/workflow and dynamic policy editing are not implemented.
- The frontend and backend have public Vercel/Render URLs, but authenticated hosted end-to-end behavior must be verified after each deployment. No OAuth provider or Render Workflows integration is implemented.
- The gateway binds to localhost by default. Public hosting requires configured transport host protection, HTTPS, production credential issuance, persistent database hosting, and deployment verification.
- The CRM data is synthetic and the audit trail is persistent, not tamper-evident.

See [SYSTEM_ARCHITECTURE.md](SYSTEM_ARCHITECTURE.md), [SECURITY_RULES.md](SECURITY_RULES.md), and [CURRENT_STATE.md](CURRENT_STATE.md) for the enforcement design and verified progress.
