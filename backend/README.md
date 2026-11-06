# Backend

The MCP Streamable HTTP gateway is `backend.app.gateway.mcp_server:app`. It is built with the official MCP Python SDK v2 (`mcp==2.3.0`) and an ASGI bearer-authentication boundary.

Run from the repository root after installing the fully pinned Python 3.11 runtime/test dependency set in `requirements.txt`:

```powershell
$env:AGENTGUARD_DB_PATH = "backend/data/agentguard.db"
.\.venv\Scripts\python.exe -m backend.app.provision_agent issue agent_sales_1
.\.venv\Scripts\python.exe -m backend.app.run_gateway
```

Provisioned tokens are shown once; only their SHA-256 hashes are stored. The registry and audit tables share the configured SQLite database with the synthetic CRM. The local registry is prototype authentication, not OAuth/SSO. The server listens on `127.0.0.1:8000` by default.

Every HTTP request passes an in-process sliding-window request limit before credential lookup. It defaults to 300 requests per socket peer per 60 seconds (`AGENTGUARD_AUTH_REQUEST_LIMIT`) and applies equally to valid and invalid credentials. Authentication-failure audit writes have a separate 20-per-peer cap (`AGENTGUARD_AUTH_FAILURE_LIMIT`); after it is reached, requests remain 401 but no further failure rows are written until the window expires. The peer bucket table is bounded by `AGENTGUARD_AUTH_FAILURE_MAX_CLIENTS`; active peers are never evicted, and excess new peers share one overflow bucket until expired buckets are reclaimed. Retention keeps the latest 10,000 sanitized authentication-failure rows by default (`AGENTGUARD_AUTH_FAILURE_RETENTION`). Invalid settings prevent startup.

The app uses only the immediate socket peer and ignores forwarded-IP headers. `run_gateway` disables Uvicorn proxy-header rewriting. Behind a reverse proxy, multiple users may share the proxy peer bucket; multiple processes do not share limiter state. Do not trust arbitrary `X-Forwarded-For`. Use upstream ingress limits as the deployment-wide control. If a proxy identity is enabled, trust only fixed proxy addresses and require the proxy to overwrite client-supplied forwarding headers. The local limiter is not DDoS protection.

`GET /healthz` is an unauthenticated liveness check returning only `{"status":"ok"}`. All admin APIs and MCP routes continue through bearer authentication. CORS reads exact comma-separated origins from `AGENTGUARD_CORS_ORIGINS`; if unset, only the two local Vite origins are allowed. For the hosted dashboard, set it to `https://agent-guard-duo-x.vercel.app`.

For hosted bootstrap, set both `AGENTGUARD_BOOTSTRAP_ADMIN_TOKEN` and `AGENTGUARD_BOOTSTRAP_DEMO_AGENT_TOKEN` to distinct URL-safe secrets of at least 43 characters. On startup, the gateway idempotently registers `agent_admin` with the admin role and `agent_sales_1` as the demo agent. SQLite stores only SHA-256 hashes. Changing either secret rotates that identity's prior active token. A token explicitly revoked in SQLite remains revoked on restart even if its configured environment value is unchanged; set a new secret to rotate it. Never put actual values in the repository or logs.

The CORS allowlist permits only the required browser headers for bearer authentication and MCP Streamable HTTP: Mcp-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Session-Id, and Last-Event-ID. Protocol header support does not broaden the configured origin allowlist.

Tools:

- `search_customer_records(query, limit)` — sales-agent search is allowed within policy limits.
- `get_customer(customer_id)` — reads a record within repository scope.
- `export_customer_records(format, limit)` — sales-agent exports require approval up to 100 records and are denied above 100; neither state executes the export.

Every allowed tool call persists the decision, claims an idempotency key, persists execution start, runs the protected CRM operation, then records success/failure. Outcome-audit failures are marked separately when possible; otherwise the event remains STARTED/unknown and cannot be replayed with the same key. A caller can pass a stable `request_id` for retry deduplication; future mutating tools must require one. See the root README and security documents for remaining prototype limitations.
