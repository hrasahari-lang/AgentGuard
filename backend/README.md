# Backend

The MCP Streamable HTTP gateway is `backend.app.gateway.mcp_server:app`. It is built with the official MCP Python SDK v2 (`mcp==2.3.0`) and an ASGI bearer-authentication boundary.

Run from the repository root after installing the fully pinned Python 3.11 runtime/test dependency set in `requirements.txt`:

```powershell
$env:AGENTGUARD_DB_PATH = "backend/data/agentguard.db"
.\.venv\Scripts\python.exe -m backend.app.provision_agent issue agent_sales_1
.\.venv\Scripts\python.exe -m backend.app.run_gateway
```

Provisioned tokens are shown once; only their SHA-256 hashes are stored. The registry and audit tables share the configured SQLite database with the synthetic CRM. The local registry is prototype authentication, not OAuth/SSO. The server listens on `127.0.0.1:8000` by default.

Authentication failures use an in-process sliding-window limit keyed by the immediate transport peer. Defaults are 20 failures per peer per 60 seconds, at most 4,096 remembered peers, and the latest 10,000 failure events retained in the dedicated sanitized table. Configure these with `AGENTGUARD_AUTH_FAILURE_LIMIT`, `AGENTGUARD_AUTH_FAILURE_WINDOW_SECONDS`, `AGENTGUARD_AUTH_FAILURE_MAX_CLIENTS`, and `AGENTGUARD_AUTH_FAILURE_RETENTION`; invalid values prevent startup. The limiter ignores forwarded-IP headers, and `run_gateway` disables Uvicorn proxy-header rewriting. Behind a reverse proxy, clients may share the proxy peer bucket unless the network is configured to preserve the actual peer; use a trusted ingress rate limit for distributed attacks. This in-process limiter is not DDoS protection.

Tools:

- `search_customer_records(query, limit)` — sales-agent search is allowed within policy limits.
- `get_customer(customer_id)` — reads a record within repository scope.
- `export_customer_records(format, limit)` — sales-agent exports require approval up to 100 records and are denied above 100; neither state executes the export.

Every allowed tool call persists the decision, claims an idempotency key, persists execution start, runs the protected CRM operation, then records success/failure. Outcome-audit failures are marked separately when possible; otherwise the event remains STARTED/unknown and cannot be replayed with the same key. A caller can pass a stable `request_id` for retry deduplication; future mutating tools must require one. See the root README and security documents for remaining prototype limitations.
