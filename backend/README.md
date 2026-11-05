# Backend

The MCP Streamable HTTP gateway is `backend.app.gateway.mcp_server:app`. It is built with the official MCP Python SDK v2 (`mcp==2.3.0`) and an ASGI bearer-authentication boundary.

Run from the repository root after installing `requirements.txt`:

```powershell
$env:AGENTGUARD_DB_PATH = "backend/data/agentguard.db"
.\.venv\Scripts\python.exe -m backend.app.provision_agent issue agent_sales_1
.\.venv\Scripts\python.exe -m backend.app.run_gateway
```

Provisioned tokens are shown once; only their SHA-256 hashes are stored. The registry and audit tables share the configured SQLite database with the synthetic CRM. The local registry is prototype authentication, not OAuth/SSO. The server listens on `127.0.0.1:8000` by default.

Tools:

- `search_customer_records(query, limit)` — sales-agent search is allowed within policy limits.
- `get_customer(customer_id)` — reads a record within repository scope.
- `export_customer_records(format, limit)` — sales-agent exports require approval up to 100 records and are denied above 100; neither state executes the export.

Every allowed tool call first persists its policy decision, then runs the protected CRM operation, then records execution success or failure. See the root README for setup and the security documents for the exact boundary and limitations.
