# Demo

Reserved for one independently implemented MCP-compatible agent client and reproducible demonstration scripts. The agent must not hold CRM credentials.
# Local MCP demonstration

Start the gateway, provision `agent_sales_1` as described in the root README, then run the separate client process:

```powershell
$env:AGENTGUARD_TOKEN = "<token shown once by the provisioning command>"
$env:AGENTGUARD_MCP_URL = "http://127.0.0.1:8000/mcp"
.\.venv\Scripts\python.exe -m demo.external_agent
```

The client discovers tools, performs an allowed synthetic CRM search, then attempts a bulk export that policy denies. It uses the official MCP SDK client over Streamable HTTP. It does not contain a model or claim to demonstrate arbitrary agents.

Both MCP clients resolve and validate `AGENTGUARD_MCP_URL` before constructing a bearer-bearing HTTP client. HTTP is limited to loopback IPs or `localhost` resolving only to loopback. Remote HTTPS requires an exact DNS hostname in `AGENTGUARD_TRUSTED_MCP_HOSTS`; every resolved address must be globally routable. Private, loopback, link-local, multicast, unspecified, reserved, and IPv4-mapped private destinations are rejected even for allowlisted hosts. Embedded credentials, malformed/ambiguous hosts, query strings, fragments, unapproved hosts and non-public destinations are rejected.

The DNS answers that pass validation are retained with the endpoint. A shared `httpx2` transport dials one of those literal IP addresses, sets the original hostname as the HTTP `Host` authority and TLS `sni_hostname`, and keeps certificate hostname verification enabled. Ambient proxy settings are disabled so a proxy cannot resolve the hostname again. Both clients use this same transport. The pinned MCP SDK allows only same-origin redirects; the transport rejects any request that escapes the configured origin before sending it.

## AgentGuard-managed task agent

`managed_agent` is the minimal agent loop: it accepts a customer-search task, discovers the gateway's MCP tools, and calls the scoped search tool using the configured bearer credential. It imports no CRM repository or database code, so protected work remains behind gateway authentication, policy evaluation, execution and audit.

```powershell
$env:AGENTGUARD_TOKEN = "<token shown once by the provisioning command>"
$env:AGENTGUARD_MCP_URL = "http://127.0.0.1:8000/mcp"
.\.venv\Scripts\python.exe -m demo.managed_agent --query "Acme"
```

The agent prints the generated request ID. Reuse it with `--request-id <id>` or `AGENTGUARD_REQUEST_ID` only when retrying the same task; AgentGuard blocks repeats. This is a deterministic MCP task agent, not an LLM-based planner.

For a remote gateway, set the exact HTTPS hostname in `AGENTGUARD_TRUSTED_MCP_HOSTS`, for example `gateway.example.com`. Do not use a wildcard. Remote private-address gateways are not accepted by these demo clients; use a public HTTPS gateway or a separately designed private network integration.
