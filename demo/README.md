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

## AgentGuard-managed task agent

`managed_agent` is the minimal agent loop: it accepts a customer-search task, discovers the gateway's MCP tools, and calls the scoped search tool using the configured bearer credential. It imports no CRM repository or database code, so protected work remains behind gateway authentication, policy evaluation, execution and audit.

```powershell
$env:AGENTGUARD_TOKEN = "<token shown once by the provisioning command>"
$env:AGENTGUARD_MCP_URL = "http://127.0.0.1:8000/mcp"
.\.venv\Scripts\python.exe -m demo.managed_agent --query "Acme"
```

The agent prints the generated request ID. Reuse it with `--request-id <id>` or `AGENTGUARD_REQUEST_ID` only when retrying the same task; AgentGuard blocks repeats. This is a deterministic MCP task agent, not an LLM-based planner.
