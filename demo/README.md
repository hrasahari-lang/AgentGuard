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
