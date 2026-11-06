"""Run the AgentGuard MCP Streamable HTTP gateway on localhost."""
import os

import uvicorn

from backend.app.gateway.mcp_server import app


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.getenv("AGENTGUARD_HOST", "127.0.0.1"),
        port=int(os.getenv("AGENTGUARD_PORT", "8000")),
        # The limiter keys off the transport peer and must not inherit an untrusted X-Forwarded-For.
        proxy_headers=False,
        log_level="info",
    )
