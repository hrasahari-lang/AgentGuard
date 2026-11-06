"""Small independent MCP client proving discovery, allowed search, and denied export."""
from __future__ import annotations

import asyncio
import json
import os
import sys

from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from demo.endpoint_validation import EndpointValidationError, resolve_mcp_endpoint
from demo.pinned_http_transport import create_pinned_mcp_http_client


async def run() -> int:
    token = os.getenv("AGENTGUARD_TOKEN")
    url = os.getenv("AGENTGUARD_MCP_URL", "http://127.0.0.1:8000/mcp")
    try:
        endpoint = resolve_mcp_endpoint(url)
    except EndpointValidationError as exc:
        print(f"Invalid AGENTGUARD_MCP_URL: {exc}", file=sys.stderr)
        return 2
    if not token:
        print("Set AGENTGUARD_TOKEN to a provisioned gateway credential.", file=sys.stderr)
        return 2

    async with create_pinned_mcp_http_client(endpoint, token) as http_client:
        transport = streamable_http_client(endpoint.url, http_client=http_client)
        async with Client(transport) as client:
            tools = await client.list_tools()
            print("Discovered tools:", ", ".join(tool.name for tool in tools.tools))
            allowed = await client.call_tool("search_customer_records", {"query": "Acme", "limit": 10})
            print("Allowed search:", "".join(item.text for item in allowed.content if hasattr(item, "text")))
            denied = await client.call_tool("export_customer_records", {"format": "json", "limit": 101})
            print("Restricted export result:", "".join(item.text for item in denied.content if hasattr(item, "text")))
            return 0 if allowed.is_error is False and denied.is_error is True else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
