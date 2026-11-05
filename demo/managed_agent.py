"""Minimal task agent whose only protected tools are supplied by AgentGuard over MCP."""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import uuid

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", required=True, help="Customer search task for the governed CRM")
    parser.add_argument("--limit", type=int, default=10, help="Maximum result count (1..100)")
    parser.add_argument(
        "--request-id",
        default=os.getenv("AGENTGUARD_REQUEST_ID"),
        help="Stable ID to reuse if retrying the same task",
    )
    return parser.parse_args()


async def run() -> int:
    args = parse_args()
    token = os.getenv("AGENTGUARD_TOKEN")
    endpoint = os.getenv("AGENTGUARD_MCP_URL", "http://127.0.0.1:8000/mcp")
    if not token:
        print("Set AGENTGUARD_TOKEN to a provisioned gateway credential.", file=sys.stderr)
        return 2
    if not 1 <= args.limit <= 100:
        print("limit must be between 1 and 100.", file=sys.stderr)
        return 2

    request_id = args.request_id or uuid.uuid4().hex
    print(f"AgentGuard request ID: {request_id}", flush=True)
    try:
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http_client:
            transport = streamable_http_client(endpoint, http_client=http_client)
            async with Client(transport) as client:
                available = {tool.name for tool in (await client.list_tools()).tools}
                if "search_customer_records" not in available:
                    print("AgentGuard does not expose the required governed search tool.", file=sys.stderr)
                    return 3
                result = await client.call_tool(
                    "search_customer_records",
                    {"query": args.query, "limit": args.limit, "request_id": request_id},
                )
    except Exception:
        print(
            "Gateway call failed; execution status may be unknown. Inspect the AgentGuard audit "
            "before retrying with this request ID.",
            file=sys.stderr,
        )
        return 1

    if result.is_error:
        message = "".join(item.text for item in result.content if hasattr(item, "text"))
        print(f"AgentGuard tool call returned an error: {message}", file=sys.stderr)
        return 1
    print("Governed customer search:")
    print("".join(item.text for item in result.content if hasattr(item, "text")))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
