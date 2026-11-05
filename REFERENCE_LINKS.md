# Official technical references checked 2026-11-05

## Model Context Protocol Python SDK

- Official SDK repository and releases: https://github.com/modelcontextprotocol/python-sdk
- Current Python SDK docs: https://py.sdk.modelcontextprotocol.io/
- Running an MCP server: https://py.sdk.modelcontextprotocol.io/run/
- MCP authorization: https://py.sdk.modelcontextprotocol.io/run/authorization/
- Client transports: https://py.sdk.modelcontextprotocol.io/client/transports/
- v1 maintenance documentation: https://py.sdk.modelcontextprotocol.io/v1/
- Migration guide: https://py.sdk.modelcontextprotocol.io/migration/

As checked 2026-11-05, the repository release page listed v2.3.0 as the latest release and v2 as current stable; v1 is maintenance-only. v2 requires Python 3.11+. Verify the release again before pinning dependencies because SDKs change.

Important SDK changes: `FastMCP` was replaced by `MCPServer` in v2; transport parameters moved to `run()` or app methods. Streamable HTTP is the recommended transport for deployed servers; SSE is the older transport.

## Google Agent Development Kit (optional demo agent)

- ADK MCP tools overview: https://google.github.io/adk-docs/tools-custom/mcp-tools/
- ADK Python package: https://pypi.org/project/google-adk/

Only add ADK after the MCP gateway itself works. A simple official MCP client is enough for the first protocol test.

## Google Antigravity

- Plans and quotas: https://antigravity.google/docs/plans

The user's last screenshot showed 100% weekly limit remaining for Gemini models and 100% for Claude/GPT models. The percentage is a weekly quota indicator, not a token balance or guaranteed number of prompts. Antigravity states that limits are workload-based and may change.

## Render (optional competition sponsor track)

- Render Workflows: https://render.com/docs/workflows
- Render persistent disks: https://render.com/docs/disks
- Render Postgres: https://render.com/docs/databases

Use Render Workflows only after the core gateway works. Organizer-provided requirement says Render Workflows must be used for the Best Use of Render prize track.

## Competition organizer requirements supplied by user

- ElevenLabs participant coupon via the Celestia Discord redemption process.
- Render participant credit claim link and documentation.
- Best Use of Render track requires Render Workflows.
- Organizers requested project details, winner email, demo video, Render URL, GitHub ID and Craftora submission.

These are user-provided organizer messages, not independently re-verified here.
