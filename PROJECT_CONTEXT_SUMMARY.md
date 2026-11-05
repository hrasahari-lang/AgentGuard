# AgentGuard — compact AI context summary

AgentGuard is a Bring Your Own AI Agent (BYOA) governance gateway for iQOO Hackathon 2026. Users connect existing compatible agents; they do not build agents inside AgentGuard. The MVP governs protected tool calls routed through an MCP Streamable HTTP gateway. It does not automatically control arbitrary agent actions or gain control merely from an LLM API key.

## Product pipeline

Identify -> Authorize -> Analyze -> Decide -> Execute -> Audit.

## Architecture

- Control plane: agent registry, tool registry, policies, approvals, audit visibility, admin API/UI.
- Enforcement plane: MCP gateway, HTTP bearer authentication, trusted request context, schema validation, RBAC/ABAC, deterministic risk rules, ALLOW/REQUIRE_APPROVAL/DENY, backend-side protected executor, audit.
- Initial protected resource: synthetic SQLite CRM.
- First integration: one existing MCP-compatible external agent. A second framework is optional after the first works.

## Non-negotiable security

- Never trust agent_id/role/user_id passed as tool arguments.
- Authenticate at the MCP HTTP boundary; derive identity from verified credentials.
- Store only hashes of random agent tokens.
- Agent never receives database or external-service master credentials.
- Missing/unknown policy -> DENY.
- Hard permission denial cannot be overridden by low risk.
- Denied and pending-approval operations must not reach the protected resource.
- Recheck exact approval binding and policy before executing an approved operation.
- Separate decision from execution outcome.
- Redact secrets and sensitive arguments from logs.
- If authorization/audit precondition cannot be established, fail closed.
- Only claim protection for actions routed through AgentGuard; bypass routes invalidate the claim.

## MVP tools

- `search_customer_records(query, limit)`
- `get_customer(customer_id)`
- `export_customer_records(format)` — registered for the policy demo but denied or approval-gated by policy.

## Core proof

1. One permitted tool call returns synthetic CRM data and increments resource invocation count.
2. One registered but denied tool call returns DENY, creates an audit event and leaves resource invocation count unchanged.
3. A central policy change affects the next call without rebuilding/restarting the external agent.

## Known flaws corrected from the initial sample

- Sample accepted caller-supplied agent_id: remove it; derive identity from authenticated request context.
- Sample did not validate tokens: add transport-level bearer verification.
- Sample declared a counter but did not increment it: instrument actual protected resource invocation.
- Sample rolled back on execution error after prior audit commit: design explicit audit lifecycle.
- Sample checked tool/role but not customer-level scope in the actual query: enforce scope in repository query.
- Sample returned a pending string without a true approval state: treat approval as a persisted workflow, add only after allow/deny works.
- Sample stored raw token: store hash only.

## Current technology guidance

As of 2026-11-05, official MCP Python SDK v2 is the current stable line, release page lists v2.3.0, and v1 is maintenance-only. v2 has breaking changes (`MCPServer` replaces `FastMCP`; transport options moved). Python 3.11+ is required. Use Streamable HTTP for new deployed integrations; do not start with legacy SSE. Verify current docs and exact APIs before coding.

## Current user workspace/state

- Windows workspace: `C:\Users\nunna\Desktop\GURDAI1`.
- Antigravity file read/write rules are scoped to this directory.
- Antigravity preset: Auto (Preview); Plan Review Policy: Always Proceed.
- Latest quota screenshot: 100% weekly remaining for Gemini and 100% for Claude/GPT at that screenshot time. This is percentage quota, not token count; no guarantee against later exhaustion.
- No project code has yet been implemented in that Windows workspace.
- Next task: open the pack in Antigravity, read `AGENTS.md` and `CURRENT_STATE.md`, run `ANTIGRAVITY_FIRST_PROMPT.md` to inspect the actual environment. Do not install packages or create the backend before reporting environment versions.

## Read next

Read `PROJECT_SPEC.md`, `SYSTEM_ARCHITECTURE.md`, `SECURITY_RULES.md`, `IMPLEMENTATION_ROADMAP.md`, `DECISIONS.md`, and `CURRENT_STATE.md`. Original pitch deck, framework and independent review are under `source_material/`.
