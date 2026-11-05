# AgentGuard — Implementation Roadmap

## Build strategy

Use a thin vertical slice. Prove backend enforcement before spending time on the dashboard. Work in milestones and run tests after each one. Do not attempt universal integrations in the first release.

## Milestone 0 — Environment and workspace verification

**Tasks**
- Verify Python >= 3.11, `py`, pip, Node.js, npm and Git on the actual Windows workstation.
- Confirm the Antigravity workspace is `C:\Users\nunna\Desktop\GURDAI1`.
- Confirm read/write permission exists only for that workspace.
- Create a virtual environment; don't install packages until the chosen SDK/API plan is agreed.

**Pass criteria**
- Environment versions are recorded in `CURRENT_STATE.md`.
- No files outside the workspace are modified.

## Milestone 1 — Database and protected CRM

**Tasks**
- Create SQLite schema and synthetic customers.
- Create agents, policies, audit events, invocation counters; approval table may follow after core flow.
- Implement repository functions using parameterized SQL or SQLAlchemy.
- Enforce customer resource scope inside repository queries.

**Pass criteria**
- Seed data loads reproducibly.
- Authorized test query returns expected synthetic records.
- A direct repository test proves the invocation counter semantics.

## Milestone 2 — Policy engine (without MCP yet)

**Tasks**
- Define typed request context and tool request models.
- Implement identity-aware policy evaluation.
- Implement ALLOW / REQUIRE_APPROVAL / DENY.
- Add deterministic constraints and explanations.
- Default to DENY when no exact policy matches.

**Pass criteria**
- Unit tests cover allow, deny, approval, scope violations and missing policy.
- Tool arguments cannot spoof agent identity or role.

## Milestone 3 — MCP Streamable HTTP gateway

**Tasks**
- Use the current official MCP Python SDK v2 API, not stale v1 examples.
- Implement MCP Streamable HTTP server.
- Integrate bearer-token verification at the HTTP/MCP boundary.
- Pass the verified principal to shared enforcement services; never accept identity in tool arguments.
- Register permitted search and restricted export tools so AgentGuard itself can return the denial.

**Pass criteria**
- External MCP client discovers tools.
- Missing/invalid token is rejected before tool code executes.
- Valid token resolves to the expected agent identity.

## Milestone 4 — Controlled execution and audit

**Tasks**
- Route all protected operations through a single executor.
- Keep CRM credentials in backend process/environment only.
- Persist decision before resource side effect.
- Track resource invocation started and execution succeeded separately.
- Persist execution failure details without rolling back the already committed decision event.

**Pass criteria**
- Allowed request reaches CRM.
- Denied request does not reach CRM.
- Approval-pending request does not reach CRM.
- Audit event shows decision and execution outcome accurately.

## Milestone 5 — External agent integration

**Tasks**
- Connect one independently implemented MCP-compatible agent to the remote/local AgentGuard MCP endpoint.
- Prefer a minimal client using the official SDK first; add Google ADK or another framework once protocol-level connectivity works.
- Supply the AgentGuard token through secure client configuration, never inside prompts or tool arguments.

**Pass criteria**
- Agent lists AgentGuard tools and calls them.
- No AgentGuard CRM credentials are present in the agent environment.

## Milestone 6 — Dynamic policies and approvals

**Tasks**
- Add an admin API to change a policy.
- Make gateway evaluate current policy on each request or use a versioned cache invalidated on change.
- Add approval state machine only after ALLOW/DENY are proven.
- Bind approval to exact request hash, agent, tool, scope, policy version, expiration and one-time request ID.
- Revalidate immediately before execution.

**Pass criteria**
- Policy change affects next request without agent restart/rebuild.
- Expired/replayed/modified approvals fail.
- Only authorized human can approve.

## Milestone 7 — Admin UI and competition polish

**Tasks**
- Show agents, tools, policies, audit events, invocation counters and pending approvals from real backend data.
- Do not fabricate metrics.
- Add test/demo scripts and capture a reproducible demo.

**Pass criteria**
- Every UI metric can be traced to backend state.

## Milestone 8 — Render / sponsor track (conditional)

The organizer's message says Render Workflows are mandatory for the Best Use of Render prize. Only pursue after core security tests pass.

**Tasks**
- Verify current official Render Workflows API and SDK.
- Use a meaningful asynchronous lifecycle such as a human-approved sensitive operation, not a fake decorative workflow.
- Make execution idempotent because workflow retries/replays may occur.
- Use hosted persistent database storage (e.g. Render Postgres) rather than assuming the service filesystem is permanent.

**Pass criteria**
- A real Render Workflow run is visible and has a meaningful role in the operation.
- Duplicate/replayed workflow execution cannot repeat a sensitive side effect.

## Hackathon demonstration script

1. Show an independently implemented agent connected to AgentGuard.
2. Show tool discovery through MCP.
3. Call an authorized customer search and return synthetic CRM data.
4. Call a registered restricted export operation.
5. Show DENY and prove the CRM invocation counter did not increase.
6. Edit the policy centrally.
7. Repeat the request and show the updated decision without rebuilding the agent.
8. Show the actual audit records.
9. If approval exists, demonstrate pending -> approve -> revalidate -> execute exactly once.

## Time-box rule

Do not assume an 8-hour completion guarantee. If time is short, cut the second agent, elaborate UI, local runtime, advanced ML and Render integration (unless sponsor prize qualification is a firm requirement). Do not cut authentication, enforcement, the counter proof or audit evidence.
