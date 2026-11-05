# AgentGuard — Project Specification

**Competition:** iQOO Hackathon 2026  
**Category:** Productivity  
**Product direction:** Bring Your Own AI Agent (BYOA) governance gateway  
**Status:** Hackathon MVP specification; implementation not yet verified on the user's Windows machine.

## 1. Product in one sentence

AgentGuard is a centralized governance gateway that lets organizations connect existing compatible AI agents and enforce identity, permissions, risk rules, controlled tool execution and auditability over the agents' access to protected resources.

## 2. Product vision

Users should not have to recreate their agents inside AgentGuard. They should be able to connect an independently built agent through a supported integration, register its identity and govern its tool access centrally.

An agent continues to reason and perform its original tasks. AgentGuard governs protected tool calls that are routed through its enforcement gateway.

**Core principle:** Agents perform the work. AgentGuard controls access to the work.

## 3. Important scope truth

“Universal agent governance” is the long-term vision, not a claim that any arbitrary agent can be controlled by pasting an LLM API key.

An API key for a model provider does not reveal or intercept all actions executed by an agent. An agent may use direct API calls, local files, shell commands, databases or browser tools without involving the LLM provider on each action.

### Initial supported integration

- First integration: MCP over Streamable HTTP.
- The connected agent must be configured to use AgentGuard as the MCP server for the protected tools.
- Protected credentials stay on the AgentGuard backend.
- The initial prototype governs only actions routed through AgentGuard.

### Later integrations

- HTTP/API reverse proxy for compatible agents and configurable endpoints.
- Framework adapters for agents that need a small integration layer.
- Local runtime / endpoint enforcement as a future research direction.

Do not claim that the MVP automatically governs tools or resources accessed through bypass routes.

## 4. Core users

- Organization administrator: registers agents, configures policies, reviews approvals and audit events.
- Agent owner/developer: connects an existing agent to the gateway.
- Employee/requester: initiates work through an existing agent.
- Connected agent: authenticates and requests access to governed tools.

## 5. Six-stage enforcement pipeline

1. **Identify:** authenticate the calling agent from verified request credentials. Do not trust an `agent_id` supplied as a tool argument.
2. **Authorize:** check the agent's role and permissions for the exact tool, operation and resource scope. Consider the requesting user when available.
3. **Analyze:** apply explainable deterministic constraints using operation, data sensitivity, request scope, record count and context.
4. **Decide:** return exactly one of `ALLOW`, `REQUIRE_APPROVAL` or `DENY`.
5. **Execute:** call the protected tool only after an `ALLOW`, or after a valid human approval followed by revalidation.
6. **Audit:** record the attempt, decision, execution start and outcome.

## 6. MVP use case

Use synthetic customer data in a protected CRM database. No real customer data or secrets.

Initial tools:

- `search_customer_records(query, limit)` — search a bounded set of synthetic customer records.
- `get_customer(customer_id)` — retrieve one record, subject to scope policy.
- `export_customer_records(format)` — a registered sensitive operation used to demonstrate deny or approval. Its handler must route through the same policy engine and must not touch the CRM when denied or pending approval.

Initial policy examples (configurable server-side):

- A sales agent can search assigned customers within an allowed record limit.
- A sales agent cannot export all customer records.
- A bulk request above a configured threshold requires approval.
- Unknown agent, unknown tool or missing policy defaults to deny.

## 7. Required MVP capabilities

- Agent registry and revocable agent credential.
- Secure token verification; store only token hashes, not raw tokens.
- MCP Streamable HTTP gateway.
- Tool registry and input validation.
- Server-side RBAC and resource-scope checks.
- Deterministic, explainable risk rules.
- `ALLOW`, `REQUIRE_APPROVAL`, `DENY` policy outcomes.
- Protected CRM execution using backend-held credentials.
- Real invocation counter proving denied requests never reach the protected resource.
- Persistent audit events that distinguish decision from execution result.
- Dynamic policy change affecting the next request without changing/rebuilding the agent.
- One independently implemented MCP-compatible agent connected as a client.

## 8. Stretch goals, only after the MVP passes

- Human approval UI and one-time approval bound to exact request arguments.
- Second independent agent framework as a compatibility proof.
- Tamper-evident audit hash chain.
- Admin dashboard and real-time monitoring.
- Render deployment and Render Workflows integration if pursuing the sponsor prize track.
- HTTP/API gateway.

## 9. Explicit non-goals for the overnight MVP

- Automatic discovery of every agent on a network.
- Controlling arbitrary locally installed software without an integration or endpoint runtime.
- Full browser, operating-system or shell interception.
- Advanced ML risk prediction without validated data.
- Production enterprise SSO, multi-region HA, compliance certification or a claim of production readiness.
- Fake dashboard metrics or simulated security events presented as real.

## 10. Success definition

The MVP is credible when a real external MCP-compatible agent can:

1. connect to AgentGuard;
2. discover a permitted tool;
3. successfully invoke an authorized operation against the synthetic CRM;
4. attempt a registered restricted operation;
5. receive a denial from AgentGuard before the protected tool is called;
6. produce a persistent audit event;
7. observe a central policy update on its next request without modifying the agent.

The protected resource invocation counter must remain unchanged for denied and approval-pending requests.

## 11. Truthful positioning

Use this description in the hackathon submission:

“AgentGuard is a BYOA governance gateway for compatible AI agents. Its initial implementation uses an MCP Streamable HTTP gateway to enforce server-side policies over protected tool calls, with agent authentication, deterministic authorization, controlled execution and audit evidence.”

Do not claim universal interception or production-grade protection beyond the implemented enforcement boundary.
