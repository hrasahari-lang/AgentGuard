# AgentGuard — System Architecture

## 1. Architectural split

### Control plane (administrative)

Owns configuration and visibility:

- Agent registration, credential rotation and revocation.
- Tool registry and tool metadata.
- Policy and permission management.
- Approval queue (after core enforcement works).
- Audit search and administrative views.

The React frontend talks to an Admin API. It must not connect directly to the database.

### Enforcement plane (runtime)

Owns every protected operation:

- MCP Streamable HTTP endpoint.
- Authentication and trusted request context.
- Tool argument/schema validation.
- Authorization and resource scope checks.
- Deterministic risk rules.
- Decision engine.
- Backend-side tool executor with protected credentials.
- Invocation counter and audit lifecycle.

## 2. Request flow

```text
Existing compatible AI agent
         |
         | MCP Streamable HTTP request + bearer credential
         v
AgentGuard MCP gateway
         |
         v
1. Authenticate request at HTTP/MCP boundary
         |
         v
2. Resolve trusted agent identity server-side
         |
         v
3. Validate tool name, schema and arguments
         |
         v
4. Authorize role + operation + resource scope
         |
         v
5. Apply deterministic risk constraints
         |
         v
6. Policy decision
    | ALLOW             | REQUIRE_APPROVAL       | DENY
    v                   v                        v
Execute protected       Persist pending          Do not call protected
CRM tool with           request; stop            tool; persist denial
backend credential      execution               audit event
    |                   |                        |
    v                   v                        v
Record execution        Approved later?         Return policy error
result and audit        Revalidate exact action  to caller
    |
    v
Return result to agent
```

## 3. Credential boundary

- Agent receives only a credential to call AgentGuard.
- Agent does not receive CRM database credentials, GitHub PATs or master resource tokens.
- AgentGuard stores protected credentials server-side in environment variables for local demo and a secret manager for later production deployment.
- A tool argument such as `agent_id="admin"` must never determine identity.
- Identity comes from a verified bearer token / authenticated transport context.

## 4. Authentication approach

For deployed MCP over Streamable HTTP, follow the current MCP authorization specification and official Python SDK authorization guidance. The MCP server acts as a resource server and verifies bearer tokens. The authorization server/token issuance story must be explicit.

For a constrained hackathon prototype, a small registry-backed bearer-token verifier can be used if it is integrated correctly with the MCP HTTP boundary and clearly documented as prototype authentication, not full enterprise OAuth/SSO. Never place the token in tool arguments.

The MCP SDK's in-memory client and stdio transport do not exercise HTTP bearer-token authentication. Security tests for authentication must use the HTTP transport or separately test the verifier boundary.

## 5. Tool execution design

- Expose tools through the AgentGuard MCP server.
- Every tool handler invokes a shared enforcement service.
- Do not duplicate policy logic in individual tools.
- Protected CRM access happens only in a controlled executor module.
- Use parameterized SQL / ORM queries.
- Enforce resource scope in the actual query, not only in a policy pre-check.
- Register sensitive tools even when policy denies them; otherwise a client-side unknown-tool error would not prove AgentGuard denied a known tool call.

## 6. Audit lifecycle

Audit records should distinguish:

- request received;
- authentication result;
- policy decision;
- approval state;
- execution started;
- execution succeeded or failed.

At minimum, persist the decision before executing a protected side effect. On completion, append or update a correlated execution outcome. If the audit write needed to establish the decision fails, fail closed before execution.

For the MVP, an append-only application API is acceptable, but do not claim tamper-proof or non-repudiable logging unless a suitable integrity and access-control design is implemented. A hash chain is an optional tamper-evidence improvement, not a substitute for secure access control.

## 7. Invocation counter semantics

Use separate counters or fields:

- `resource_invocation_started`: increment immediately before the protected CRM operation is invoked.
- `resource_execution_succeeded`: increment only after successful completion.

A denied or approval-pending request increments neither counter. An authorized request that reaches the resource but fails during execution increments the started counter but not the succeeded counter.

Use a dedicated test resource or instrumented repository method so the test measures actual calls, not a dashboard number.

## 8. Policy model

A policy should at least identify:

- role or agent identity;
- tool name;
- operation;
- resource scope;
- decision (`ALLOW`, `REQUIRE_APPROVAL`, `DENY`);
- constraints such as maximum result count;
- enabled state and policy version.

Missing or ambiguous rules default to `DENY`. Hard authorization failures must not be converted into approval merely because a numeric risk score is low.

Risk is separate from authorization. Use transparent rules and explain which rule caused the decision.

## 9. Human approval

Approval is not “return a pending string.” It is a persisted state machine:

`PENDING -> APPROVED | REJECTED | EXPIRED`

If approved, bind approval to agent identity, user identity where available, tool, canonical argument hash, resource, policy version and expiry. Revalidate authorization at resume time and enforce one-time/idempotent execution. The agent cannot approve itself.

## 10. Proposed project structure

```text
AgentGuard/
├── AGENTS.md
├── PROJECT_SPEC.md
├── SYSTEM_ARCHITECTURE.md
├── SECURITY_RULES.md
├── IMPLEMENTATION_ROADMAP.md
├── CURRENT_STATE.md
├── DECISIONS.md
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── gateway/
│   │   │   ├── mcp_server.py
│   │   │   ├── request_context.py
│   │   │   └── executor.py
│   │   ├── security/
│   │   │   ├── auth.py
│   │   │   ├── permissions.py
│   │   │   ├── policy_engine.py
│   │   │   └── risk_engine.py
│   │   ├── tools/
│   │   │   └── crm_tools.py
│   │   ├── audit/
│   │   │   └── audit_service.py
│   │   └── approvals/
│   │       └── approval_service.py
│   └── requirements.txt
├── demo/
│   └── external_agent.py
├── tests/
│   ├── test_auth.py
│   ├── test_policy.py
│   ├── test_gateway.py
│   └── test_invocation_counter.py
├── frontend/                 # only after backend vertical slice works
└── source_material/
```

## 11. Current MCP SDK decision

As checked on 2026-11-05, the official Python MCP SDK v2 is the current stable line; the repository release page lists v2.3.0 as latest, while v1 is maintenance-only. The v2 API has breaking changes: `FastMCP` becomes `MCPServer`, and transport options move to `run()` / app methods. Do not copy older v1 snippets without adapting them. Pin a tested v2 version in the project after checking local Python compatibility.

Use Streamable HTTP for deployed gateway work. SSE is the older transport and should not be selected for a new implementation.
