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

The gateway uses the official MCP Python SDK v2 Streamable HTTP app behind an ASGI bearer-authentication middleware. Every admin API and MCP request is authenticated; the sole exception is `GET /healthz`, which returns only a static liveness status. The initial hackathon implementation uses a local credential registry as a constrained prototype, not OAuth or enterprise SSO; credentials can be provisioned by a trusted CLI or paired environment bootstrap, and only SHA-256 token hashes are stored. Remote clients must be configured with a bearer token out of band. Do not describe this as an OAuth authorization server.

`AgentAuthenticationMiddleware` verifies the credential against the registry using constant-time hash comparison, then derives `TrustedAgentContext` from the stored `agent_id` and admin flag. `AgentPrincipal` and `TrustedAgentContext` constructors reject ordinary construction; the context is created through the verified principal path. Unit tests use an explicit fixture that issues and verifies an isolated credential. A request-scoped `ContextVar` carries the context to handlers. Tool schemas contain no identity or role fields. When both `AGENTGUARD_BOOTSTRAP_ADMIN_TOKEN` and `AGENTGUARD_BOOTSTRAP_DEMO_AGENT_TOKEN` are set, startup idempotently registers `agent_admin` and `agent_sales_1`; environment values are never returned or logged, and only SHA-256 hashes are stored. Changing either environment token rotates that identity's prior active token. A token revoked in SQLite remains revoked after restart until its environment value is changed. Otherwise a credential can be provisioned by the trusted CLI and displayed once.

Authentication requests pass a bounded peer request limiter before header parsing or credential-registry lookup. Its default is 300 requests per peer per 60 seconds and it counts valid and invalid credentials alike, so valid tokens do not bypass lookup protection. Requests beyond this early budget fail with HTTP 429 without a registry query. Admitted authentication failures are persisted separately as fixed reason categories only: missing credential, malformed bearer, invalid token, revoked credential, duplicate Authorization header, or credential-registry failure. No header, token, source IP, or request body is persisted. If the audit write fails, authentication still denies the request; only a fixed category is emitted through the application logger.

Authentication-failure audit writes have a second bounded per-process sliding-window cap of 20 failures per peer per 60 seconds. The configured peer table has at most 4,096 buckets; it does not evict active peer buckets. If capacity is full, new peers share a single overflow bucket until stale buckets can be reclaimed. The provided Uvicorn launcher disables proxy-header rewriting and the middleware ignores all forwarded-IP headers. Audit retention keeps at most 10,000 authentication-failure rows and prunes only that dedicated table. These controls are local to one process: behind a reverse proxy, callers can share the proxy socket identity, and separate workers/instances do not share counts. Public deployment requires upstream ingress rate limiting. Any trusted forwarding configuration must name only known proxy addresses and require those proxies to overwrite untrusted client-supplied forwarding headers.

## MCP client endpoint trust

The two demo MCP clients require remote HTTPS hostnames to appear in the exact `AGENTGUARD_TRUSTED_MCP_HOSTS` allowlist before creating a bearer-bearing client. Every DNS answer must be globally routable; private, loopback, link-local, multicast, unspecified, reserved and IPv4-mapped non-public addresses are rejected. Plain HTTP remains available for literal loopback IPs and `localhost` only when its DNS answers are loopback.

The resolver retains the approved address set and the shared `PinnedAddressTransport` sends to a literal IP from that set. It leaves the configured hostname in the HTTP `Host` header and `sni_hostname` extension, so TLS SNI and certificate hostname validation continue to use the approved DNS name. Ambient proxy settings are disabled to avoid a second hostname resolution by a proxy. The transport rejects requests with any other scheme, hostname or port. The pinned MCP v2 SDK permits only same-origin redirects; cross-origin redirect attempts are refused before the bearer can be sent to the redirect target.

This closes the DNS time-of-check/time-of-use window in the bundled demo clients, subject to the assumptions that the installed, pinned `httpx2`/`httpcore2` versions continue to honor the tested `sni_hostname` extension and that no alternate network transport is substituted. Deployment egress controls remain defense in depth, especially for public-routed addresses that an infrastructure layer may route unusually. No deployment network policy is provisioned by this local prototype.

## Dashboard origin boundary

Development builds may use loopback HTTP. Production builds require HTTPS on the standard port and an exact DNS hostname in `VITE_AGENTGUARD_ALLOWED_API_HOSTS`; `VITE_AGENTGUARD_API_ORIGIN` must match one of those names. Missing or malformed allowlists fail closed. Every dashboard request goes through the shared same-origin fetch helper with redirects disabled. Any request failure clears the in-memory admin token, connection and privileged dashboard data.

The MCP SDK's in-memory client and stdio transport do not exercise this HTTP middleware. Gateway security tests start a local ASGI server and use the SDK's Streamable HTTP client with bearer headers.

Backend CORS accepts exact canonical origins from `AGENTGUARD_CORS_ORIGINS`; an unset value retains only the localhost Vite development origins. Wildcards, paths, and non-loopback HTTP origins are rejected. The Render demo must configure only `https://agent-guard-duo-x.vercel.app`.

## 5. Tool execution design

- Expose tools through the AgentGuard MCP server.
- Every tool handler invokes a shared enforcement service.
- Do not duplicate policy logic in individual tools.
- Protected CRM access happens only in a controlled executor module.
- Use parameterized SQL / ORM queries.
- Enforce resource scope in the actual query, not only in a policy pre-check.
- Register sensitive tools even when policy denies them; otherwise a client-side unknown-tool error would not prove AgentGuard denied a known tool call.
- Current registered tools are `search_customer_records`, `get_customer`, and `export_customer_records`; all execute only after an `ALLOW` and a persisted audit decision.

## 6. Audit lifecycle

Audit records distinguish:

- request received;
- authentication result;
- policy decision;
- approval state;
- execution started;
- execution succeeded, failed, or has an ambiguous outcome because its outcome audit write failed.

For an allowed request, the database records `DECISION_RECORDED`, then an atomic transition to `STARTED` before invoking the resource, followed by `SUCCEEDED` or `FAILED`. If the outcome write fails, a best-effort marker records `OUTCOME_AUDIT_FAILED`; if that write also fails, `STARTED` remains as an explicit unknown outcome and the caller is told not to retry with a new request ID. A denial or approval-pending request is persisted without touching CRM. Audit data includes a digest of request identifiers and request content, never raw arguments or credentials. If the decision or start write fails, do not execute.

Current tools accept an optional stable `request_id`; its digest is scoped by authenticated agent and bound to a canonical request hash. A repeated key is not re-executed, and reuse with different content is rejected. Current tools are read-only. Any future mutating tool must require a caller-supplied stable idempotency key; an automatically generated key cannot deduplicate a client retry across calls.

Authentication failure rows are sanitized reason categories only. The ordinary SQLite audit remains mutable and is not tamper-evident, immutable, or non-repudiable.

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

## Browser Agent Playground

The dashboard's Agent Playground is a browser MCP client, not a second execution path. It connects to the already-configured gateway origin at /mcp using the official TypeScript MCP SDK v2 Streamable HTTP transport. The browser performs the MCP handshake, discovers tools with tools/list, and sends tool calls with the separately entered demo-agent bearer credential. Redirects are rejected.

The admin credential remains scoped to the control-plane APIs in the dashboard component. The demo-agent credential is masked, kept in the Agent Playground component and transport memory only, and cleared on disconnect or when leaving the page. It is never compiled into a Vite variable or sent to an admin API. All protected reads and export attempts still pass through gateway authentication, policy evaluation, controlled execution and audit.

After each tool attempt the dashboard reloads its overview and audit APIs with the admin session. The client generates a request ID, the gateway persists only its digest, and the frontend correlates that digest with the refreshed audit result to display the recorded decision and execution status when present. Tool responses and errors are displayed from the MCP result; the page provides no policy editor or approval action.

## 11. Current MCP SDK decision

As checked on 2026-11-06, the official Python MCP SDK v2 release page lists v2.3.0 as latest. The project pins `mcp==2.3.0`. The v2 API has breaking changes: `FastMCP` becomes `MCPServer`, and transport options move to `run()` / app methods. The gateway uses `MCPServer` and `streamable_http_app()`; it does not copy v1 `FastMCP` or SSE examples.

Use Streamable HTTP for gateway work. SSE is the older transport and should not be selected for a new implementation. The local prototype binds to `127.0.0.1`; public-host transport security and a real OAuth provider remain deployment prerequisites.
