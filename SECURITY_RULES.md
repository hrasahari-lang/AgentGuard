# AgentGuard — Security Rules and Invariants

These rules are mandatory for the MVP. A feature is not complete if it violates one of them.

## Identity and authentication

1. Never trust `agent_id`, `role`, `user_id` or permissions supplied as ordinary tool arguments.
2. Authenticate at the HTTP/MCP transport boundary before any tool handler runs.
3. Resolve agent identity from verified credentials and create a trusted server-side request context.
4. Store only cryptographic hashes of random agent tokens; show raw tokens once at issuance.
5. Support revocation / inactive agent status.
6. Use constant-time comparison where custom token-hash verification is implemented.
7. Do not log bearer tokens or secrets.
8. Do not allow ordinary code paths or request payloads to construct trusted principals. Trusted contexts are issued only from an active credential verification result; tests must use an explicit credential-backed fixture.
9. Persist authentication failures as fixed reason categories only. Never include bearer values, Authorization headers, raw bodies, or tokens in failure rows or fallback logs. Deny the request if authentication auditing fails.

## Authorization

10. Check exact tool + operation + resource scope.
11. Enforce scope in the actual protected-resource query or API operation, not only in a pre-check.
12. Missing, unknown, conflicting or unavailable policy defaults to DENY.
13. A hard permission violation remains DENY; risk scores cannot override it.
14. LLM outputs, prompts, tool descriptions and retrieved documents cannot change policy or approve actions.

## Execution and credentials

15. Agents never receive direct protected database connection strings or master API tokens.
16. Only the AgentGuard backend executor holds protected resource credentials.
17. A protected tool executes only after an ALLOW decision or valid human approval followed by revalidation.
18. `REQUIRE_APPROVAL` must not execute the tool.
19. A DENY must not invoke the protected tool.
20. Use parameterized database operations and validate arguments against schemas and business rules.
21. Bind a stable request ID to the authenticated agent and canonical request hash. Reject duplicate or conflicting replays without re-execution. Every future mutating tool must require a caller-supplied stable idempotency key.
22. For the MVP, do not expose shell, arbitrary SQL or generic HTTP request tools to agents.

## Audit

23. Record every attempt, including sanitized authentication failure categories and policy denials.
24. Separate policy decision from execution status.
25. Record execution start and success/failure separately. Mark outcome-audit failure when possible; otherwise leave the event in STARTED/unknown state and prevent replay.
26. Redact secrets and sensitive data from logs; store sanitized summaries or hashes.
27. If the audit write needed to establish the authorization decision or execution start fails, fail closed before the resource operation.
28. Do not call ordinary database logs “non-repudiable,” “immutable” or “tamper-proof.” Use “persistent audit trail”; describe tamper-evidence only if a verified integrity mechanism is implemented.

## Risk

27. Use deterministic, explainable risk rules for the first release.
28. Display the reason/rule behind a risk result.
29. Risk score is not authorization. A low-risk unauthorized action remains denied.
30. Label all scores as prototype policy scores, not validated predictions.

## Demo proof

31. Denied and approval-pending requests must not increment the protected-resource invocation counter.
32. An allowed request increments invocation-started immediately before the protected resource call.
33. If an allowed call reaches the resource but fails, record invocation-started but not execution-succeeded.
34. The counter test must instrument the actual repository/resource call, not a UI-only number.
35. Show one central policy edit changing the next request's outcome without rebuilding the agent.
36. Store only SHA-256 hashes of randomly generated gateway credentials; verify credentials before MCP parsing and support revocation.
37. Derive trusted identity only from the active credential record; never accept identity or role from tool arguments.
38. Persist the policy decision before an allowed CRM side effect. If this audit write fails, do not execute the CRM operation.
39. Keep decision and execution status separate in persistent audit records; do not persist raw request values or credential material.

## Known boundary

AgentGuard only governs resources and tool operations routed through its enforcement boundary. Any direct credential or network path around the gateway is a bypass and must be removed or separately governed before claiming protection for that resource.

The Agent playground must accept a separate demo-agent bearer token. Keep it masked and in component memory only; never use localStorage, sessionStorage, VITE variables, or hardcoded agent credentials. Send it only to the configured same-origin /mcp endpoint with the official MCP client, and reject redirects.

Never pass the admin bearer credential to the MCP client or the demo-agent token to admin APIs. The only bridge between tool execution and admin views is a callback that refreshes overview and audit data after the MCP operation.

CORS must keep exact configured origins and explicitly allow only the browser headers required by MCP Streamable HTTP; protocol header support must not add wildcard origins.

## Authentication abuse controls

- Validate demo MCP endpoints before constructing the bearer-bearing client. Plain HTTP is allowed only for literal loopback IPs or `localhost` that resolves only to loopback. Remote HTTPS requires an exact hostname in `AGENTGUARD_TRUSTED_MCP_HOSTS`, and every DNS answer must be globally routable. Private, loopback, link-local, multicast, unspecified, reserved and IPv4-mapped non-public destinations are rejected without private-host exceptions.
- Retain the validated DNS addresses and dial one of them as a literal IP for each MCP client connection. Preserve the configured hostname in the HTTP `Host` header and TLS `sni_hostname`; use the default certificate verification context. Set `trust_env=False` and do not use an ambient proxy that may resolve the original hostname independently. The transport must reject requests outside the configured scheme, hostname and port before sending them.
- The pinned MCP SDK v2 permits only same-origin redirects and the shared transport enforces the configured origin on every send. Keep the exact SDK version pinned and regression-tested.
- Apply a bounded per-process sliding-window request limit before credential lookup. It counts every request, including valid credentials, so a credential cannot bypass the lookup budget. The default is 300 requests per socket peer per 60 seconds (`AGENTGUARD_AUTH_REQUEST_LIMIT`). Only after this independent early limit is passed does the middleware parse and verify the bearer token.
- Separately cap sanitized authentication-failure audit writes at 20 per peer per window. Once that audit cap is reached, requests still return 401; only the early all-request limit returns 429 before credential lookup.
- Use only the immediate transport peer; do not trust forwarded-IP headers. The bounded bucket table never evicts an active peer: new peers share one overflow bucket until expired buckets can be reclaimed. This prevents peer rotation from resetting an active bucket but can make excess peers share throttling.
- Bound the dedicated authentication-failure table by retention count without deleting policy or execution audit history. Store only a fixed failure category and timestamp.
- Application limiters are process-local. Behind a reverse proxy with proxy-header rewriting disabled, many users may share the proxy's socket identity; multiple workers or instances do not share counts. Public deployments require upstream ingress rate limiting. If client-IP forwarding is enabled, trust only known proxy addresses and require that proxy to overwrite client-supplied forwarding headers; never trust arbitrary `X-Forwarded-For` values.
- The dashboard must take its origin from `VITE_AGENTGUARD_API_ORIGIN`, not browser input. Development may use loopback HTTP. Production must use HTTPS on port 443 and a hostname listed in `VITE_AGENTGUARD_ALLOWED_API_HOSTS`. Missing or malformed production allowlists fail closed. Any failed dashboard request clears the token, connection and privileged data from component state.
- The only unauthenticated gateway route is `GET /healthz`; it returns a static status with no customer or credential data. All admin APIs and MCP routes remain behind bearer authentication.
- Configure backend CORS only with exact canonical origins in `AGENTGUARD_CORS_ORIGINS`; reject wildcard and path-bearing origins. Production must list only the dashboard's HTTPS origin.
- Keep the MCP SDK's DNS-rebinding protection enabled. Allow only local loopback development Host patterns and exact remote service hostnames from `AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS`; align accepted MCP Origin values with the exact CORS origin list. Never use a wildcard Host/Origin rule to fix a deployment mismatch.
- Hosted bootstrap must configure distinct, high-entropy admin and demo-agent tokens together. Read them only from environment variables, persist only SHA-256 hashes, never log or print their values, and rotate the prior active token when an environment value changes.
