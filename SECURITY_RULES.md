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

## Authentication abuse controls

- Validate MCP endpoint URLs before attaching bearer credentials. Permit plain HTTP only for canonical loopback hosts; remote endpoints require HTTPS.
- Apply a bounded per-process sliding-window limit before writing authentication-failure audit rows. Key it only by the immediate transport peer; do not trust forwarded-IP headers unless an explicitly trusted proxy design is configured.
- Bound the dedicated authentication-failure table by retention count without deleting policy or execution audit history. Store only a fixed failure category and timestamp.
- The in-process limiter does not stop distributed attacks and may see all users as one peer behind a reverse proxy. Public deployments require upstream ingress rate limiting and an explicit proxy trust configuration.
- The dashboard must take its gateway origin from `VITE_AGENTGUARD_API_ORIGIN`, not user-entered data. It must reject noncanonical/insecure configuration and clear privileged state after HTTP 401 or 403.
