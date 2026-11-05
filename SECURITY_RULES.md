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

## Authorization

8. Check exact tool + operation + resource scope.
9. Enforce scope in the actual protected-resource query or API operation, not only in a pre-check.
10. Missing, unknown, conflicting or unavailable policy defaults to DENY.
11. A hard permission violation remains DENY; risk scores cannot override it.
12. LLM outputs, prompts, tool descriptions and retrieved documents cannot change policy or approve actions.

## Execution and credentials

13. Agents never receive direct protected database connection strings or master API tokens.
14. Only the AgentGuard backend executor holds protected resource credentials.
15. A protected tool executes only after an ALLOW decision or valid human approval followed by revalidation.
16. `REQUIRE_APPROVAL` must not execute the tool.
17. A DENY must not invoke the protected tool.
18. Use parameterized database operations and validate arguments against schemas and business rules.
19. Protect against duplicate calls and approval replay using unique request IDs / idempotency keys.
20. For the MVP, do not expose shell, arbitrary SQL or generic HTTP request tools to agents.

## Audit

21. Record every attempt, including authentication failures and denials where possible.
22. Separate policy decision from execution status.
23. Record execution start and success/failure separately.
24. Redact secrets and sensitive data from logs; store sanitized summaries or hashes.
25. If the audit write needed to establish the authorization decision fails, fail closed before executing the resource operation.
26. Do not call ordinary database logs “non-repudiable” or “tamper-proof.” Use “persistent audit trail”; describe tamper-evidence only if a verified integrity mechanism is implemented.

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
