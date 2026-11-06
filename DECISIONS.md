# AgentGuard — Locked Decisions

These decisions are the current baseline. Reopen them only when a concrete technical blocker or test result justifies it.

1. **Product identity:** BYOA governance gateway, not an agent-builder platform.
2. **Universal vision:** Long-term objective; initial honest claim is compatible MCP agents routed through AgentGuard.
3. **First integration:** MCP Streamable HTTP. Do not start a new implementation on legacy SSE.
4. **SDK:** Pin the official MCP Python SDK at `mcp==2.3.0` (verified against the official release page on 2026-11-06). Use v2 `MCPServer` and Streamable HTTP APIs; do not copy `FastMCP` v1 examples or select legacy SSE.
5. **Authentication:** Verified HTTP bearer token / authenticated principal. Never accept `agent_id` or `role` from tool arguments.
6. **Demo agents:** One independently implemented MCP-compatible agent first. A second framework is a stretch interoperability proof, not a core requirement.
7. **Protected data:** Synthetic SQLite CRM locally; PostgreSQL for hosted deployment if persistent multi-service state is needed.
8. **Policy:** Deterministic and explainable; explicit `ALLOW`, `REQUIRE_APPROVAL`, `DENY`; missing rule is deny.
9. **Risk:** Separate from authorization. Risk score cannot override a hard permission denial.
10. **Execution:** All protected resources are called through a backend-held credential; agent never receives protected credentials.
11. **Proof:** Actual invocation counter / instrumented repository proves denied calls never reach the protected resource.
12. **Audit language:** Say persistent audit trail unless tamper-evidence is actually implemented and tested. Do not claim non-repudiation by default.
13. **Frontend:** Build after the enforcement vertical slice. No invented dashboard metrics.
14. **Render:** Conditional milestone after core proof. Render Workflows are required only if pursuing the organizer's Best Use of Render prize track.
15. **Development:** Milestone-based, minimal diffs, tests after changes, Git commits after passing milestones.

16. **M2 final request validation:** Normalize only non-empty action/resource identifiers matching the bounded lowercase identifier grammar after case folding; malformed values and wildcard request identifiers fail closed. Policy condition keys and value types are validated when `PolicyRule` is created.
17. **M2 policy immutability:** Freeze target lists as tuples and recursively freeze condition mappings/sequences so a frozen dataclass cannot be altered through nested containers. Keep the existing copy-on-ingress/read boundary.
18. **M2 audit summaries:** `PolicyDecision.to_dict()` returns a deep copy of its summary. Sanitization removes sensitive-key fields and masks common inline credential assignments and bearer tokens; arbitrary unlabeled strings cannot be reliably classified as secrets.
19. **M3 prototype authentication:** Use opaque, randomly generated bearer credentials provisioned from a trusted local CLI, store only SHA-256 hashes, resolve hashes through the unique token-hash index and compare the returned hash in constant time, and support rotation/revocation. This registry middleware protects the HTTP/MCP boundary but is not an OAuth authorization server or enterprise SSO.
20. **M3 audit and concurrency:** Persist the policy decision before protected execution, record execution status separately, omit request values from the audit database, and protect dynamic policy registry reads/writes with a lock.
21. **MCP v2 HTTP dependency:** `httpx2` is intentional, not a typo: the official SDK v2 migration replaces `httpx`/`httpx-sse` with `httpx2`. Pin the directly imported MCP SDK, HTTP transport and Uvicorn dependencies, and lock the resolved Python dependency set in `requirements.txt`.
22. **Trusted identity boundary:** Normal `TrustedAgentContext` and `AgentPrincipal` constructors reject calls without internal authentication capabilities. Production contexts are derived only from verified active credentials. Tests create contexts by issuing and verifying isolated test credentials.
23. **Authentication failure audit:** Persist only a fixed category and timestamp for failed credentials. Authentication remains denied when the audit write fails; fallback logging emits the category only.
24. **Execution idempotency and ambiguity:** Bind optional stable request IDs to agent and canonical request hashes; hash request IDs before persistence; reject repeats and mismatches. Current tools are read-only. Any future mutating tool must require a stable caller-provided idempotency key. Record decision, start, completed outcome, and outcome-audit failure distinctly; an unmarkable outcome remains STARTED/unknown and cannot be replayed.
25. **Managed agent demo:** The minimal AgentGuard-managed task agent is an MCP client only. It obtains its bearer credential from the process environment, discovers the existing gateway tool, and sends all work through that gateway. It does not import the CRM repository or database. It prints a request ID before execution so ambiguous network outcomes can be checked against audit records.
26. **MCP client endpoint safety:** Both demo clients use one URL resolver and one pinned HTTP transport. HTTP is accepted only for literal loopback addresses or `localhost` that resolves only to loopback. Remote HTTPS requires an exact host in `AGENTGUARD_TRUSTED_MCP_HOSTS`; every DNS answer must be globally routable. The transport dials a retained literal IP while preserving the original Host header, TLS SNI and hostname certificate verification. No private destination exception is supported.
27. **Authentication request limits:** Apply a bounded per-peer request budget before credential lookup to every request, including valid credentials. Cap authentication-failure audit writes separately. Keep peer identity bound to the immediate socket and ignore forwarded headers. A full bucket map uses one shared overflow bucket instead of evicting active peers. Application limits are process-local and must be supplemented by upstream ingress limits in deployments.
28. **Dashboard gateway trust:** Compile the dashboard with `VITE_AGENTGUARD_API_ORIGIN`; production also requires exact approved DNS names in `VITE_AGENTGUARD_ALLOWED_API_HOSTS`, HTTPS and port 443. Development loopback HTTP remains supported. Keep the admin credential in component memory only, prevent redirects, and clear all privileged state after any failed request.
29. **MCP redirect protection:** Pin MCP Python SDK v2 and set `follow_redirects=False` on both demo bearer clients. The SDK's Streamable HTTP helper enforces same-origin redirect rules even if a supplied client enables generic redirects; the pinned transport also rejects any request outside the configured origin.
30. **DNS rebinding protection:** Validation returns immutable approved addresses that the shared transport uses as literal connection destinations, preventing a second DNS resolution of the configured hostname. TLS continues to use the configured hostname via the tested `sni_hostname` extension. Regression tests cover answer changes, actual TLS SNI, hostname verification, IPv4/IPv6 pinning and cross-origin redirects. Keep `httpx2`/`httpcore2` pinned and rerun these tests on upgrades; retain outbound egress controls as defense in depth.
31. **Hosted CORS and health check:** Configure browser origins through `AGENTGUARD_CORS_ORIGINS`, requiring exact canonical origins and rejecting wildcards. Expose only a static `GET /healthz` outside authentication; every admin API and MCP path stays behind the bearer middleware.
32. **Environment credential bootstrap:** When both bootstrap token variables are configured, startup idempotently registers the fixed admin and demo identities. Require distinct high-entropy URL-safe tokens, store only SHA-256 hashes, and rotate prior active credentials when the configured values change. A matching revoked credential stays revoked across restarts. Never print or log token values.

## User environment and preferences

- User is working on Windows 11.
- Current approved Antigravity project folder: `C:\Users\nunna\Desktop\GURDAI1`.
- Antigravity permission preset: Auto (Preview).
- Plan Review Policy: Always Proceed.
- File read/write rules are scoped to the GURDAI1 folder.
- User wants free tools and quota-aware, token-efficient development.
- User's latest Antigravity Models & Usage screenshot showed 100% weekly limit remaining for Gemini models and 100% for Claude/GPT models at the time of the screenshot. This is a quota percentage, not a token count or guarantee of unlimited use.
