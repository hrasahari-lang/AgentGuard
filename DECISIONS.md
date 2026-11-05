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
19. **M3 prototype authentication:** Use opaque, randomly generated bearer credentials provisioned from a trusted local CLI, store only SHA-256 hashes, compare hashes in constant time, and support rotation/revocation. This registry middleware protects the HTTP/MCP boundary but is not an OAuth authorization server or enterprise SSO.
20. **M3 audit and concurrency:** Persist the policy decision before protected execution, record execution status separately, omit request values from the audit database, and protect dynamic policy registry reads/writes with a lock.
21. **MCP v2 HTTP dependency:** `httpx2` is intentional, not a typo: the official SDK v2 migration replaces `httpx`/`httpx-sse` with `httpx2`. Pin the directly imported MCP SDK, HTTP transport and Uvicorn dependencies, and lock the resolved Python dependency set in `requirements.txt`.
22. **Trusted identity boundary:** Normal `TrustedAgentContext` and `AgentPrincipal` constructors reject calls without internal authentication capabilities. Production contexts are derived only from verified active credentials. Tests create contexts by issuing and verifying isolated test credentials.
23. **Authentication failure audit:** Persist only a fixed category and timestamp for failed credentials. Authentication remains denied when the audit write fails; fallback logging emits the category only.
24. **Execution idempotency and ambiguity:** Bind optional stable request IDs to agent and canonical request hashes; hash request IDs before persistence; reject repeats and mismatches. Current tools are read-only. Any future mutating tool must require a stable caller-provided idempotency key. Record decision, start, completed outcome, and outcome-audit failure distinctly; an unmarkable outcome remains STARTED/unknown and cannot be replayed.

## User environment and preferences

- User is working on Windows 11.
- Current approved Antigravity project folder: `C:\Users\nunna\Desktop\GURDAI1`.
- Antigravity permission preset: Auto (Preview).
- Plan Review Policy: Always Proceed.
- File read/write rules are scoped to the GURDAI1 folder.
- User wants free tools and quota-aware, token-efficient development.
- User's latest Antigravity Models & Usage screenshot showed 100% weekly limit remaining for Gemini models and 100% for Claude/GPT models at the time of the screenshot. This is a quota percentage, not a token count or guarantee of unlimited use.
