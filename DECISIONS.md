# AgentGuard — Locked Decisions

These decisions are the current baseline. Reopen them only when a concrete technical blocker or test result justifies it.

1. **Product identity:** BYOA governance gateway, not an agent-builder platform.
2. **Universal vision:** Long-term objective; initial honest claim is compatible MCP agents routed through AgentGuard.
3. **First integration:** MCP Streamable HTTP. Do not start a new implementation on legacy SSE.
4. **SDK:** Current official MCP Python SDK v2 is stable. Release page showed v2.3.0 as latest on 2026-11-05; v1 is maintenance-only. Verify package version before pinning and use v2 APIs. Do not copy `FastMCP` v1 examples blindly; v2 names the server `MCPServer` and moved transport options.
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

## User environment and preferences

- User is working on Windows 11.
- Current approved Antigravity project folder: `C:\Users\nunna\Desktop\GURDAI1`.
- Antigravity permission preset: Auto (Preview).
- Plan Review Policy: Always Proceed.
- File read/write rules are scoped to the GURDAI1 folder.
- User wants free tools and quota-aware, token-efficient development.
- User's latest Antigravity Models & Usage screenshot showed 100% weekly limit remaining for Gemini models and 100% for Claude/GPT models at the time of the screenshot. This is a quota percentage, not a token count or guarantee of unlimited use.
