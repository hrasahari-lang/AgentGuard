# AgentGuard — Goals & Progress Tracker

**Master Milestone & Progress Tracker**  
**Hackathon Target:** iQOO Hackathon 2026 — BYOA AI Agent Governance Platform  
**Remote Repository:** `https://github.com/hrasahari-lang/AgentGuard.git`  
**Current Branch:** `main`  
**Last Updated:** 2026-11-06  

---

## 1. Hackathon Objective & Vision

Build AgentGuard into a fully functional, professionally designed, and publicly deployed BYOA (Bring Your Own Agent) AI Agent Governance Platform.
AgentGuard acts as a zero-trust governance gateway between compatible AI agents (connecting via Model Context Protocol / Streamable HTTP) and sensitive enterprise tools / data.

---

## 2. Milestone Progress Tracker

Progress is calculated strictly on **verified acceptance criteria**, supported by automated test suites and passing verification commands.

| Milestone | Description | Status | Verified Criteria Passed |
|---|---|---|---|
| **Milestone 0** | Environment & Workspace Verification | **COMPLETE** | Python 3.11, pip, Node.js, Git verified; workspace constrained to `C:\Users\nunna\Desktop\GURDAI1`; clean `.venv` created. |
| **Milestone 1** | Database & Protected Synthetic CRM | **COMPLETE** | SQLite schema, idempotent seeding, RFC 2606 safe domains, parameterized SQL queries, server-side resource scoping, atomic pre-committed invocation counters, WAL mode, 15s timeout, 11/11 unit tests passing. |
| **Milestone 2** | Deterministic Policy Engine (without MCP) | **FINAL SECURITY REMEDIATION VERIFIED** | Pure deterministic rule engine, explicit outcomes, trusted context requirement, deterministic precedence, default deny, no CRM execution during evaluation. Final remediation validates action/resource syntax and all condition schemas; recursively freezes rule targets/conditions; detaches serialized audit summaries; redacts labeled inline secrets; precise exception assertions. The suite had 45 tests at M2 finalization; subsequent security and deployment regressions bring the current total to 85 (`CURRENT_STATE.md`). |
| **Milestone 3** | MCP Streamable HTTP Gateway | **COMPLETE (local prototype; security remediation verified)** | Explicit pinned MCP v2 dependencies; pre-routing bearer validation; trusted contexts only from verified credential principals; categorized auth-failure audit; all admin endpoints tested by identity class. |
| **Milestone 4** | Controlled Execution & Audit Engine | **COMPLETE (local prototype; security remediation verified)** | Separate decision/start/completion phases; request-ID and hash-bound idempotency; ambiguous outcomes surfaced and replay blocked. Current full suite: 85 tests, including the preserved 45-test baseline. |
| **Milestone 5** | External Agent Integration | **COMPLETE (SDK demos)** | Separate official-SDK MCP client demonstrates ALLOW/DENY; minimal managed task agent discovers and invokes the governed search tool; subprocess regression proves request-ID replay does not repeat the protected operation. Broader agent framework integrations remain future work. |
| **Milestone 6** | Dynamic Policies & Human Approvals | **PENDING** | Admin policy API, one-time approval tokens, replay protection, cryptographic request hash binding, revalidation before execution. |
| **Milestone 7** | Enterprise Admin UI & Polish | **LOCAL MVP + AGENT PLAYGROUND VERIFIED** | Authenticated overview, agents, policies and audit views remain read-only. The new Agent Playground uses a separate in-memory demo-agent credential and the official MCP TypeScript client for real gateway tool discovery/calls. UI feature work remains minimal; hosted deployment verification is pending. |
| **Milestone 8** | Hosted Demo & Public Deployment | **DEPLOY CONFIGURATION IMPLEMENTED; PLAYGROUND DEPLOYMENT PENDING** | Exact CORS origin, MCP browser headers, health endpoint and hashed bootstrap credentials are implemented. After push, verify Vercel/Render deploy, persistent DB, hosted authenticated MCP outcomes and audit updates. Render Workflows remain optional unless pursuing that prize track. |

**Overall Progress:** M0–M5 complete for the local prototype; independent security remediation Stage 1, managed-agent Stage 2, final AG-01–AG-03 hardening, the live-demo configuration and the Agent Playground have local regression evidence. AG-01's bundled clients pin validated DNS addresses while preserving TLS hostname verification; AG-02 remains partial because application limits are process-local; AG-03's production origin and failure-clearing boundaries are fixed locally. M6 remains pending. The Agent Playground has not yet been tested against the hosted backend with a real demo token.

**Immediate next action:** publish the verified Agent Playground change, confirm frontend/backend deploy status, then test the hosted tool calls with the user-provisioned demo-agent token without exposing it. Verify audit updates and blocked-call invocation counts.

---

## 3. Milestone 1 Verified Acceptance Criteria

- [x] **Reproducible Schema & Data Seeding:**
  - `customers` and `resource_invocation_counter` tables created with parameterized initial state.
  - 7 synthetic customer records loaded across 3 agents using RFC 2606 `.example.com` domains.
  - Idempotent re-initialization confirmed (`init_db()` preserves data without duplicates).
- [x] **Zero SQL Injection Vulnerabilities:**
  - 100% parameterized queries using `?` placeholders across all repository functions.
- [x] **Server-Side Resource Scoping:**
  - Agent-specific filtering enforced inside SQL (`WHERE customer_id = ? AND assigned_agent_id = ?`).
- [x] **Strict Pre-Execution Validation:**
  - `isinstance(agent_context, TrustedAgentContext)` enforced on all protected methods.
- [x] **Persistent Invocation Counters:**
  - `total_invocations` committed immediately before running queries; persists through query failures.
- [x] **Database Concurrency & Reliability Hardening:**
  - WAL journal mode on file databases; 15-second busy timeout.
- [x] **Test Verification:**
  - 11 automated unit tests in `tests/test_crm_repository.py` passing in ~0.6s.

---

## 4. Milestone 2 Verified Acceptance Criteria

- [x] **Deterministic Outcomes:**
  - Explicit distinction between `ALLOW`, `REQUIRE_APPROVAL`, and `DENY`.
  - No LLM in authorization loop; zero fuzzy logic or unexplainable heuristics.
- [x] **Server-Side Identity Verification & Anti-Spoofing:**
  - Agent identity and administrative status derived strictly from `TrustedAgentContext`.
  - Tool arguments (e.g. `parameters={"agent_id": "admin", "is_admin": True}`) are completely ignored for authorization.
  - Missing or untrusted contexts fail closed to `DENY` with `CRITICAL` risk level.
- [x] **Deterministic Precedence Hierarchy:**
  1. Priority integer ascending (lower integer = higher precedence).
  2. Deny-overrides on collision: `DENY` > `REQUIRE_APPROVAL` > `ALLOW`.
  3. Specificity on collision: Specific agent > wildcard agent, Specific tool > wildcard tool.
  4. Lexical sort on `policy_id` as stable tie-breaker.
- [x] **Fail-Closed Default:**
  - Requests matching no policy return `DENY` with `policy_id=None` and explainable reason.
- [x] **Decoupled Architecture:**
  - Policy evaluation never touches the database or CRM counters (`test_no_protected_crm_execution_during_policy_evaluation` verifies counter remains 0).
- [x] **Audit-Ready Serialization & Recursive Secret Redaction:**
  - `PolicyDecision.to_dict()` outputs structured audit dictionaries with recursive parameter redaction.
  - Multi-level nested dictionaries, lists, and sensitive keyword variations (`password`, `secret`, `token`, `key`, `auth`, `credential`, `bearer`, `private`) are safely scrubbed.
  - Recursion depth bounded to 5 levels; oversized string parameters truncated.
- [x] **Security Review Hardening (M2 Findings Remediated):**
  - M2-H-01: `PolicyRule` is immutable (`@dataclass(frozen=True)`); engine stores and returns independent deep copies, preventing external state tampering.
  - M2-M-01: Resource wildcard prefix matching corrected (`[:-1]` retains the colon separator, preventing prefix boundary leaks like `crmX:secret`).
  - M2-M-02: Implicit cross-resource aliasing removed; policy scopes are strictly explicit or namespace-bounded.
  - M2-M-03: Limit conditions fail closed if `limit` parameter is missing or non-numeric.
  - M2-M-04: Recursive parameter sanitization protects against nested credential leaks in audit logs.
  - M2-L-02: Target list items validated as strings at rule construction time.
- [x] **Test Verification:**
  - 25 automated unit tests in `tests/test_policy_engine.py`, including final M2 remediation regressions and concurrent registry updates.
  - Total test suite at M2 finalization: 45 tests; later gateway, managed-agent, and independent-review regressions bring the current full suite to 65 (`CURRENT_STATE.md`).

- [x] **Final M2 Security Review Findings:**
  - Malformed action/resource identifiers and non-dictionary parameters fail closed.
  - Policy conditions accept only known keys and validated types/ranges.
  - Rule targets are tuples and nested conditions are recursively immutable.
  - `PolicyDecision.to_dict()` returns a detached summary.
  - Audit strings redact labeled inline credentials and bearer tokens in addition to sensitive-key redaction.
  - Immutability tests assert specific exception types instead of broad `Exception`.

---

## 5. Current Next Action

Latest issue: hosted MCP POST returned `Invalid Host header`. The MCP SDK was applying its localhost-only DNS-rebinding Host default; a local fix now explicitly allows the exact Render host and configured CORS origins without disabling that protection. Regression coverage verifies successful MCP initialization on the approved host and rejection of unknown hostnames/origins.

Next task: publish this fix and allow Render to deploy it, then verify authenticated MCP tool discovery and ALLOW/DENY/REQUIRE_APPROVAL behavior with the separately provisioned demo-agent credential. Preserve persistent DB configuration and ingress controls.
