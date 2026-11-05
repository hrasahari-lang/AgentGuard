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
| **Milestone 2** | Deterministic Policy Engine (without MCP) | **COMPLETE** | Pure deterministic rule engine, explicit outcomes (ALLOW, REQUIRE_APPROVAL, DENY), verified `TrustedAgentContext` requirement, tool argument spoofing resistance, deterministic precedence, fail-closed default, zero CRM execution during evaluation. Hardened per M2 security review: frozen immutable `PolicyRule`, deep copies on get/list, exact wildcard prefix `crm:*`, explicit resource scoping without implicit aliasing, limit condition fail-closed, and recursive audit parameter redaction. 20 policy tests (31/31 total suite passing). |
| **Milestone 3** | MCP Streamable HTTP Gateway | **PENDING** | Official MCP Python SDK v2, HTTP Bearer token authentication boundary, session identity mapping, tool registration, protected credential isolation. |
| **Milestone 4** | Controlled Execution & Audit Engine | **PENDING** | Single executor routing, audit logging, separate decision vs. execution recording, failure recording without rolling back decision logs. |
| **Milestone 5** | External Agent Integration | **PENDING** | Standalone agent client connecting over MCP Streamable HTTP, discovering tools and executing governed operations. |
| **Milestone 6** | Dynamic Policies & Human Approvals | **PENDING** | Admin policy API, one-time approval tokens, replay protection, cryptographic request hash binding, revalidation before execution. |
| **Milestone 7** | Enterprise Admin UI & Polish | **PENDING** | Professional React + TypeScript interface, live backend telemetry, metrics tied to persistent backend data, demo scripts. |
| **Milestone 8** | Render Workflows & Public Deployment | **PENDING** | Render Web Services (FastAPI + MCP gateway), Render Static Sites (React frontend), Render PostgreSQL, Render Workflows integration. |

**Overall Progress:** 3 / 9 Milestones Complete (~33% based on verified acceptance criteria).

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
  - 20 automated unit tests in `tests/test_policy_engine.py` (14 foundational + 6 targeted security regression tests).
  - Total test suite: 31 tests passing in ~0.65s.

---

## 5. Next Milestone Scope: Milestone 3

**Target:** MCP Streamable HTTP Gateway
1. Implement official MCP Python SDK v2 server with Streamable HTTP transport.
2. Bearer token authentication boundary verifying cryptographic token hashes.
3. Establish session-level `TrustedAgentContext` without accepting identity from MCP tool arguments.
4. Tool registration for permitted and restricted tools, enabling AgentGuard to return denial responses.
