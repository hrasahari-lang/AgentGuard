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
| **Milestone 2** | Deterministic Policy Engine (without MCP) | **PENDING** | Next milestone: Typed request models, identity-aware policies, ALLOW / REQUIRE_APPROVAL / DENY, deterministic constraints, fail-closed default. |
| **Milestone 3** | MCP Streamable HTTP Gateway | **PENDING** | Official MCP Python SDK v2, HTTP Bearer token authentication boundary, session identity mapping, tool registration, protected credential isolation. |
| **Milestone 4** | Controlled Execution & Audit Engine | **PENDING** | Single executor routing, audit logging, separate decision vs. execution recording, failure recording without rolling back decision logs. |
| **Milestone 5** | External Agent Integration | **PENDING** | Standalone agent client connecting over MCP Streamable HTTP, discovering tools and executing governed operations. |
| **Milestone 6** | Dynamic Policies & Human Approvals | **PENDING** | Admin policy API, one-time approval tokens, replay protection, cryptographic request hash binding, revalidation before execution. |
| **Milestone 7** | Enterprise Admin UI & Polish | **PENDING** | Professional React + TypeScript interface, live backend telemetry, metrics tied to persistent backend data, demo scripts. |
| **Milestone 8** | Render Workflows & Public Deployment | **PENDING** | Render Web Services (FastAPI + MCP gateway), Render Static Sites (React frontend), Render PostgreSQL, Render Workflows integration. |

**Overall Progress:** 2 / 9 Milestones Complete (~22% based on verified acceptance criteria).

---

## 3. Milestone 1 Verified Acceptance Criteria

- [x] **Reproducible Schema & Data Seeding:**
  - `customers` table with `customer_id`, `name`, `email`, `status`, `assigned_agent_id`.
  - `resource_invocation_counter` table with `id`, `resource_name`, `total_invocations`, `successful_invocations`.
  - 7 synthetic customer records loaded across 3 agents using RFC 2606 reserved `.example.com` domains.
  - Idempotent re-initialization confirmed (`init_db()` preserves data and counter rows without duplicates).
- [x] **Zero SQL Injection Vulnerabilities:**
  - 100% parameterized queries using `?` placeholders across all repository functions.
  - Payloads tested: malicious OR conditions, DROP TABLE attempts, UNION SELECT injection.
- [x] **Server-Side Resource Scoping:**
  - Agent-specific filtering enforced inside SQL (`WHERE customer_id = ? AND assigned_agent_id = ?`).
  - Standard agents cannot view, search, or export records belonging to other agents.
  - Admin agent maintains cross-agent visibility.
- [x] **Strict Pre-Execution Validation:**
  - `isinstance(agent_context, TrustedAgentContext)` enforced on all protected methods.
  - Untrusted contexts or missing arguments raise `TypeError` prior to repository execution.
  - Search limits bounded to `1 <= limit <= 100`; export limits bounded to `1 <= limit <= 1000`.
  - Booleans rejected for integer limit parameters.
  - Export format restricted to whitelist `("json", "csv")`.
- [x] **Persistent Invocation Counters:**
  - `total_invocations` committed immediately in a dedicated connection before running queries.
  - Failed queries (e.g. dropped tables) retain `total_invocations` increment while `successful_invocations` remains unincremented.
  - Validation failures do not increment counters.
- [x] **Database Concurrency & Reliability Hardening:**
  - WAL (Write-Ahead Logging) journal mode enabled on file-backed databases (`PRAGMA journal_mode = WAL;`).
  - In-memory databases (`:memory:`) skip WAL activation.
  - 15-second busy timeout set on SQLite connections.
- [x] **Test Verification:**
  - 11 automated unit tests in `tests/test_crm_repository.py` passing in ~0.6s.
  - Clean bytecode compilation with `python -m compileall`.

---

## 4. Next Milestone Scope: Milestone 2

**Target:** Deterministic Policy Engine (Without MCP)
1. Typed request context and tool execution request models (`dataclass` or `pydantic`).
2. Policy rule definitions mapping agent identities and scopes to tools and constraints.
3. Decision outcomes: `ALLOW`, `REQUIRE_APPROVAL`, `DENY`.
4. Deterministic condition evaluation (scope match, argument constraints, rate/record bounds).
5. Default to `DENY` when no explicit matching policy exists (fail-closed security).
6. Comprehensive unit test suite covering allow, deny, approval, scope violations, and missing policies.
