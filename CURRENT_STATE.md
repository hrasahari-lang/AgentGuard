# AgentGuard — Current State

**Last updated:** 2026-11-06
**Stage:** Milestone 2 Complete — Deterministic Policy Engine (without MCP integration)

---

## 1. Product Status

- BYOA governance gateway for compatible AI agents over MCP Streamable HTTP.
- Milestone 1 complete & hardened: SQLite synthetic CRM, parameterized queries, server-side resource scoping, persistent entry/success invocation counters, WAL journal mode, 15-second busy timeout.
- Milestone 2 complete: Deterministic policy evaluation engine (`backend/app/policy_engine.py`) implementing:
  - Three distinct outcomes: `ALLOW`, `REQUIRE_APPROVAL`, `DENY`.
  - Zero-trust identity enforcement using server-side `TrustedAgentContext` (tool argument spoofing rejected).
  - Deterministic precedence: priority integer -> deny-overrides -> specificity -> lexical tie-break.
  - Fail-closed security for unmatched, malformed, or untrusted requests.
  - Total decoupling from CRM tool execution (zero CRM queries or counter increments during evaluation).
  - 14 automated policy tests added; 25/25 total test suite passing.

---

## 2. Workspace & Git Configuration

- **Workspace directory:** `C:\Users\nunna\Desktop\GURDAI1`
- **Git status:** Branch `main`, committed Milestone 1 (`71fb8a2`).
- **Git remote:** `origin` -> `https://github.com/hrasahari-lang/AgentGuard.git`
- **`.gitignore` active:** Excludes `.venv/`, `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*`, `__pycache__/`, `.env`, `.env.*`.
- **Python environment:** Python 3.11.1 standard library (zero third-party package dependencies across M1 and M2).

---

## 3. Milestone 2 Implementation Summary

### New Components:
- **Policy Engine Module (`backend/app/policy_engine.py`):**
  - `PolicyOutcome`: Enum (`ALLOW`, `REQUIRE_APPROVAL`, `DENY`).
  - `RiskLevel`: Enum (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - `PolicyEvaluationRequest`: Frozen dataclass capturing agent context, tool name, action, resource, parameters, and client request ID.
  - `PolicyDecision`: Structured, immutable authorization decision with `.to_dict()` audit serialization.
  - `PolicyRule`: Validated policy rule with priority, targets, conditions, and risk level.
  - `PolicyEngine`: Registry with dynamic add/remove/get/list/enable/disable and deterministic `evaluate()` algorithm.
  - Baseline default policies: Admin full access, sales search allow (<= 50), sales search approval (51-100), sales lookup allow, sales export approval (<= 100), sales bulk export deny (> 100), dangerous tools deny.
- **Automated Test Suite (`tests/test_policy_engine.py`):**
  - 14 tests covering explicit allow/deny/approval, fail-closed defaults, precedence, disabled rules, identity isolation & spoofing resistance, resource scoping, unknown tools, untrusted contexts, malformed rule definitions, repeated determinism, audit serialization, and decoupling proof.

---

## 4. Files Created or Modified

- `backend/app/policy_engine.py` (Created)
- `tests/test_policy_engine.py` (Created)
- `GOALS_AND_PROGRESS.md` (Updated)
- `CURRENT_STATE.md` (Updated)

---

## 5. Actual Test Results

Command: `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`  
Result: **Ran 25 tests in 0.624s — OK (All 25 tests passed)**

**Milestone 1 Tests (11 passed):**
1. `test_agent_specific_record_access` — ok
2. `test_counter_persistence_on_failure` — ok
3. `test_customer_search` — ok
4. `test_database_initialization` — ok
5. `test_invocation_counter_increments` — ok
6. `test_missing_customer_handling` — ok
7. `test_record_limits` — ok
8. `test_sql_injection_resistance` — ok
9. `test_successful_customer_lookup` — ok
10. `test_synthetic_data_seeding` — ok
11. `test_wal_mode_and_connection_settings` — ok

**Milestone 2 Tests (14 passed):**
12. `test_agent_identity_isolation` — ok (verifies agent cannot access other agents' rules or spoof identity via parameters)
13. `test_conflicting_policies_and_precedence` — ok (verifies priority, deny-overrides, specificity, and lexical tie-break)
14. `test_decision_audit_serialization` — ok (verifies structured audit dictionary and secret redaction)
15. `test_deterministic_repeated_evaluation` — ok (100 iterations yield identical decisions)
16. `test_disabled_policies` — ok (disabled rules ignored; dynamic enable/disable verified)
17. `test_explicit_allow` — ok (search <= 50, lookup, admin full access)
18. `test_explicit_deny` — ok (dangerous tools, bulk export > 100)
19. `test_malformed_policy_definitions` — ok (validation rejects empty IDs, invalid outcomes, invalid priority types)
20. `test_missing_or_untrusted_agent_context` — ok (None, string, dict contexts fail closed to DENY with CRITICAL risk)
21. `test_no_matching_policy` — ok (unregistered agent or unknown tool fails closed to DENY)
22. `test_no_protected_crm_execution_during_policy_evaluation` — ok (verifies CRM invocation counter remains exactly 0)
23. `test_require_approval` — ok (bulk search 51-100, sensitive export <= 100)
24. `test_resource_level_restrictions` — ok (mismatched resource scopes fail closed)
25. `test_unknown_tools_and_actions` — ok (unconfigured actions fail closed without unhandled errors)

Compilation: `.\.venv\Scripts\python.exe -m compileall -q backend tests` — Exit Code `0`.
Diff Check: `git diff --check` — Exit Code `0`.

---

## 6. Current Known Errors / Blockers

None. Milestone 2 is complete and verified.

---

## 7. Next Exact Task

1. Stage verified Milestone 2 files.
2. Commit locally with message: `feat: add deterministic policy engine`.
3. Await user instructions to proceed to Milestone 3 (MCP Streamable HTTP Gateway).
