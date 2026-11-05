# AgentGuard — Current State

**Last updated:** 2026-11-06
**Stage:** Milestone 2 Hardened — Security Review Remediation Complete

---

## 1. Product Status

- BYOA governance gateway for compatible AI agents over MCP Streamable HTTP.
- Milestone 1 complete & hardened: SQLite synthetic CRM, parameterized queries, server-side resource scoping, persistent entry/success invocation counters, WAL journal mode, 15-second busy timeout.
- Milestone 2 complete & hardened per independent security review (`M2_INDEPENDENT_SECURITY_REVIEW.md`):
  - Deterministic policy evaluation engine (`backend/app/policy_engine.py`).
  - Three distinct outcomes: `ALLOW`, `REQUIRE_APPROVAL`, `DENY`.
  - Zero-trust identity enforcement using server-side `TrustedAgentContext` (tool argument spoofing rejected).
  - Deterministic precedence: priority integer -> deny-overrides -> specificity -> lexical tie-break.
  - Fail-closed security for unmatched, malformed, or untrusted requests.
  - Total decoupling from CRM tool execution (zero CRM queries or counter increments during evaluation).
  - Hardening remediations applied:
    - **M2-H-01 (HIGH):** `PolicyRule` is immutable (`@dataclass(frozen=True)`). Engine stores and returns independent deep copies on `add_policy`, `get_policy`, and `list_policies` to prevent external memory tampering.
    - **M2-M-01 (MEDIUM):** Resource wildcard prefix matching corrected: `tr_lower[:-1]` preserves the `:` separator so `crm:*` matches `crm:customers` and `crm:orders` but strictly rejects adjacent namespace prefixes like `crmX:secret` or `crm2:hr_data`.
    - **M2-M-02 (MEDIUM):** Removed hardcoded bidirectional `crm`/`crm:customers` equivalence bridge to prevent unauthorized sub-resource widening. Policy scopes are strictly explicit or namespace wildcarded.
    - **M2-M-03 (MEDIUM):** Limit condition evaluations fail closed: requests lacking a valid numeric `limit` parameter cannot match rules with `min_limit` or `max_limit` conditions.
    - **M2-M-04 (MEDIUM):** Recursive parameter sanitization scrubs sensitive keys (`password`, `secret`, `token`, `key`, `auth`, `credential`, `bearer`, `private`) across arbitrary nesting depths and lists/dicts, bounded to depth 5 with string truncation.
    - **M2-L-02 (LOW):** PolicyRule targets validated at initialization to reject non-string elements.
  - 31/31 total automated tests passing (11 M1 CRM tests + 14 M2 core policy tests + 6 M2 security regression tests).

---

## 2. Workspace & Git Configuration

- **Workspace directory:** `C:\Users\nunna\Desktop\GURDAI1`
- **Git status:** Branch `main`, committed Milestone 2 (`77da5b8`).
- **Git remote:** `origin` -> `https://github.com/hrasahari-lang/AgentGuard.git`
- **`.gitignore` active:** Excludes `.venv/`, `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*`, `__pycache__/`, `.env`, `.env.*`.
- **Python environment:** Python 3.11.1 standard library (zero third-party package dependencies across M1 and M2).

---

## 3. Files Created or Modified in this Remediation

- `backend/app/policy_engine.py` (Hardened with immutable rules, deep-copies, exact wildcard slicing, fail-closed limit checks, recursive parameter sanitization)
- `tests/test_policy_engine.py` (Added 6 targeted regression tests for M2-H-01, M2-M-01, M2-M-02, M2-M-03, M2-M-04, and M2-L-02)
- `M2_INDEPENDENT_SECURITY_REVIEW.md` (Preserved independent review audit document)
- `GOALS_AND_PROGRESS.md` (Updated verified criteria and test counts)
- `CURRENT_STATE.md` (Updated)

---

## 4. Actual Test Results

Command: `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`
Result: **Ran 31 tests in 0.655s — OK (All 31 tests passed)**

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

**Milestone 2 Tests (20 passed):**
12. `test_agent_identity_isolation` — ok
13. `test_conflicting_policies_and_precedence` — ok
14. `test_decision_audit_serialization` — ok
15. `test_deterministic_repeated_evaluation` — ok
16. `test_disabled_policies` — ok
17. `test_explicit_allow` — ok
18. `test_explicit_deny` — ok
19. `test_finding_m2_h01_immutable_policy_rules_and_defensive_copies` — ok
20. `test_finding_m2_l02_policy_rule_list_item_type_validation` — ok
21. `test_finding_m2_m01_resource_wildcard_boundary` — ok
22. `test_finding_m2_m02_explicit_resource_scoping_no_implicit_alias` — ok
23. `test_finding_m2_m03_limit_condition_fail_closed_on_missing_or_invalid_limit` — ok
24. `test_finding_m2_m04_recursive_audit_parameter_redaction` — ok
25. `test_malformed_policy_definitions` — ok
26. `test_missing_or_untrusted_agent_context` — ok
27. `test_no_matching_policy` — ok
28. `test_no_protected_crm_execution_during_policy_evaluation` — ok
29. `test_require_approval` — ok
30. `test_resource_level_restrictions` — ok
31. `test_unknown_tools_and_actions` — ok

Compilation: `.\.venv\Scripts\python.exe -m compileall -q backend tests` — Exit Code `0`.
Diff Check: `git diff --check` — Exit Code `0`.

---

## 5. Current Known Errors / Blockers

None. Milestone 2 security hardening is verified and complete.

---

## 6. Next Exact Task

1. Commit hardened files locally with message: `fix: harden policy engine security validation`.
2. Await user instructions to proceed to Milestone 3 (MCP Streamable HTTP Gateway).
