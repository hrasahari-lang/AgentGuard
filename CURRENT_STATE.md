# AgentGuard — Current State

**Last updated:** 2026-11-06
**Stage:** Milestone 2 Final Security Remediation — Verified

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
- Final M2 remediation addressed malformed action/resource normalization, policy condition schema validation, nested rule mutability, detached audit serialization, inline secret redaction, and precise exception assertions.
- M2 regression tests now cover malformed request identifiers, invalid condition schemas, nested immutable policy data, detached summaries, and labeled inline credentials.
- Full-suite verification for this remediation: `.\\.venv\\Scripts\\python.exe -B -m unittest discover -s tests -v` — **35 tests passed in 0.551s**.

---

## 2. Workspace & Git Configuration

- **Workspace directory:** `C:\Users\nunna\Desktop\GURDAI1`
- **Git status:** Branch `main`, M2 final security remediation committed as `bca98b0`; pre-existing untracked `M2_FINAL_SECURITY_REVIEW.md` remains untouched.
- **Git remote:** `origin` -> `https://github.com/hrasahari-lang/AgentGuard.git`
- **`.gitignore` active:** Excludes `.venv/`, `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*`, `__pycache__/`, `.env`, `.env.*`.
- **Python environment:** Python 3.11.1 standard library (zero third-party package dependencies across M1 and M2).

---

## 3. Files Modified in this Remediation

- `backend/app/policy_engine.py` (Added strict action/resource validation, comprehensive condition schema validation, immutable nested rule data, copied audit output, and inline secret redaction)
- `tests/test_policy_engine.py` (Added four regression tests and tightened exception assertions)
- `GOALS_AND_PROGRESS.md` (Updated verified criteria and test counts)
- `DECISIONS.md` (Recorded the M2 validation and immutability choices)
- `CURRENT_STATE.md` (Updated)

---

## 4. Actual Test Results

Command: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v`
Result: **Ran 35 tests in 0.551s — OK (all passed).**

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

**Milestone 2 Tests (24 passed):**
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
32. `test_malformed_action_resource_and_parameters_fail_closed` — ok
33. `test_policy_condition_schema_is_validated` — ok
34. `test_audit_serialization_returns_detached_summary` — ok
35. `test_inline_secret_values_are_redacted` — ok

Compilation: `.\.venv\Scripts\python.exe -B -m compileall -q backend tests` — Exit Code `0`.
Diff Check: `git diff --check` — Exit Code `0`.

---

## 5. Current Known Errors / Blockers

No M2 test failures remain. The existing untracked `M2_FINAL_SECURITY_REVIEW.md` was present before this work and remains untouched. Thread safety and trusted-context construction boundary remain deferred to M3 as recorded in the independent review.

---

## 6. Next Exact Task

1. Await user instructions before Milestone 3 (MCP Streamable HTTP Gateway).
