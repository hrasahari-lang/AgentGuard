# AgentGuard — Current State

**Last updated:** 2026-11-06
**Stage:** M3/M4/M5 local vertical slice and read-only dashboard MVP — verified locally

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
- M3/M4 implementation adds the pinned MCP SDK 2.3.0 Streamable HTTP gateway, hashed/revocable credentials, pre-routing bearer auth, scoped CRM tools, persistent decision/execution audit, and fail-closed handling.
- A separate MCP client demo and HTTP tests exercise discovery, ALLOW, DENY, REQUIRE_APPROVAL, identity spoof attempts, token rejection/rotation/revocation, audit failures, and execution failures.
- An admin-authenticated read-only React + TypeScript dashboard loads real overview counts, agents, policies, and audit rows from backend APIs. No metrics are simulated. The admin token is held in browser memory only.
- The M3/M4/M5 backend and local dashboard milestone changes are implemented and verified. This remains a local prototype: authentication is a local bearer-token registry, not OAuth; approval handling, dynamic policy editing, production deployment, and Render Workflows remain outstanding.

---

## 2. Workspace & Git Configuration

- **Workspace directory:** `C:\Users\nunna\Desktop\GURDAI1`
- **Git status:** Branch `main`; base HEAD `d56fb53` includes remote commit `85eca75` via a merge preserving both histories. Milestone implementation changes are pending local checkpoint. Pre-existing untracked `M2_FINAL_SECURITY_REVIEW.md` remains untouched and must not be included in the checkpoint.
- **Git remote:** `origin` -> `https://github.com/hrasahari-lang/AgentGuard.git`
- **`.gitignore` active:** Excludes `.venv/`, `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*`, `__pycache__/`, `.env`, `.env.*`.
- **Python environment:** Python 3.11; `mcp==2.3.0` and HTTP runtime dependencies installed in `.venv` and pinned directly in `requirements.txt` for the gateway. Tests use standard-library `unittest`.
- **Frontend environment:** Node 24/npm 11; React 19.3.1, Vite 8.3.6, TypeScript 7.0.2. `npm run build` succeeds.

---

## 3. M3/M4/M5 Files Added or Modified

- `backend/app/policy_engine.py` (M2 hardening plus thread-safe policy registry reads and writes)
- `backend/app/security/auth.py` (hashed credential issuance, rotation, revocation, verification and ASGI middleware)
- `backend/app/audit/audit_store.py` (persistent policy and execution audit)
- `backend/app/gateway/mcp_server.py` (MCP tools and governed execution)
- `backend/app/provision_agent.py`, `backend/app/run_gateway.py`, `requirements.txt`
- `demo/external_agent.py`, `tests/test_gateway.py`, concurrency and integration coverage
- Root README, backend setup, security and architecture docs

---

## 4. Actual Test Results

Command: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v`
Latest result: **Ran 45 tests in 5.319s — OK (all passed).** This includes the 11 M1 CRM tests, M2 policy regression tests and M3/M4 HTTP gateway/API tests.

Frontend build: `npm run build` from `frontend/` — **exit code 0**, TypeScript check and Vite production bundle succeeded.

Compilation: `.venv\Scripts\python.exe -B -m compileall -q backend tests demo` — **exit code 0** after implementation and docs update.
Diff Check: `git diff --check` — **exit code 0** after implementation and docs update.

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

**Milestone 2 Policy Tests (25 passed in the latest full suite):**
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

M3 uses prototype registry authentication, not OAuth/SSO. Human approvals, dynamic policy editing, hosted deployment, and Render Workflows remain unimplemented. `gh auth status` reports no authenticated GitHub host; therefore account identity and write permission cannot be verified, and no push is safe or was attempted. The pre-existing untracked `M2_FINAL_SECURITY_REVIEW.md` remains untouched.

---

## 6. Next Exact Task

1. Commit the verified local M3/M4/M5 and read-only dashboard milestone, excluding the pre-existing independent review file.
2. Run the documented local backend + dashboard demo from a clean setup.
3. Continue with human approval/replay protection; do not begin deployment until asked and production auth/database are resolved.
