# AgentGuard — Current State

**Last updated:** 2026-11-06
**Stage:** AG-01–AG-03 immediate security remediation — verified locally, not deployed

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
- Independent review Stage 1 fixes: gated trusted context/principal constructors; credential-backed test fixtures; sanitized authentication failure records; endpoint authorization matrix; request ID idempotency; distinct execution/audit ambiguity states.
- Managed-agent Stage 2 adds a minimal deterministic MCP task client that reads its bearer token from the environment, discovers the gateway tool, and sends a scoped search through the existing authenticated gateway. The request ID is printed before the call to help investigate ambiguous outcomes. It has no CRM repository or database access; this is not an LLM planner.
- `httpx2` is intentional for MCP SDK v2. `requirements.txt` pins the complete Python 3.11 runtime/test dependency set, including direct `mcp`, `httpx2`, and `uvicorn` imports. Tests use standard-library `unittest`.
- An admin-authenticated read-only React + TypeScript dashboard loads real overview counts, agents, policies, and audit rows from backend APIs. No metrics are simulated. The admin token is held in browser memory only.
- The M3/M4/M5 backend and local dashboard milestone changes are implemented and verified. This remains a local prototype: authentication is a local bearer-token registry, not OAuth; approval handling, dynamic policy editing, production deployment, and Render Workflows remain outstanding.
- **AG-01 — fixed and regression-tested locally:** both MCP demo clients share a strict endpoint validator; remote HTTP, unsupported schemes, malformed URLs, embedded credentials and ambiguous host forms fail before an HTTP client is constructed. Loopback HTTP and remote HTTPS are accepted.
- **AG-02 — bounded locally, not distributed protection:** authentication failures are limited to 20 per transport peer per 60 seconds by default before auth-failure audit writes; peer buckets are capped at 4,096; only the newest 10,000 sanitized auth-failure rows are retained. Invalid token hashes use the unique indexed lookup. The provided Uvicorn launcher disables proxy-header rewriting. An upstream ingress limiter remains required against distributed attacks and shared reverse-proxy peer addresses.
- **AG-03 — fixed and regression-tested locally:** the dashboard uses only build-time `VITE_AGENTGUARD_API_ORIGIN`, rejects invalid/insecure/noncanonical settings, has no editable gateway URL, blocks absolute cross-origin API paths and redirects, keeps the token in memory, clears privileged state on 401/403, and displays the configured origin and current gateway status.
- Latest verification after these changes: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` — **65 tests passed in 16.222s**; Python compileall exit 0; frontend `npm test` — **4 passed**; `npm run typecheck` and `npm run build` exit 0; `git diff --check` exit 0.
- No dependencies were installed. No credential was provisioned. No commit, push, or deployment was performed.
- Public deployment remains blocked pending production CORS allowlisting, `0.0.0.0`/platform `PORT` binding, durable database configuration, same-database admin credential provisioning, and upstream rate limiting. The local registry is not OAuth/SSO.

---

## 2. Workspace & Git Configuration

- **Workspace directory:** `C:\Users\nunna\Desktop\GURDAI1`
- **Git status:** Branch `main`; AG-01–AG-03 changes are uncommitted. Existing untracked `M2_FINAL_SECURITY_REVIEW.md`, `AgentGuard_Audit.zip`, and `AgentGuard_Audit/` remain untouched. No commit or push was made.
- **Git remote:** `origin` -> `https://github.com/hrasahari-lang/AgentGuard.git`
- **`.gitignore` active:** Excludes `.venv/`, `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*`, `__pycache__/`, `.env`, `.env.*`.
- **Python environment:** Python 3.11; `mcp==2.3.0` and HTTP runtime dependencies installed in `.venv` and pinned directly in `requirements.txt` for the gateway. Tests use standard-library `unittest`.
- **Frontend environment:** Node 24/npm 11; React 19.3.1, Vite 8.3.6, TypeScript 7.0.2. `npm run build` succeeds.

---

## 3. Files Changed

### Security remediation Stage 1

- `requirements.txt` (pinned Python 3.11 dependency set)
- `backend/app/crm_repository.py`, `backend/app/security/auth.py` (gated identity construction and authentication audit)
- `backend/app/audit/audit_store.py`, `backend/app/gateway/mcp_server.py` (execution phases and idempotency)
- `tests/context_fixtures.py`, `tests/test_crm_repository.py`, `tests/test_policy_engine.py`, `tests/test_gateway.py`
- `SYSTEM_ARCHITECTURE.md`, `SECURITY_RULES.md`, `DECISIONS.md`, `backend/README.md`, `CURRENT_STATE.md`, `GOALS_AND_PROGRESS.md`

### Managed-agent Stage 2

- `demo/managed_agent.py` (minimal authenticated task client)
- `demo/README.md`, `README.md` (run instructions and security boundary)
- `tests/test_gateway.py` (gateway integration, successful execution, duplicate request audit)
- `DECISIONS.md`, `CURRENT_STATE.md`, `GOALS_AND_PROGRESS.md`
- No application dashboard or frontend files changed.

### Independent review findings AG-01–AG-03

- `demo/endpoint_validation.py`, `demo/managed_agent.py`, `demo/external_agent.py`, `tests/test_agent_endpoint.py`
- `backend/app/config.py`, `backend/app/security/auth.py`, `backend/app/audit/audit_store.py`, `backend/app/gateway/mcp_server.py`, `backend/app/run_gateway.py`
- `tests/test_auth_failure_controls.py`, `tests/test_gateway.py`
- `frontend/src/gatewaySecurity.ts`, `frontend/src/App.tsx`, `frontend/src/vite-env.d.ts`, `frontend/src/styles.css`, `frontend/tests/gatewaySecurity.test.mjs`, `frontend/package.json`, `frontend/.env.example`
- `.env.example`, `backend/README.md`, `demo/README.md`, `SECURITY_RULES.md`, `SYSTEM_ARCHITECTURE.md`, `DECISIONS.md`, `CURRENT_STATE.md`, `GOALS_AND_PROGRESS.md`

---

## 4. Actual Test Results

Command: `C:\Users\nunna\AppData\Local\Temp\AgentGuard-Clean-Requirements-20261106\Scripts\python.exe -B -m unittest discover -s tests -v`
Final result in the clean requirements environment: **Ran 56 tests in 15.449s — OK (all passed).** This includes the preserved 45-test baseline, 10 security regressions, and the managed-agent integration regression.

Clean-install evidence: created a fresh Python 3.11 venv outside the project and installed only with `pip install -r requirements.txt`; the final 56-test suite and `compileall` passed in that environment. No pytest dependency is needed.

New gateway regressions cover gated identity construction, sanitized auth-failure categories, fail-closed auth-audit errors, all admin endpoints for anonymous/invalid/ordinary/admin callers, sensitive-data exclusion, duplicate and conflicting request IDs, hashed identifiers, execution-start audit failure, outcome-audit ambiguity and replay refusal, explicit idempotency keys for future mutations, and the managed agent's authenticated execution plus same-ID replay refusal.

Frontend build: `npm run build` from `frontend/` — **exit code 0**, TypeScript check and Vite production bundle succeeded.

Clean-environment interpreter: `C:\Users\nunna\AppData\Local\Temp\AgentGuard-Clean-Requirements-20261106\Scripts\python.exe`.
Compilation: clean-environment `python -B -m compileall -q backend tests demo` — **exit code 0**.
Frontend type check: `npm run typecheck` — **exit code 0**.
Frontend production build: `npm run build` — **exit code 0**.
Diff Check: `git diff --check` — **exit code 0**.

### Latest AG-01–AG-03 verification (2026-11-06)

- Full backend suite: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` — **Ran 65 tests in 16.222s — OK**, exit code 0.
- Python compilation: `.\.venv\Scripts\python.exe -B -m compileall -q backend tests demo` — exit code 0.
- Frontend security tests: `npm test` — **4 passed**, exit code 0.
- Frontend typecheck: `npm run typecheck` — exit code 0.
- Frontend production build: `npm run build` — exit code 0.
- `git diff --check` — exit code 0 (Git emitted only configured LF-to-CRLF advisory warnings).

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

M3 authentication is a local registry prototype, not OAuth/SSO. Request IDs remain optional for current read-only tools; retry deduplication requires the caller to pass a stable `request_id`. Any future mutating operation must require one. SQLite audit is persistent but mutable and not tamper-evident. Human approvals, dynamic policy editing, hosted deployment, and Render Workflows remain outstanding. No GitHub push was attempted.

---

## 6. Next Exact Task

AG-01–AG-03 remediation is verified locally. Next, review and implement only the minimum approved deployment-readiness changes: explicit backend CORS origins, platform bind/port handling, durable storage, secure same-database admin credential provisioning, and trusted ingress rate limiting. Do not expose a public backend or deploy until those requirements and approval are satisfied. No feature milestone, commit, push, credential provisioning, or deployment was performed.
