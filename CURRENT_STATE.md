# AgentGuard — Current State

**Last updated:** 2026-11-06
**Stage:** Final release deployment attempt — local security verification complete; provider authorization and hosted configuration are blocked

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
- An admin-authenticated read-only React + TypeScript dashboard loads real overview counts, agents, policies, and audit rows from backend APIs. No metrics are simulated. The admin token is held in browser memory only and privileged data is cleared on request failures.
- The M3/M4/M5 backend and local dashboard milestone changes are implemented and verified. This remains a local prototype: authentication is a local bearer-token registry, not OAuth; approval handling, dynamic policy editing, production deployment, and Render Workflows remain outstanding.
- **AG-01 — fixed in the bundled clients:** both clients use the shared endpoint resolver and `PinnedAddressTransport`. The resolver rejects every non-public DNS answer; the transport dials a retained literal address, preserves the configured Host and TLS SNI name, and uses normal certificate verification. Ambient proxies are disabled. Loopback HTTP remains restricted to verified loopback destinations. Regression tests exercise rebinding, IPv4/IPv6, TLS hostname mismatch, SNI and redirects. Keep the pinned `httpx2`/`httpcore2` versions and rerun these tests on upgrades; network egress rules remain defense in depth.
- **AG-02 — partially fixed:** a process-local request limiter allows at most 300 requests per peer per 60 seconds by default before credential lookup and counts valid and invalid requests equally. Auth-failure audit writes have a separate 20-per-peer cap. The bounded peer table does not evict active peers; new peers share an overflow bucket. The gateway ignores forwarded headers and the launcher disables Uvicorn proxy rewriting. Per-process limits and proxy-shared peer identities require upstream ingress controls for hosted deployments.
- **AG-03 — fixed locally:** production dashboard origins require HTTPS on the default port and an exact hostname in build-time `VITE_AGENTGUARD_ALLOWED_API_HOSTS`; loopback HTTP is accepted only for development. Request failures (including 401/403, server errors and network errors) clear privileged data, connection credentials and timestamps. Regression coverage verifies these boundaries.
- Latest verification after DNS pinning: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` — **76 tests passed in 17.408s**; frontend `npm test` — **5 passed**; `npm run typecheck`, `npm run build`, Python compileall and `git diff --check` all exited 0.
- No dependencies or deployment credentials were installed or provisioned. No hosted deployment or live smoke test was performed.
- **Deployment check (2026-11-06): blocked before deployment.** The Vercel app connection returned `UNAUTHORIZED` and requires reconnection; Vercel and Railway CLIs are unavailable in the workspace, and no authenticated alternate host is connected. The repository has no Vercel or Railway deployment configuration.
- Backend deployment prerequisites are still missing: `backend/app/run_gateway.py` defaults to `127.0.0.1` and reads `AGENTGUARD_PORT` rather than platform `PORT`; CORS in `backend/app/gateway/mcp_server.py` only allows local Vite origins; SQLite defaults to `backend/data/crm.db` and needs a persistent mount configured through `AGENTGUARD_DB_PATH`; no explicit health route was found; no production admin credential was provisioned. Upstream ingress limits are also required. No public URLs were available to smoke-test. Outbound egress restrictions remain defense in depth. The local credential registry is not OAuth/SSO.

---

## 2. Workspace & Git Configuration

- **Workspace directory:** `C:\Users\nunna\Desktop\GURDAI1`
- **Git status:** Branch `main`, HEAD `3abde8fcc249f43288237203e31b8f46ae260f55` (different from the supplied published baseline `1b471fbc56c488d0dc79bdea5bc23ca98cf16cd6`); AG-01–AG-03 changes are uncommitted. Existing untracked `M2_FINAL_SECURITY_REVIEW.md`, `AgentGuard_Audit.zip`, and `AgentGuard_Audit/` remain untouched. No commit or push was made.
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

- `demo/endpoint_validation.py`, `demo/pinned_http_transport.py`, `demo/managed_agent.py`, `demo/external_agent.py`, `tests/test_agent_endpoint.py`
- `backend/app/config.py`, `backend/app/security/auth.py`, `backend/app/audit/audit_store.py`, `backend/app/gateway/mcp_server.py`, `backend/app/run_gateway.py`
- `tests/test_auth_failure_controls.py`, `tests/test_gateway.py`
- `frontend/src/gatewaySecurity.ts`, `frontend/src/App.tsx`, `frontend/src/vite-env.d.ts`, `frontend/src/styles.css`, `frontend/tests/gatewaySecurity.test.mjs`, `frontend/package.json`, `frontend/.env.example`
- `.env.example`, `backend/README.md`, `demo/README.md`, `SECURITY_RULES.md`, `SYSTEM_ARCHITECTURE.md`, `DECISIONS.md`, `CURRENT_STATE.md`, `GOALS_AND_PROGRESS.md`

---

## 4. Actual Test Results

Earlier clean-install result: `C:\Users\nunna\AppData\Local\Temp\AgentGuard-Clean-Requirements-20261106\Scripts\python.exe -B -m unittest discover -s tests -v` — **Ran 56 tests in 15.449s — OK** at that earlier code state. This includes the preserved 45-test baseline, 10 security regressions, and the managed-agent integration regression.

Clean-install evidence: created a fresh Python 3.11 venv outside the project and installed only with `pip install -r requirements.txt`; the final 56-test suite and `compileall` passed in that environment. No pytest dependency is needed.

New gateway regressions cover gated identity construction, sanitized auth-failure categories, fail-closed auth-audit errors, all admin endpoints for anonymous/invalid/ordinary/admin callers, sensitive-data exclusion, duplicate and conflicting request IDs, hashed identifiers, execution-start audit failure, outcome-audit ambiguity and replay refusal, explicit idempotency keys for future mutations, and the managed agent's authenticated execution plus same-ID replay refusal.

Frontend build: `npm run build` from `frontend/` — **exit code 0**, TypeScript check and Vite production bundle succeeded.

Clean-environment interpreter: `C:\Users\nunna\AppData\Local\Temp\AgentGuard-Clean-Requirements-20261106\Scripts\python.exe`.
Compilation: clean-environment `python -B -m compileall -q backend tests demo` — **exit code 0**.
Frontend type check: `npm run typecheck` — **exit code 0**.
Frontend production build: `npm run build` — **exit code 0**.
Diff Check: `git diff --check` — **exit code 0**.

### Final AG-01–AG-03 release verification (2026-11-06)

- Full backend suite: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` — **Ran 76 tests in 17.408s — OK**, exit code 0.
- Python compilation: `.\.venv\Scripts\python.exe -B -m compileall -q backend tests demo` — exit code 0.
- Frontend security tests: `npm test` — **5 passed, 0 failed**, exit code 0.
- Frontend typecheck: `npm run typecheck` — exit code 0.
- Frontend production build: `npm run build` — exit code 0.
- `git diff --check` — exit code 0 after final documentation update (Git may emit configured LF-to-CRLF advisory warnings).

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

Next: before private hosted testing, configure upstream ingress limits and trusted proxy handling, then address production CORS, platform bind/port handling, durable storage, and secure same-database admin credential provisioning. The bundled MCP clients now pin validated DNS results to literal IP connections while retaining TLS hostname verification. Keep egress restrictions as defense in depth. Do not deploy or expose a public backend until the hosted prerequisites are met and deployment is separately authorized. No feature milestone, commit, push, credential provisioning, or deployment was performed in this task.
