# AgentGuard — M2 Independent Security Review

**Review Date:** 2026-11-06  
**Review Type:** Read-Only Independent Security Analysis  
**Target Commit:** `77da5b8ff7896107faf3013f94bc9570a62b2682` (`feat: add deterministic policy engine`)  
**Reviewer Scope:** `backend/app/policy_engine.py`, `tests/test_policy_engine.py`, `backend/app/crm_repository.py`, complete M2 git diff  

---

## Executive Summary

The Milestone 2 policy engine is architecturally sound: it is deterministic, enforces `TrustedAgentContext`, never executes CRM operations, and fails closed to `DENY` for unmatched requests. The seven areas investigated reveal no Critical vulnerabilities. The findings are predominantly Medium and Low severity design gaps, all remediable before Milestone 3 integration.

**Findings count by severity:**

| Severity | Count |
|---|:---:|
| Critical | 0 |
| High | 1 |
| Medium | 4 |
| Low | 4 |

---

## Findings

---

### FINDING M2-H-01 — `PolicyRule` Is Mutable After Registration

**Severity: HIGH**  
**Category: External Mutation of Registered Policies**  
**Files:**  
- [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L88-L133) — `PolicyRule` declared with `@dataclass` (not `@dataclass(frozen=True)`)  
- [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L262-L266) — `add_policy` stores the passed reference directly  
- [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop\GURDAI1/backend/app/policy_engine.py#L272-L274) — `get_policy` returns the live internal reference  

**Description:**  
`PolicyRule` is a plain `@dataclass` — not frozen. Any caller holding a reference to a registered rule, or who retrieves one via `get_policy()`, can silently mutate any field (`outcome`, `priority`, `enabled`, `conditions`, `target_agents`, `target_tools`, `target_resources`) without going through `add_policy` or any validation path. The engine's registered rules dictionary holds the live object, so mutations take immediate effect for all subsequent evaluations without any audit trail.

**Reproduction Steps:**

```python
engine = PolicyEngine(load_defaults=True)
rule = engine.get_policy("POL-SALES-SEARCH-ALLOW")
# No copy is returned — this is the live registered object
rule.outcome = PolicyOutcome.DENY          # Silently changes ALLOW to DENY
rule.target_agents = ["*"]                 # Widens scope to ALL agents
rule.conditions = {}                       # Removes all limit conditions
# All subsequent evaluations are now silently affected with no log event
```

Additionally, since `add_policy` stores the same object reference that was passed in, the caller continues to hold a reference through which it can mutate the rule after registration:

```python
my_rule = PolicyRule(policy_id="X", ..., outcome=PolicyOutcome.ALLOW, ...)
engine.add_policy(my_rule)
my_rule.outcome = PolicyOutcome.DENY       # Mutates the live registered rule directly
```

**Risk:** An attacker with any application-layer access to the engine or who recovers a rule reference can silently escalate privileges, bypass explicit deny rules, or widen any policy scope without detection, without any validation, and without triggering a commit or audit event.

**Recommended Fix:**  
1. Change `@dataclass` to `@dataclass(frozen=True)` on `PolicyRule`. Where runtime enable/disable is needed, hold `enabled` in a separate `Dict[str, bool]` on the engine rather than as a mutable attribute on the rule.  
2. In `add_policy`, store a deep copy of the rule: `self._rules[rule.policy_id] = copy.deepcopy(rule)`.  
3. In `get_policy` and `list_policies`, return deep copies or use a frozen wrapper to prevent callers from holding live references.

---

### FINDING M2-M-01 — Resource Wildcard Prefix Match Is Unbounded

**Severity: MEDIUM**  
**Category: Resource Wildcard Boundary Bypass**  
**File:** [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L496-L498) — `_matches_resource`

**Description:**  
The rule `"crm:*"` is intended to match any resource beginning with `"crm:"`. The implementation uses:

```python
if tr_lower.endswith(":*") and res_lower.startswith(tr_lower[:-2]):
```

This slices off only the trailing `*` character but retains the `:`, so `tr_lower[:-2]` for `"crm:*"` produces `"crm"` — which means `res_lower.startswith("crm")` matches not only `"crm:customers"` and `"crm:orders"` but also `"crm_backup:secrets"`, `"crm2:hr_data"`, or any string beginning with `"crm"`.

The separator `:` is consumed by the slice, widening the match beyond the intended namespace. Any policy that uses `"crm:*"` as a resource target will match resources in adjacent namespaces that share the `"crm"` prefix.

**Reproduction Steps:**

```python
engine = PolicyEngine(load_defaults=False)
engine.add_policy(PolicyRule(
    policy_id="CRM-RULE",
    name="CRM Rule",
    description="Allow crm:*",
    outcome=PolicyOutcome.ALLOW,
    priority=10,
    target_agents=["agent_sales_1"],
    target_tools=["some_tool"],
    target_resources=["crm:*"],
))
ctx = TrustedAgentContext(agent_id="agent_sales_1")
# The following should NOT match crm:* but does:
req = PolicyEvaluationRequest(agent_context=ctx, tool_name="some_tool", resource="crm2:hr_data")
dec = engine.evaluate(req)
# dec.outcome == PolicyOutcome.ALLOW  (incorrect — should DENY)
```

**Recommended Fix:**  
Correct the slice to preserve the separator: change `tr_lower[:-2]` to `tr_lower[:-1]`. The correct check for `"crm:*"` → prefix `"crm:"` is:

```python
if tr_lower.endswith(":*") and res_lower.startswith(tr_lower[:-1]):
    return True
```

This matches `"crm:customers"` correctly while rejecting `"crm2:hr_data"` and `"crm_backup:secrets"`.

---

### FINDING M2-M-02 — Hardcoded `"crm"` / `"crm:customers"` Equivalence Leaks Cross-Resource Aliasing

**Severity: MEDIUM**  
**Category: Resource Wildcard Boundary / Invalid Resource Fail-Open**  
**File:** [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L499-L503) — `_matches_resource`

**Description:**  
Lines 500–503 hard-code bidirectional equivalence between the resource strings `"crm"` and `"crm:customers"`:

```python
if tr_lower == "crm" and res_lower == "crm:customers":
    return True
if tr_lower == "crm:customers" and res_lower == "crm":
    return True
```

This creates two risks:

1. **Overly broad aliasing:** A policy rule targeting resource `"crm"` (a namespace root) will match requests for `"crm:customers"` (a specific sub-resource). If a future sub-resource such as `"crm:invoices"` or `"crm:audit_logs"` is added to a different access tier, any policy that simply says `target_resources=["crm"]` will also silently match the new sub-resource without any policy update. 

2. **Reverse aliasing is inconsistent:** A policy authorizing `"crm:customers"` now also matches requests specifying only `"crm"`. An agent that requests the top-level namespace `"crm"` (which should be less specific or undefined) is granted access authorized at the sub-resource level.

**Reproduction Steps:**

```python
engine = PolicyEngine(load_defaults=False)
engine.add_policy(PolicyRule(
    policy_id="CRM-NS-RULE",
    name="Allow crm namespace",
    description="Restrict to crm namespace only",
    outcome=PolicyOutcome.ALLOW,
    priority=10,
    target_agents=["agent_sales_1"],
    target_tools=["query_tool"],
    target_resources=["crm"],   # Intended to match namespace root only
))
ctx = TrustedAgentContext(agent_id="agent_sales_1")
# This matches the "crm" namespace rule even though it targets a specific sub-resource:
req = PolicyEvaluationRequest(agent_context=ctx, tool_name="query_tool", resource="crm:customers")
dec = engine.evaluate(req)
# dec.outcome == PolicyOutcome.ALLOW — policy author may not have intended this
```

**Recommended Fix:**  
Remove the hardcoded equivalence bridge. Require policy authors to explicitly list all intended sub-resources (`target_resources=["crm", "crm:customers"]`) or use the corrected wildcard pattern `"crm:*"`. Document this clearly in `_matches_resource` and in policy authoring guidelines.

---

### FINDING M2-M-03 — Condition Matching Fails Open When `limit` Parameter Is Absent

**Severity: MEDIUM**  
**Category: Malformed Policy Conditions / Invalid Action Fail-Open Behavior**  
**File:** [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L512-L518) — `_matches_conditions`

**Description:**  
When a policy rule defines `min_limit` or `max_limit` conditions, the condition check is gated on whether the `limit` parameter is present in the request:

```python
limit_val = params.get("limit")
if limit_val is not None and isinstance(limit_val, (int, float)) and not isinstance(limit_val, bool):
    if "max_limit" in conditions and limit_val > conditions["max_limit"]:
        return False
    if "min_limit" in conditions and limit_val < conditions["min_limit"]:
        return False
```

If `limit` is absent from `params`, the entire block is skipped and the function falls through to `return True`, meaning the rule **matches** regardless of its limit conditions.

**Concrete Impact:**  
`POL-SALES-EXPORT-APPROVAL` requires `max_limit=100` and `POL-SALES-EXPORT-BULK-DENY` requires `min_limit=101`. An agent that submits an export request with **no `limit` parameter** will match `POL-SALES-EXPORT-APPROVAL` (which is correct), but it also silently matches `POL-SALES-EXPORT-BULK-DENY`. Because deny-overrides wins the collision, the result is DENY in the default policy set — however this is accidental protection from the precedence algorithm, not from the condition logic. For a custom engine that lacks a competing deny rule but has `max_limit=50`, an agent can bypass the limit condition entirely by omitting `limit`.

**Reproduction Steps:**

```python
engine = PolicyEngine(load_defaults=False)
engine.add_policy(PolicyRule(
    policy_id="SEARCH-ALLOW-50",
    name="Allow search <= 50",
    description="Allow only small searches",
    outcome=PolicyOutcome.ALLOW,
    priority=100,
    target_agents=["agent_sales_1"],
    target_tools=["search_customer_records"],
    conditions={"max_limit": 50},
))
ctx = TrustedAgentContext(agent_id="agent_sales_1")
# No limit parameter — should this match a rule designed for limit <= 50?
req = PolicyEvaluationRequest(agent_context=ctx, tool_name="search_customer_records",
                               parameters={})  # No limit supplied
dec = engine.evaluate(req)
# dec.outcome == PolicyOutcome.ALLOW — condition was not enforced
```

**Recommended Fix:**  
When `min_limit` or `max_limit` conditions are present and `limit` is absent or non-numeric, the condition should not match (i.e., return `False`):

```python
limit_val = params.get("limit")
has_limit_condition = "max_limit" in conditions or "min_limit" in conditions
if has_limit_condition:
    if limit_val is None or not isinstance(limit_val, (int, float)) or isinstance(limit_val, bool):
        return False  # Fail closed — required limit condition cannot be evaluated
    if "max_limit" in conditions and limit_val > conditions["max_limit"]:
        return False
    if "min_limit" in conditions and limit_val < conditions["min_limit"]:
        return False
```

---

### FINDING M2-M-04 — Nested Dict / List Values in Parameters Are Not Redacted in Audit Summary

**Severity: MEDIUM**  
**Category: Nested Secret Leakage in Audit Serialization**  
**File:** [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L364-L368) — parameter redaction in `evaluate()`

**Description:**  
The parameter summary redaction is a simple flat key-substring filter:

```python
param_summary = {
    k: v for k, v in params.items()
    if not any(s in k.lower() for s in ("password", "secret", "token", "key"))
}
```

This only redacts top-level keys whose names contain the listed substrings. It does not handle:

1. **Nested dictionaries:** A parameter `parameters={"auth": {"api_key": "sk-secret"}}` passes the top-level key filter (`"auth"` does not contain a sensitive word), and `{"api_key": "sk-secret"}` is emitted verbatim into the audit summary.
2. **Secret values in innocuous keys:** A parameter `parameters={"query": "password=hunter2"}` passes the key filter and emits the secret in the value.
3. **List values containing nested dicts with secrets:** `parameters={"headers": [{"Authorization": "Bearer tok_secret"}]}` will pass through fully.
4. **Exact-case bypass:** Keys like `"API_KEY"`, `"Token"`, and `"SECRET_VALUE"` are caught (`.lower()` applied), but keys like `"bearer"` or `"credential"` are not in the filter and pass through.

**Reproduction Steps:**

```python
req = PolicyEvaluationRequest(
    agent_context=TrustedAgentContext(agent_id="agent_sales_1"),
    tool_name="search_customer_records",
    action="search",
    resource="crm:customers",
    parameters={
        "query": "Acme",
        "limit": 10,
        "auth": {"api_key": "sk-prod-secret-9876"},          # Nested secret leaks
        "headers": [{"Authorization": "Bearer tok_secret"}], # List-nested secret leaks
        "credential": "my_credential_value",                  # Key not in redact list
    },
)
dec = engine.evaluate(req)
audit = dec.to_dict()
# audit["evaluated_parameters_summary"]["auth"]["api_key"] == "sk-prod-secret-9876"  (leaked)
# audit["evaluated_parameters_summary"]["headers"][0]["Authorization"] == "Bearer tok_secret"  (leaked)
# audit["evaluated_parameters_summary"]["credential"] == "my_credential_value"  (leaked)
```

**Recommended Fix:**  
Implement a recursive sanitization function that walks nested dicts and lists, redacting values at any depth whose key matches the sensitive keyword set. Additionally expand the keyword set to include `"auth"`, `"authorization"`, `"credential"`, `"bearer"`, and `"private"`. Values that are non-scalar (nested dicts/lists) should be replaced with a placeholder (e.g. `"[REDACTED-NESTED]"`) or recursively filtered:

```python
_SENSITIVE_KEY_SUBSTRINGS = frozenset(
    ("password", "secret", "token", "key", "auth", "credential", "bearer", "private")
)

def _sanitize_params(obj, depth=0):
    if depth > 5:
        return "[REDACTED-DEPTH]"
    if isinstance(obj, dict):
        return {
            k: "[REDACTED]" if any(s in k.lower() for s in _SENSITIVE_KEY_SUBSTRINGS)
               else _sanitize_params(v, depth + 1)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_sanitize_params(item, depth + 1) for item in obj]
    return obj
```

---

### FINDING M2-L-01 — `TrustedAgentContext` Can Be Constructed Freely by Any In-Process Code

**Severity: LOW** *(by scope — boundary is deferred to M3)*  
**Category: Trusted Identity Construction**  
**File:** [`backend/app/crm_repository.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/crm_repository.py#L23-L37)

**Description:**  
`TrustedAgentContext` is documented as "instantiated only by verified backend authentication" but is a standard frozen dataclass with no construction guard. Any Python code within the same process — including tests, scripts, notebook cells, or a future MCP handler — can instantiate one with any `agent_id` and `is_admin=True`:

```python
spoofed = TrustedAgentContext(agent_id="admin_service", is_admin=True)
```

The docstring is the only barrier. This is acceptable while M3 (bearer token verification) is not implemented, as the import boundary is the boundary of trust. However, the risk is that the absence of a construction guard makes it very easy for future Milestone 3 code to accidentally construct a `TrustedAgentContext` before or without token verification.

**Risk (pre-M3):** Low — the boundary is correct in concept; there is no network-exposed path yet.  
**Risk (at M3 integration):** High if the MCP handler constructs `TrustedAgentContext` before token verification completes, or reuses one from an unauthenticated code path.

**Recommended Fix:**  
Prior to M3 integration, add a module-private factory function in the authentication module that is the sole construction point, and document that direct instantiation from outside that module is prohibited. Consider adding a construction-time marker (e.g. a private sentinel argument or a `__init_subclass__` guard) that cannot be satisfied accidentally.

---

### FINDING M2-L-02 — `PolicyRule` Does Not Validate List Item Types

**Severity: LOW**  
**Category: Malformed Policy Conditions**  
**File:** [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L124-L133) — `__post_init__`

**Description:**  
`__post_init__` checks that `target_agents`, `target_tools`, `target_actions`, and `target_resources` are instances of `list`, but does not validate that all items within those lists are strings. A rule constructed with `target_agents=[None, 123, True]` passes validation but causes silent evaluation errors when compared against `agent_id` during matching, potentially producing incorrect silent non-matches rather than explicit errors.

```python
rule = PolicyRule(
    policy_id="BAD-AGENTS",
    name="Bad",
    description="bad agents list",
    outcome=PolicyOutcome.ALLOW,
    target_agents=[None, 123],  # Passes __post_init__ silently
    target_tools=["some_tool"],
)
# engine.add_policy(rule) succeeds
# _matches_agent → agent_id in [None, 123] → False, silently fails to match
# No error raised; behaviorally wrong
```

Conditions dict values are also unvalidated — a condition like `{"max_limit": "high"}` (string instead of numeric) will cause the numeric comparison `limit_val > "high"` to raise a `TypeError` at evaluation time, crashing the evaluation unhandled.

**Recommended Fix:**  
In `__post_init__`, validate that all items in the target lists are strings, and that `min_limit`/`max_limit` condition values (if present) are numeric. Raise `TypeError` or `ValueError` immediately at rule construction time rather than at evaluation time.

---

### FINDING M2-L-03 — Concurrency: `PolicyEngine` State Is Not Thread-Safe

**Severity: LOW** *(single-threaded for M2; relevant at M3)*  
**Category: Concurrency and Deterministic Policy Evaluation**  
**File:** [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L254-L266) — `PolicyEngine._rules`

**Description:**  
`PolicyEngine._rules` is a plain `dict`. Concurrent operations (`add_policy`, `remove_policy`, `set_policy_enabled`, `evaluate`, `reset_to_defaults`) from multiple threads (e.g. multiple concurrent MCP HTTP requests in Milestone 3's asyncio or multi-threaded ASGI server) can produce races:

- **Race 1:** `evaluate` iterates `self._rules.values()` while `add_policy` or `remove_policy` mutates the dict simultaneously → `RuntimeError: dictionary changed size during iteration` in CPython.
- **Race 2:** `set_policy_enabled` reads and writes `rule.enabled` on the mutable `PolicyRule` object while `evaluate` reads it → torn read (non-atomic in multi-threaded scenarios without GIL guarantee across two ops).
- **Race 3:** `reset_to_defaults` clears the dict then re-populates it; concurrent `evaluate` calls during the gap see an empty registry and return `DENY` for all requests — this is fail-closed but causes a brief service disruption window.

For the current single-threaded Python test environment this is safe. It becomes a correctness and reliability concern the moment M3 uses an ASGI framework with a thread pool or multiple workers.

**Recommended Fix:**  
Protect `_rules` mutations with a `threading.RLock`. Alternatively, adopt an immutable swap pattern: build a new rules dict and atomically replace `self._rules` as a single assignment (which is atomic in CPython due to the GIL, though still not safe across non-CPython runtimes). Document the threading guarantee explicitly in the class docstring.

---

### FINDING M2-L-04 — `parameters` Field Is Not Validated for Depth or Size

**Severity: LOW**  
**Category: Malformed Policy Conditions / Denial of Service**  
**File:** [`backend/app/policy_engine.py`](file:///c:/Users/nunna/Desktop/GURDAI1/backend/app/policy_engine.py#L362-L368)

**Description:**  
The `parameters` dict accepted in `PolicyEvaluationRequest` and processed during `evaluate()` has no size, depth, or type bounds. An adversary who can submit requests to the policy engine (e.g., through the M3 MCP gateway) can send:

- **Deeply nested dict:** `parameters={"a": {"b": {"c": {"d": ...}}}}` — no nesting limit → stack overflow or excessive recursion when any recursive sanitizer is added.
- **Very large dict:** `parameters={str(i): "x" * 10_000 for i in range(100_000)}` — unbounded memory allocation into `param_summary`.
- **Large string values:** `parameters={"query": "A" * 10_000_000}` — the full value is copied into the audit summary and potentially into the audit database row.

Currently `param_summary` is copied from `params` with only key-name redaction, making the full parameters dict size proportional to the allocation in every audit record.

**Recommended Fix:**  
Validate at the `evaluate()` entry point that `params` has at most a configured maximum number of keys (e.g. 50), that string values do not exceed a configured maximum length (e.g. 1 KB), and that nesting depth does not exceed a configured maximum (e.g. 3). Truncate oversized values with a marker such as `"[TRUNCATED]"`.

---

## Test Gap Summary

The following scenarios are **not currently covered** in `tests/test_policy_engine.py`:

| Gap | Description | Recommended Test |
|---|---|---|
| **T-GAP-01** | Resource prefix bypass (`crm2:hr` matches `crm:*` rule) | Test `_matches_resource` with adjacent-prefix resources |
| **T-GAP-02** | Missing `limit` parameter bypasses limit conditions | Test export/search with no `limit` key in `parameters` |
| **T-GAP-03** | Nested dict with secrets passes audit redaction | Test `parameters={"auth": {"api_key": "s"}}` |
| **T-GAP-04** | External mutation of live rule via `get_policy()` reference | Assert rule outcome unchanged after external mutation attempt |
| **T-GAP-05** | Rule list items are non-string types | Assert `PolicyRule` raises on `target_agents=[None, 123]` |
| **T-GAP-06** | Condition numeric type error at evaluation time | Test rule with `{"max_limit": "high"}` |
| **T-GAP-07** | `admin` can call `execute_shell` via dangerous-tool deny workaround | Confirm `POL-DANGEROUS-TOOLS-DENY` applies to admin at priority 1 |
| **T-GAP-08** | `parameters` without `limit` matching limit-conditioned approval rule | Verify REQUIRE_APPROVAL is returned, not unexpected ALLOW |

> [!NOTE]
> T-GAP-07: The test `test_explicit_deny` already verifies this for `run_raw_sql`. The same should be verified explicitly for `execute_shell` with the admin context.

---

## Security Invariant Verification

| Invariant (from SECURITY_RULES.md) | Status |
|---|---|
| Never trust `agent_id` from tool arguments | ✅ Verified — `_matches_agent` uses `agent_context.agent_id` only |
| LLM cannot change policy or approve actions | ✅ Verified — zero external calls in `policy_engine.py` |
| Missing policy defaults to DENY | ✅ Verified — fail-closed `return PolicyDecision(DENY, ...)` with `policy_id=None` |
| Hard permission violation remains DENY regardless of risk score | ✅ Verified — `POL-DANGEROUS-TOOLS-DENY` priority=1 tested against admin |
| Denied / approval-pending never executes protected tool | ✅ Verified — `test_no_protected_crm_execution_during_policy_evaluation` counter check |
| Secret values excluded from logs | ⚠️ Partial — flat key redaction only; nested values leak (M2-M-04) |
| Fail closed if authorization cannot be established | ✅ Verified — untrusted context → DENY with CRITICAL risk |
| `PolicyRule` external mutation safety | ❌ Not enforced — mutable dataclass with live references returned (M2-H-01) |

---

## M2 Approval Recommendation

**Recommendation: CONDITIONAL APPROVAL**

Milestone 2 delivers a correct deterministic engine and passes all security invariants within the in-process single-threaded evaluation scope. It is safe to proceed to Milestone 3 architecture design **provided the following blocking items are fixed before the first MCP gateway endpoint accepts external requests:**

| ID | Item | Must-Fix Before |
|---|---|---|
| M2-H-01 | Freeze or deep-copy `PolicyRule` to prevent external mutation | M3 gateway integration |
| M2-M-01 | Fix resource wildcard prefix slice `[:-2]` → `[:-1]` | M3 gateway integration |
| M2-M-02 | Remove or document the hardcoded `crm`/`crm:customers` equivalence | M3 gateway integration |
| M2-M-03 | Fail closed when `limit` is absent but limit condition exists | M3 gateway integration |
| M2-M-04 | Implement recursive audit parameter sanitization | M3 gateway integration |
| M2-L-03 | Add `threading.RLock` to `PolicyEngine` before ASGI deployment | M3 ASGI server deployment |

The Low findings (M2-L-01, M2-L-02, M2-L-04) are deferred but should be addressed before the public deployment milestone.
