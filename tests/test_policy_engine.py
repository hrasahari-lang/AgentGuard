"""Automated Unit Tests for AgentGuard Milestone 2: Deterministic Policy Engine.

Covers all Milestone 2 requirements:
- Explicit ALLOW decisions
- Explicit DENY decisions
- REQUIRE_APPROVAL decisions
- Default fail-closed DENY when no policy matches
- Deterministic policy precedence (priority, deny-overrides, specificity, lexical sort)
- Dynamic policy enabling and disabling
- Agent identity isolation & prevention of argument-based spoofing
- Resource-level scope restrictions
- Unknown tools and actions
- Missing or untrusted agent contexts (fail-closed)
- Malformed policy definitions validation
- Deterministic repeated evaluation
- Absence of protected tool execution during policy evaluation
"""
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError

from backend.app.crm_repository import TrustedAgentContext
from backend.app.policy_engine import (
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluationRequest,
    PolicyOutcome,
    PolicyRule,
    RiskLevel,
    get_default_policies,
)


class TestPolicyEngineMilestone2(unittest.TestCase):
    """Test suite covering the deterministic policy engine."""

    def setUp(self):
        self.engine = PolicyEngine(load_defaults=True)
        self.agent_sales_1 = TrustedAgentContext(agent_id="agent_sales_1")
        self.agent_sales_2 = TrustedAgentContext(agent_id="agent_sales_2")
        self.admin_agent = TrustedAgentContext(agent_id="admin_service", is_admin=True)

    # 1. Explicit allow
    def test_explicit_allow(self):
        """Verify authorized requests explicitly match ALLOW policies."""
        # Standard customer search within allowed limit (10 <= 50)
        req_search = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={"query": "Acme", "limit": 10},
        )
        dec_search = self.engine.evaluate(req_search)
        self.assertEqual(dec_search.outcome, PolicyOutcome.ALLOW)
        self.assertTrue(dec_search.allowed)
        self.assertFalse(dec_search.denied)
        self.assertFalse(dec_search.requires_approval)
        self.assertEqual(dec_search.policy_id, "POL-SALES-SEARCH-ALLOW")
        self.assertEqual(dec_search.risk_level, RiskLevel.LOW)

        # Single customer record lookup
        req_lookup = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="get_customer_by_id",
            action="read",
            resource="crm:customers",
            parameters={"customer_id": "CUST-101"},
        )
        dec_lookup = self.engine.evaluate(req_lookup)
        self.assertEqual(dec_lookup.outcome, PolicyOutcome.ALLOW)
        self.assertTrue(dec_lookup.allowed)
        self.assertEqual(dec_lookup.policy_id, "POL-SALES-LOOKUP-ALLOW")

        # Administrator full access across tools
        req_admin = PolicyEvaluationRequest(
            agent_context=self.admin_agent,
            tool_name="export_customer_records",
            action="export",
            resource="crm:customers",
            parameters={"format": "csv", "limit": 500},
        )
        dec_admin = self.engine.evaluate(req_admin)
        self.assertEqual(dec_admin.outcome, PolicyOutcome.ALLOW)
        self.assertTrue(dec_admin.allowed)
        self.assertEqual(dec_admin.policy_id, "POL-ADMIN-FULL-ACCESS")

    # 2. Explicit deny
    def test_explicit_deny(self):
        """Verify explicitly forbidden tools and exceeded thresholds return DENY."""
        # Dangerous system tool (execute_shell) blocked by high-priority DENY
        req_danger = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="execute_shell",
            action="execute",
            resource="system",
            parameters={"command": "rm -rf /"},
        )
        dec_danger = self.engine.evaluate(req_danger)
        self.assertEqual(dec_danger.outcome, PolicyOutcome.DENY)
        self.assertTrue(dec_danger.denied)
        self.assertFalse(dec_danger.allowed)
        self.assertEqual(dec_danger.policy_id, "POL-DANGEROUS-TOOLS-DENY")
        self.assertEqual(dec_danger.risk_level, RiskLevel.CRITICAL)

        # Admin attempting dangerous tool is still denied (security invariant)
        req_admin_danger = PolicyEvaluationRequest(
            agent_context=self.admin_agent,
            tool_name="run_raw_sql",
            action="execute",
            resource="database",
            parameters={"sql": "DROP TABLE customers;"},
        )
        dec_admin_danger = self.engine.evaluate(req_admin_danger)
        self.assertEqual(dec_admin_danger.outcome, PolicyOutcome.DENY)
        self.assertEqual(dec_admin_danger.policy_id, "POL-DANGEROUS-TOOLS-DENY")

        # Bulk export exceeding 100 records for sales agent is explicitly denied
        req_bulk_export = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="export_customer_records",
            action="export",
            resource="crm:customers",
            parameters={"format": "json", "limit": 250},
        )
        dec_bulk_export = self.engine.evaluate(req_bulk_export)
        self.assertEqual(dec_bulk_export.outcome, PolicyOutcome.DENY)
        self.assertTrue(dec_bulk_export.denied)
        self.assertEqual(dec_bulk_export.policy_id, "POL-SALES-EXPORT-BULK-DENY")
        self.assertEqual(dec_bulk_export.risk_level, RiskLevel.CRITICAL)

    # 3. Require approval
    def test_require_approval(self):
        """Verify operations requiring human intervention return REQUIRE_APPROVAL."""
        # Sensitive export operation within allowed limit (1 <= limit <= 100)
        req_export = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="export_customer_records",
            action="export",
            resource="crm:customers",
            parameters={"format": "json", "limit": 50},
        )
        dec_export = self.engine.evaluate(req_export)
        self.assertEqual(dec_export.outcome, PolicyOutcome.REQUIRE_APPROVAL)
        self.assertTrue(dec_export.requires_approval)
        self.assertFalse(dec_export.allowed)
        self.assertFalse(dec_export.denied)
        self.assertEqual(dec_export.policy_id, "POL-SALES-EXPORT-APPROVAL")
        self.assertEqual(dec_export.risk_level, RiskLevel.HIGH)

        # Bulk search exceeding 50 records (51 to 100)
        req_search_bulk = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={"query": "example", "limit": 75},
        )
        dec_search_bulk = self.engine.evaluate(req_search_bulk)
        self.assertEqual(dec_search_bulk.outcome, PolicyOutcome.REQUIRE_APPROVAL)
        self.assertTrue(dec_search_bulk.requires_approval)
        self.assertEqual(dec_search_bulk.policy_id, "POL-SALES-SEARCH-BULK-APPROVAL")
        self.assertEqual(dec_search_bulk.risk_level, RiskLevel.MEDIUM)

    # 4. No matching policy (fail closed)
    def test_no_matching_policy(self):
        """Verify requests with no matching policy fail closed to DENY."""
        # Unregistered agent identity
        unregistered_agent = TrustedAgentContext(agent_id="agent_unregistered_999")
        req_unregistered = PolicyEvaluationRequest(
            agent_context=unregistered_agent,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={"query": "Acme", "limit": 10},
        )
        dec_unregistered = self.engine.evaluate(req_unregistered)
        self.assertEqual(dec_unregistered.outcome, PolicyOutcome.DENY)
        self.assertTrue(dec_unregistered.denied)
        self.assertIsNone(dec_unregistered.policy_id)
        self.assertIn("fail-closed", dec_unregistered.reason)

        # Unregistered tool
        req_unknown_tool = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="unregistered_custom_tool",
            action="read",
            resource="crm:customers",
            parameters={},
        )
        dec_unknown_tool = self.engine.evaluate(req_unknown_tool)
        self.assertEqual(dec_unknown_tool.outcome, PolicyOutcome.DENY)
        self.assertTrue(dec_unknown_tool.denied)
        self.assertIsNone(dec_unknown_tool.policy_id)

    # 5. Conflicting policies and deterministic precedence
    def test_conflicting_policies_and_precedence(self):
        """Verify deterministic precedence: priority integer > deny-overrides > specificity > lexical tie-break."""
        custom_engine = PolicyEngine(load_defaults=False)

        # Case A: Priority integer precedence (lower integer = higher priority)
        rule_low_prio = PolicyRule(
            policy_id="RULE-ALLOW-PRIO-100",
            name="Allow at 100",
            description="Lower precedence allow",
            outcome=PolicyOutcome.ALLOW,
            priority=100,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )
        rule_high_prio = PolicyRule(
            policy_id="RULE-DENY-PRIO-50",
            name="Deny at 50",
            description="Higher precedence deny",
            outcome=PolicyOutcome.DENY,
            priority=50,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )
        custom_engine.add_policy(rule_low_prio)
        custom_engine.add_policy(rule_high_prio)

        req = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="test_tool",
            action="read",
            resource="crm:customers",
        )
        dec = custom_engine.evaluate(req)
        self.assertEqual(dec.policy_id, "RULE-DENY-PRIO-50")
        self.assertEqual(dec.outcome, PolicyOutcome.DENY)

        # Case B: Deny-overrides on same priority collision
        engine_collision = PolicyEngine(load_defaults=False)
        allow_rule = PolicyRule(
            policy_id="COLLIDE-ALLOW",
            name="Collide Allow",
            description="Allow at 100",
            outcome=PolicyOutcome.ALLOW,
            priority=100,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )
        deny_rule = PolicyRule(
            policy_id="COLLIDE-DENY",
            name="Collide Deny",
            description="Deny at 100",
            outcome=PolicyOutcome.DENY,
            priority=100,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )
        approval_rule = PolicyRule(
            policy_id="COLLIDE-APPROVAL",
            name="Collide Approval",
            description="Approval at 100",
            outcome=PolicyOutcome.REQUIRE_APPROVAL,
            priority=100,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )

        # DENY beats ALLOW
        engine_collision.add_policy(allow_rule)
        engine_collision.add_policy(deny_rule)
        dec_deny_override = engine_collision.evaluate(req)
        self.assertEqual(dec_deny_override.outcome, PolicyOutcome.DENY)
        self.assertEqual(dec_deny_override.policy_id, "COLLIDE-DENY")

        # REQUIRE_APPROVAL beats ALLOW
        engine_approval = PolicyEngine(load_defaults=False)
        engine_approval.add_policy(allow_rule)
        engine_approval.add_policy(approval_rule)
        dec_approval_override = engine_approval.evaluate(req)
        self.assertEqual(dec_approval_override.outcome, PolicyOutcome.REQUIRE_APPROVAL)
        self.assertEqual(dec_approval_override.policy_id, "COLLIDE-APPROVAL")

        # Case C: Specificity precedence (specific agent beats wildcard agent at same priority & outcome)
        engine_spec = PolicyEngine(load_defaults=False)
        wildcard_rule = PolicyRule(
            policy_id="WILDCARD-ALLOW",
            name="Wildcard Allow",
            description="Wildcard agent match",
            outcome=PolicyOutcome.ALLOW,
            priority=100,
            target_agents=["*"],
            target_tools=["test_tool"],
        )
        specific_rule = PolicyRule(
            policy_id="SPECIFIC-ALLOW",
            name="Specific Allow",
            description="Specific agent match",
            outcome=PolicyOutcome.ALLOW,
            priority=100,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )
        engine_spec.add_policy(wildcard_rule)
        engine_spec.add_policy(specific_rule)
        dec_spec = engine_spec.evaluate(req)
        self.assertEqual(dec_spec.policy_id, "SPECIFIC-ALLOW")

        # Case D: Lexical tie-break on identical priority, outcome, and specificity
        engine_lex = PolicyEngine(load_defaults=False)
        rule_z = PolicyRule(
            policy_id="RULE-ZZZ",
            name="ZZZ",
            description="Z rule",
            outcome=PolicyOutcome.ALLOW,
            priority=100,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )
        rule_a = PolicyRule(
            policy_id="RULE-AAA",
            name="AAA",
            description="A rule",
            outcome=PolicyOutcome.ALLOW,
            priority=100,
            target_agents=["agent_sales_1"],
            target_tools=["test_tool"],
        )
        engine_lex.add_policy(rule_z)
        engine_lex.add_policy(rule_a)
        dec_lex = engine_lex.evaluate(req)
        self.assertEqual(dec_lex.policy_id, "RULE-AAA")

    # 6. Disabled policies
    def test_disabled_policies(self):
        """Verify disabled policies are ignored during evaluation."""
        req = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={"query": "test", "limit": 10},
        )
        # Enabled baseline -> ALLOW
        dec_before = self.engine.evaluate(req)
        self.assertEqual(dec_before.outcome, PolicyOutcome.ALLOW)

        # Disable rule dynamically -> Fails closed to DENY (no other sales search rule matches limit=10)
        self.engine.set_policy_enabled("POL-SALES-SEARCH-ALLOW", False)
        dec_after = self.engine.evaluate(req)
        self.assertEqual(dec_after.outcome, PolicyOutcome.DENY)
        self.assertIsNone(dec_after.policy_id)

        # Re-enable rule -> Restores ALLOW
        self.engine.set_policy_enabled("POL-SALES-SEARCH-ALLOW", True)
        dec_restored = self.engine.evaluate(req)
        self.assertEqual(dec_restored.outcome, PolicyOutcome.ALLOW)

    # 7. Agent identity isolation & spoofing resistance
    def test_agent_identity_isolation(self):
        """Verify agent cannot access another agent's policy rules or spoof identity via parameters."""
        custom_engine = PolicyEngine(load_defaults=False)
        custom_engine.add_policy(
            PolicyRule(
                policy_id="AGENT-2-EXCLUSIVE",
                name="Agent 2 Exclusive",
                description="Allowed only for agent_sales_2",
                outcome=PolicyOutcome.ALLOW,
                priority=10,
                target_agents=["agent_sales_2"],
                target_tools=["exclusive_tool"],
            )
        )

        # agent_sales_1 is denied
        req_1 = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="exclusive_tool",
            action="read",
            resource="crm:customers",
        )
        dec_1 = custom_engine.evaluate(req_1)
        self.assertEqual(dec_1.outcome, PolicyOutcome.DENY)

        # agent_sales_2 is allowed
        req_2 = PolicyEvaluationRequest(
            agent_context=self.agent_sales_2,
            tool_name="exclusive_tool",
            action="read",
            resource="crm:customers",
        )
        dec_2 = custom_engine.evaluate(req_2)
        self.assertEqual(dec_2.outcome, PolicyOutcome.ALLOW)

        # Identity spoofing attempt: agent_sales_1 tries to pass agent_id="agent_sales_2" in arguments
        req_spoof = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="exclusive_tool",
            action="read",
            resource="crm:customers",
            parameters={"agent_id": "agent_sales_2", "is_admin": True, "role": "admin"},
        )
        dec_spoof = custom_engine.evaluate(req_spoof)
        self.assertEqual(
            dec_spoof.outcome,
            PolicyOutcome.DENY,
            "Security vulnerability: agent spoofed identity through tool arguments!"
        )

    # 8. Resource-level restrictions
    def test_resource_level_restrictions(self):
        """Verify policies enforce resource scope and reject mismatched resources."""
        custom_engine = PolicyEngine(load_defaults=False)
        custom_engine.add_policy(
            PolicyRule(
                policy_id="HR-ONLY-RULE",
                name="HR Only",
                description="Allowed only for HR resource",
                outcome=PolicyOutcome.ALLOW,
                priority=10,
                target_agents=["agent_sales_1"],
                target_tools=["search_tool"],
                target_resources=["hr:employees"],
            )
        )

        # Attempting to access CRM resource with HR rule
        req_crm = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_tool",
            action="read",
            resource="crm:customers",
        )
        dec_crm = custom_engine.evaluate(req_crm)
        self.assertEqual(dec_crm.outcome, PolicyOutcome.DENY)

        # Accessing exact resource succeeds
        req_hr = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_tool",
            action="read",
            resource="hr:employees",
        )
        dec_hr = custom_engine.evaluate(req_hr)
        self.assertEqual(dec_hr.outcome, PolicyOutcome.ALLOW)

    # 9. Unknown tools and actions
    def test_unknown_tools_and_actions(self):
        """Verify unknown or unconfigured actions fail closed without throwing unhandled errors."""
        req_unknown_action = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="unexpected_destroy_action",
            resource="crm:customers",
            parameters={"query": "test"},
        )
        dec = self.engine.evaluate(req_unknown_action)
        self.assertEqual(dec.outcome, PolicyOutcome.DENY)
        self.assertTrue(dec.denied)

    # 10. Missing or untrusted agent context
    def test_missing_or_untrusted_agent_context(self):
        """Verify missing, None, or untrusted agent contexts fail closed with critical risk."""
        # None context
        req_none = PolicyEvaluationRequest(
            agent_context=None,
            tool_name="search_customer_records",
        )
        dec_none = self.engine.evaluate(req_none)
        self.assertEqual(dec_none.outcome, PolicyOutcome.DENY)
        self.assertEqual(dec_none.risk_level, RiskLevel.CRITICAL)
        self.assertIn("Untrusted or missing agent context", dec_none.reason)

        # String context instead of TrustedAgentContext instance
        req_str = PolicyEvaluationRequest(
            agent_context="fake_agent_string",
            tool_name="search_customer_records",
        )
        dec_str = self.engine.evaluate(req_str)
        self.assertEqual(dec_str.outcome, PolicyOutcome.DENY)
        self.assertEqual(dec_str.risk_level, RiskLevel.CRITICAL)

        # Dict context
        req_dict = PolicyEvaluationRequest(
            agent_context={"agent_id": "admin_service", "is_admin": True},
            tool_name="search_customer_records",
        )
        dec_dict = self.engine.evaluate(req_dict)
        self.assertEqual(dec_dict.outcome, PolicyOutcome.DENY)
        self.assertEqual(dec_dict.risk_level, RiskLevel.CRITICAL)

        # Empty tool_name
        req_empty_tool = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="",
        )
        dec_empty_tool = self.engine.evaluate(req_empty_tool)
        self.assertEqual(dec_empty_tool.outcome, PolicyOutcome.DENY)
        self.assertEqual(dec_empty_tool.risk_level, RiskLevel.HIGH)

    # 11. Malformed policy definitions
    def test_malformed_policy_definitions(self):
        """Verify policy rule validation rejects invalid rule configurations."""
        # Empty policy_id
        with self.assertRaises(ValueError):
            PolicyRule(
                policy_id="",
                name="Invalid",
                description="test",
                outcome=PolicyOutcome.ALLOW,
            )

        # Invalid outcome
        with self.assertRaises(ValueError):
            PolicyRule(
                policy_id="TEST",
                name="Invalid",
                description="test",
                outcome="INVALID_OUTCOME_STRING",
            )

        # Invalid priority type (bool or str)
        with self.assertRaises(TypeError):
            PolicyRule(
                policy_id="TEST",
                name="Invalid",
                description="test",
                outcome=PolicyOutcome.ALLOW,
                priority="high",
            )

        # Invalid enabled type
        with self.assertRaises(TypeError):
            PolicyRule(
                policy_id="TEST",
                name="Invalid",
                description="test",
                outcome=PolicyOutcome.ALLOW,
                enabled="yes",
            )

        # Non-PolicyRule passed to add_policy
        with self.assertRaises(TypeError):
            self.engine.add_policy("not_a_policy_rule")

    # 12. Deterministic repeated evaluation
    def test_deterministic_repeated_evaluation(self):
        """Verify evaluating the exact same request 100 times returns identical results."""
        req = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={"query": "BioPulse", "limit": 25},
        )
        initial_decision = self.engine.evaluate(req)

        for _ in range(100):
            repeated = self.engine.evaluate(req)
            self.assertEqual(repeated.outcome, initial_decision.outcome)
            self.assertEqual(repeated.policy_id, initial_decision.policy_id)
            self.assertEqual(repeated.rule_name, initial_decision.rule_name)
            self.assertEqual(repeated.reason, initial_decision.reason)
            self.assertEqual(repeated.risk_level, initial_decision.risk_level)
            self.assertEqual(repeated.allowed, initial_decision.allowed)
            self.assertEqual(repeated.denied, initial_decision.denied)
            self.assertEqual(repeated.requires_approval, initial_decision.requires_approval)

    def test_policy_registry_concurrent_evaluation_and_updates(self):
        request = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={"query": "Acme", "limit": 10},
        )

        def evaluate_many(_):
            return [self.engine.evaluate(request).outcome for _ in range(80)]

        def update_many(_):
            for index in range(80):
                self.engine.set_policy_enabled("POL-SALES-SEARCH-ALLOW", index % 2 == 0)
                transient = PolicyRule(
                    policy_id=f"TRANSIENT-{index}", name="Transient", description="concurrency test",
                    outcome=PolicyOutcome.DENY, target_agents=["other_agent"],
                    target_tools=["unrelated_tool"], target_resources=["other:resource"],
                )
                self.engine.add_policy(transient)
                self.engine.remove_policy(transient.policy_id)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(evaluate_many, index) for index in range(5)]
            futures.append(pool.submit(update_many, 0))
            results = [future.result() for future in futures]

        self.assertTrue(all(outcome in {PolicyOutcome.ALLOW, PolicyOutcome.DENY} for group in results[:-1] for outcome in group))

    # 13. Audit serialization
    def test_decision_audit_serialization(self):
        """Verify PolicyDecision to_dict produces clean audit dictionary with redacted secrets."""
        req = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={"query": "Acme", "limit": 10, "api_key": "secret_123"},
        )
        dec = self.engine.evaluate(req)
        audit_dict = dec.to_dict()
        self.assertIn("outcome", audit_dict)
        self.assertIn("policy_id", audit_dict)
        self.assertIn("agent_id", audit_dict)
        self.assertIn("evaluated_parameters_summary", audit_dict)
        # Verify secret key was redacted from parameter summary
        self.assertNotIn("api_key", audit_dict["evaluated_parameters_summary"])


    # 14. Decoupling: Zero CRM invocation during policy evaluation
    def test_no_protected_crm_execution_during_policy_evaluation(self):
        """Verify policy evaluation NEVER invokes protected CRM tools or increments counters."""
        import tempfile
        from pathlib import Path
        from backend.app.database import init_db
        from backend.app.crm_repository import get_total_invocations

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_policy_isolation.db"
            init_db(db_path)
            start_count = get_total_invocations(db_path, "crm")
            self.assertEqual(start_count, 0)

            # Evaluate ALLOW
            req_allow = PolicyEvaluationRequest(
                agent_context=self.agent_sales_1,
                tool_name="search_customer_records",
                action="search",
                resource="crm:customers",
                parameters={"query": "test", "limit": 10},
            )
            dec_allow = self.engine.evaluate(req_allow)
            self.assertEqual(dec_allow.outcome, PolicyOutcome.ALLOW)

            # Evaluate REQUIRE_APPROVAL
            req_approval = PolicyEvaluationRequest(
                agent_context=self.agent_sales_1,
                tool_name="export_customer_records",
                action="export",
                resource="crm:customers",
                parameters={"format": "json", "limit": 50},
            )
            dec_approval = self.engine.evaluate(req_approval)
            self.assertEqual(dec_approval.outcome, PolicyOutcome.REQUIRE_APPROVAL)

            # Evaluate DENY
            req_deny = PolicyEvaluationRequest(
                agent_context=self.agent_sales_1,
                tool_name="execute_shell",
                action="execute",
                resource="system",
            )
            dec_deny = self.engine.evaluate(req_deny)
            self.assertEqual(dec_deny.outcome, PolicyOutcome.DENY)

            # Invocation counter MUST remain exactly 0
            end_count = get_total_invocations(db_path, "crm")
            self.assertEqual(
                end_count,
                0,
                "Security violation: Policy engine invoked protected CRM operations or touched counters!"
            )

    # 15. Regression: M2-H-01 Immutable Policy Rules & Defensive Copies
    def test_finding_m2_h01_immutable_policy_rules_and_defensive_copies(self):
        """M2-H-01: Verify PolicyRule is frozen and engine returns independent deep copies."""
        rule = self.engine.get_policy("POL-SALES-SEARCH-ALLOW")
        self.assertIsNotNone(rule)

        # 1. Direct mutation of frozen PolicyRule raises FrozenInstanceError (AttributeError)
        with self.assertRaises(FrozenInstanceError):
            rule.outcome = PolicyOutcome.DENY  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            rule.enabled = False  # type: ignore

        # 2. Nested containers are immutable on the rule itself.
        with self.assertRaises(AttributeError):
            rule.target_agents.append("malicious_agent_override")
        with self.assertRaises(TypeError):
            rule.conditions["max_limit"] = 999999

        # Re-fetch from engine: internal rule remains unmodified
        fresh_rule = self.engine.get_policy("POL-SALES-SEARCH-ALLOW")
        self.assertNotIn("malicious_agent_override", fresh_rule.target_agents)
        self.assertEqual(fresh_rule.conditions.get("max_limit"), 50)

        # Evaluation for malicious agent still fails closed
        malicious_ctx = TrustedAgentContext(agent_id="malicious_agent_override")
        req_malicious = PolicyEvaluationRequest(
            agent_context=malicious_ctx,
            tool_name="search_customer_records",
            parameters={"query": "test", "limit": 10},
        )
        dec_malicious = self.engine.evaluate(req_malicious)
        self.assertEqual(dec_malicious.outcome, PolicyOutcome.DENY)

        # 3. Post-registration mutation on original passed rule does not affect engine
        custom_engine = PolicyEngine(load_defaults=False)
        agent_list = ["agent_sales_1"]
        conds = {"max_limit": 20}
        custom_rule = PolicyRule(
            policy_id="MUTABLE-TEST",
            name="Mutable Test",
            description="Testing post-add mutation",
            outcome=PolicyOutcome.ALLOW,
            target_agents=agent_list,
            target_tools=["test_tool"],
            conditions=conds,
        )
        custom_engine.add_policy(custom_rule)

        # Mutate the original inputs after registration
        agent_list.append("spoofed_agent")
        conds["max_limit"] = 1000

        stored = custom_engine.get_policy("MUTABLE-TEST")
        self.assertNotIn("spoofed_agent", stored.target_agents)
        self.assertEqual(stored.conditions["max_limit"], 20)

        # 4. list_policies returns independent copies
        listed = custom_engine.list_policies()
        with self.assertRaises(AttributeError):
            listed[0].target_agents.append("another_tamper")
        stored_again = custom_engine.get_policy("MUTABLE-TEST")
        self.assertNotIn("another_tamper", stored_again.target_agents)

    def test_malformed_action_resource_and_parameters_fail_closed(self):
        for kwargs in (
            {"action": {"name": "read"}},
            {"resource": ["crm:customers"]},
            {"resource": "   "},
            {"resource": "*"},
            {"resource": "crm: customers"},
            {"action": " "},
            {"action": "read*"},
            {"parameters": ["limit", 10]},
        ):
            request = PolicyEvaluationRequest(
                agent_context=self.admin_agent,
                tool_name="search_customer_records",
                **kwargs,
            )
            decision = self.engine.evaluate(request)
            self.assertEqual(decision.outcome, PolicyOutcome.DENY, kwargs)
            self.assertIsNone(decision.policy_id, kwargs)

    def test_policy_condition_schema_is_validated(self):
        invalid_conditions = (
            ({"max_limit": "high"}, TypeError),
            ({"min_limit": 10, "max_limit": 5}, ValueError),
            ({"allowed_formats": "csv"}, TypeError),
            ({"allowed_formats": ["csv", 3]}, TypeError),
            ({"exact_parameters": []}, TypeError),
            ({"parameter_prefix": {"customer_id": 42}}, TypeError),
            ({"unrecognized_condition": True}, ValueError),
            ({"max_limit": float("nan")}, TypeError),
            ({"exact_parameters": {"value": object()}}, TypeError),
        )
        for conditions, error_type in invalid_conditions:
            with self.subTest(conditions=conditions), self.assertRaises(error_type):
                PolicyRule(
                    policy_id="INVALID-CONDITION", name="Invalid", description="test",
                    outcome=PolicyOutcome.ALLOW, conditions=conditions,
                )

        mutable_prefix = {"customer_id": "CUST-"}
        rule = PolicyRule(
            policy_id="NESTED-CONDITION", name="Nested", description="test",
            outcome=PolicyOutcome.ALLOW,
            conditions={"parameter_prefix": mutable_prefix},
        )
        mutable_prefix["customer_id"] = "ATTACKER-"
        self.assertEqual(rule.conditions["parameter_prefix"]["customer_id"], "CUST-")
        with self.assertRaises(TypeError):
            rule.conditions["parameter_prefix"]["customer_id"] = "ATTACKER-"

    def test_audit_serialization_returns_detached_summary(self):
        request = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "Acme", "limit": 10, "nested": {"items": ["safe"]}},
        )
        decision = self.engine.evaluate(request)
        serialized = decision.to_dict()
        serialized["evaluated_parameters_summary"]["nested"]["items"][0] = "tampered"
        self.assertEqual(
            decision.evaluated_parameters_summary["nested"]["items"][0], "safe"
        )

    def test_inline_secret_values_are_redacted(self):
        request = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={
                "note": "operator used password=hunter2 and api_key:sk-live-123",
                "header": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
            },
        )
        summary = self.engine.evaluate(request).to_dict()["evaluated_parameters_summary"]
        self.assertNotIn("hunter2", str(summary))
        self.assertNotIn("sk-live-123", str(summary))
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", str(summary))

    # 16. Regression: M2-M-01 Resource Wildcard Boundary
    def test_finding_m2_m01_resource_wildcard_boundary(self):
        """M2-M-01: Verify 'crm:*' matches 'crm:customers' but NEVER 'crmX:secret' or 'crm2:data'."""
        engine = PolicyEngine(load_defaults=False)
        engine.add_policy(
            PolicyRule(
                policy_id="CRM-WILDCARD-RULE",
                name="CRM Wildcard",
                description="Allow crm:* namespace resources",
                outcome=PolicyOutcome.ALLOW,
                priority=10,
                target_agents=["agent_sales_1"],
                target_tools=["query_tool"],
                target_resources=["crm:*"],
            )
        )

        # Allowed sub-resources in crm: namespace
        for valid_res in ["crm:customers", "crm:orders", "crm:invoices", "crm:customers:active"]:
            req = PolicyEvaluationRequest(
                agent_context=self.agent_sales_1,
                tool_name="query_tool",
                resource=valid_res,
            )
            dec = engine.evaluate(req)
            self.assertEqual(dec.outcome, PolicyOutcome.ALLOW, f"Expected ALLOW for {valid_res}")

        # Blocked adjacent resources that merely share 'crm' prefix without colon separator
        for invalid_res in ["crmX:secret", "crm2:hr_data", "crm_backup:secrets", "crm_internal", "crmextra"]:
            req = PolicyEvaluationRequest(
                agent_context=self.agent_sales_1,
                tool_name="query_tool",
                resource=invalid_res,
            )
            dec = engine.evaluate(req)
            self.assertEqual(dec.outcome, PolicyOutcome.DENY, f"Expected DENY for {invalid_res}")

    # 17. Regression: M2-M-02 Explicit Resource Scoping (No Implicit Cross-Resource Aliasing)
    def test_finding_m2_m02_explicit_resource_scoping_no_implicit_alias(self):
        """M2-M-02: Verify no automatic aliasing between 'crm' root and 'crm:customers'."""
        engine = PolicyEngine(load_defaults=False)

        # Rule 1: Targets ONLY "crm" root namespace
        engine.add_policy(
            PolicyRule(
                policy_id="CRM-ROOT-ONLY",
                name="CRM Root Only",
                description="Allows only crm root",
                outcome=PolicyOutcome.ALLOW,
                priority=10,
                target_agents=["agent_sales_1"],
                target_tools=["query_tool"],
                target_resources=["crm"],
            )
        )

        # Root "crm" succeeds
        req_root = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="query_tool",
            resource="crm",
        )
        self.assertEqual(engine.evaluate(req_root).outcome, PolicyOutcome.ALLOW)

        # Sub-resource "crm:customers" must NOT match "crm" root rule (no implicit widening)
        req_sub = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="query_tool",
            resource="crm:customers",
        )
        self.assertEqual(engine.evaluate(req_sub).outcome, PolicyOutcome.DENY)

        # Rule 2: Targets ONLY "crm:customers" sub-resource
        engine_sub = PolicyEngine(load_defaults=False)
        engine_sub.add_policy(
            PolicyRule(
                policy_id="CRM-SUB-ONLY",
                name="CRM Customers Sub-Resource Only",
                description="Allows only crm:customers",
                outcome=PolicyOutcome.ALLOW,
                priority=10,
                target_agents=["agent_sales_1"],
                target_tools=["query_tool"],
                target_resources=["crm:customers"],
            )
        )

        # Sub-resource "crm:customers" succeeds
        self.assertEqual(engine_sub.evaluate(req_sub).outcome, PolicyOutcome.ALLOW)

        # Root "crm" must NOT match "crm:customers" rule (no reverse aliasing)
        self.assertEqual(engine_sub.evaluate(req_root).outcome, PolicyOutcome.DENY)

    # 18. Regression: M2-M-03 Limit Condition Fail-Closed
    def test_finding_m2_m03_limit_condition_fail_closed_on_missing_or_invalid_limit(self):
        """M2-M-03: Verify requests fail closed when limit condition exists but limit is missing/invalid."""
        engine = PolicyEngine(load_defaults=False)
        engine.add_policy(
            PolicyRule(
                policy_id="LIMITED-SEARCH-ALLOW",
                name="Limited Search",
                description="Allow search <= 50",
                outcome=PolicyOutcome.ALLOW,
                priority=10,
                target_agents=["agent_sales_1"],
                target_tools=["search_customer_records"],
                conditions={"max_limit": 50},
            )
        )

        # Missing limit parameter -> Fails closed to DENY (does not match rule)
        req_no_limit = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "test"},
        )
        dec_no_limit = engine.evaluate(req_no_limit)
        self.assertEqual(dec_no_limit.outcome, PolicyOutcome.DENY)

        # None limit -> DENY
        req_none_limit = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "test", "limit": None},
        )
        self.assertEqual(engine.evaluate(req_none_limit).outcome, PolicyOutcome.DENY)

        # String limit -> DENY
        req_str_limit = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "test", "limit": "50"},
        )
        self.assertEqual(engine.evaluate(req_str_limit).outcome, PolicyOutcome.DENY)

        # Boolean limit (True/False should not be treated as int 1/0) -> DENY
        req_bool_limit = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "test", "limit": True},
        )
        self.assertEqual(engine.evaluate(req_bool_limit).outcome, PolicyOutcome.DENY)

        # Valid limit <= 50 -> ALLOW
        req_valid_limit = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "test", "limit": 25},
        )
        self.assertEqual(engine.evaluate(req_valid_limit).outcome, PolicyOutcome.ALLOW)

        # Valid limit > 50 -> DENY
        req_exceeded = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "test", "limit": 75},
        )
        self.assertEqual(engine.evaluate(req_exceeded).outcome, PolicyOutcome.DENY)

    # 19. Regression: M2-M-04 Recursive Secret Redaction in Audit Summary
    def test_finding_m2_m04_recursive_audit_parameter_redaction(self):
        """M2-M-04: Verify recursive secret redaction across nested dictionaries and lists."""
        req = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            action="search",
            resource="crm:customers",
            parameters={
                "query": "Acme",
                "limit": 10,
                # Nested dict containing secret
                "connection": {
                    "host": "crm.internal",
                    "api_key": "sk-super-secret-key-1234",
                    "port": 5432,
                },
                # List containing nested dicts with secrets
                "headers": [
                    {"Content-Type": "application/json"},
                    {"Authorization": "Bearer secret_bearer_token"},
                ],
                # Top-level sensitive keyword variants
                "credential": "cred_secret_value",
                "bearer_token": "bearer_abc",
                "private_data": "private_xyz",
                "safe_field": "public_data",
            },
        )
        dec = self.engine.evaluate(req)
        audit = dec.to_dict()
        summary = audit["evaluated_parameters_summary"]

        # Safe values preserved
        self.assertEqual(summary["query"], "Acme")
        self.assertEqual(summary["limit"], 10)
        self.assertEqual(summary["safe_field"], "public_data")
        self.assertEqual(summary["connection"]["host"], "crm.internal")
        self.assertEqual(summary["connection"]["port"], 5432)
        self.assertEqual(summary["headers"][0]["Content-Type"], "application/json")

        # Nested dict secret omitted
        self.assertNotIn("api_key", summary["connection"])

        # List-nested secret omitted
        self.assertNotIn("Authorization", summary["headers"][1])

        # Sensitive keywords omitted
        self.assertNotIn("credential", summary)
        self.assertNotIn("bearer_token", summary)
        self.assertNotIn("private_data", summary)

        # Test depth bounding (> 5 levels)
        deep_dict = {"level1": {"level2": {"level3": {"level4": {"level5": {"level6": "too_deep"}}}}}}
        req_deep = PolicyEvaluationRequest(
            agent_context=self.agent_sales_1,
            tool_name="search_customer_records",
            parameters={"query": "test", "limit": 10, "data": deep_dict},
        )
        summary_deep = self.engine.evaluate(req_deep).to_dict()["evaluated_parameters_summary"]
        self.assertEqual(
            summary_deep["data"]["level1"]["level2"]["level3"]["level4"]["level5"],
            "[REDACTED-DEPTH]"
        )

    # 20. Regression: M2-L-02 Policy Rule List Item Validation
    def test_finding_m2_l02_policy_rule_list_item_type_validation(self):
        """M2-L-02: Verify PolicyRule rejects non-string items in target lists."""
        with self.assertRaises(TypeError):
            PolicyRule(
                policy_id="BAD-TARGET-AGENTS",
                name="Bad Agents",
                description="Testing non-string agent items",
                outcome=PolicyOutcome.ALLOW,
                target_agents=[None, 123],  # Non-string items
            )

        with self.assertRaises(TypeError):
            PolicyRule(
                policy_id="BAD-TARGET-TOOLS",
                name="Bad Tools",
                description="Testing non-string tool items",
                outcome=PolicyOutcome.ALLOW,
                target_tools=["tool_a", 456],  # Non-string item
            )


if __name__ == "__main__":
    unittest.main()
