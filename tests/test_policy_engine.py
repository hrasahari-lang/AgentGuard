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


if __name__ == "__main__":
    unittest.main()
