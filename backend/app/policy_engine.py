"""AgentGuard Deterministic Policy Engine.

Enforces deterministic, explainable, zero-trust authorization decisions:
- Supported outcomes: ALLOW, REQUIRE_APPROVAL, DENY
- Server-side identity: Enforces verified TrustedAgentContext (never trusts tool arguments)
- Explicit precedence: Priority integer -> Deny-overrides -> Specificity -> Lexical tie-break
- Fail-closed security: Missing, ambiguous, disabled, or malformed policies default to DENY
- Decoupled architecture: Pure authorization analysis; never executes protected CRM tools
"""
from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set, Union

from backend.app.crm_repository import TrustedAgentContext


class PolicyOutcome(str, Enum):
    """Deterministic policy authorization decision outcomes."""
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class RiskLevel(str, Enum):
    """Categorical risk assessment level for policy evaluation."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class PolicyEvaluationRequest:
    """Incoming request context submitted to the policy engine for evaluation.
    
    Security Invariant:
    Identity and administrative privileges are derived strictly from the verified
    agent_context. Any identity or role values passed inside 'parameters' are untrusted
    and ignored for authorization decisions.
    """
    agent_context: Any  # Validated at evaluation time to ensure fail-closed handling
    tool_name: str
    action: str = "read"
    resource: str = "crm:customers"
    parameters: Dict[str, Any] = field(default_factory=dict)
    client_request_id: Optional[str] = None


@dataclass(frozen=True)
class PolicyDecision:
    """Structured, immutable authorization decision returned by the policy engine."""
    outcome: PolicyOutcome
    allowed: bool
    requires_approval: bool
    denied: bool
    policy_id: Optional[str]
    rule_name: Optional[str]
    reason: str
    risk_level: RiskLevel
    agent_id: str
    tool_name: str
    action: str
    resource: str
    timestamp: float
    evaluated_parameters_summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize decision for persistent audit logging."""
        return {
            "outcome": self.outcome.value,
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "denied": self.denied,
            "policy_id": self.policy_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "risk_level": self.risk_level.value,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "action": self.action,
            "resource": self.resource,
            "timestamp": self.timestamp,
            "evaluated_parameters_summary": self.evaluated_parameters_summary,
        }


@dataclass
class PolicyRule:
    """Configurable, deterministic policy rule governing tool operations."""
    policy_id: str
    name: str
    description: str
    outcome: PolicyOutcome
    priority: int = 100  # Smaller integer = higher precedence (1 = highest)
    target_agents: List[str] = field(default_factory=lambda: ["*"])
    target_roles: List[str] = field(default_factory=list)
    target_tools: List[str] = field(default_factory=lambda: ["*"])
    target_actions: List[str] = field(default_factory=lambda: ["*"])
    target_resources: List[str] = field(default_factory=lambda: ["*"])
    conditions: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    enabled: bool = True

    def __post_init__(self):
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise ValueError("policy_id must be a non-empty string")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.outcome, PolicyOutcome):
            if isinstance(self.outcome, str) and self.outcome.upper() in PolicyOutcome.__members__:
                self.outcome = PolicyOutcome[self.outcome.upper()]
            else:
                raise ValueError(f"outcome must be a valid PolicyOutcome, got {self.outcome}")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool):
            raise TypeError("priority must be an integer")
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a boolean")
        if not isinstance(self.risk_level, RiskLevel):
            if isinstance(self.risk_level, str) and self.risk_level.upper() in RiskLevel.__members__:
                self.risk_level = RiskLevel[self.risk_level.upper()]
            else:
                self.risk_level = RiskLevel.LOW
        if not isinstance(self.target_agents, list):
            raise TypeError("target_agents must be a list of strings")
        if not isinstance(self.target_tools, list):
            raise TypeError("target_tools must be a list of strings")
        if not isinstance(self.target_actions, list):
            raise TypeError("target_actions must be a list of strings")
        if not isinstance(self.target_resources, list):
            raise TypeError("target_resources must be a list of strings")
        if not isinstance(self.conditions, dict):
            raise TypeError("conditions must be a dictionary")


def get_default_policies() -> List[PolicyRule]:
    """Return the baseline enterprise governance policies for AgentGuard CRM."""
    return [
        # 1. Dangerous tools: Highest priority explicit deny
        PolicyRule(
            policy_id="POL-DANGEROUS-TOOLS-DENY",
            name="Block Dangerous System Operations",
            description="Strictly forbid execution of shell, arbitrary SQL, or database destruction tools.",
            outcome=PolicyOutcome.DENY,
            priority=1,
            target_agents=["*"],
            target_tools=["execute_shell", "run_raw_sql", "delete_database", "drop_table", "bash"],
            target_actions=["*"],
            target_resources=["*"],
            risk_level=RiskLevel.CRITICAL,
            enabled=True,
        ),
        # 2. Administrator bypass: Full access across tools for verified admin agents
        PolicyRule(
            policy_id="POL-ADMIN-FULL-ACCESS",
            name="Administrator Full Access",
            description="Grants verified administrative agents full access across all CRM tools and operations.",
            outcome=PolicyOutcome.ALLOW,
            priority=10,
            target_agents=[],
            target_roles=["admin"],
            target_tools=["*"],
            target_actions=["*"],
            target_resources=["*"],
            risk_level=RiskLevel.LOW,
            enabled=True,
        ),
        # 3. Bulk export limit exceeded: Explicit deny for sales agents
        PolicyRule(
            policy_id="POL-SALES-EXPORT-BULK-DENY",
            name="Deny Bulk Customer Data Export",
            description="Denies customer record export requests exceeding 100 records for standard sales agents.",
            outcome=PolicyOutcome.DENY,
            priority=90,
            target_agents=["agent_sales_1", "agent_sales_2", "agent_sales_3"],
            target_tools=["export_customer_records"],
            target_actions=["export"],
            target_resources=["crm", "crm:customers"],
            conditions={"min_limit": 101},
            risk_level=RiskLevel.CRITICAL,
            enabled=True,
        ),
        # 4. Standard export: Requires human approval
        PolicyRule(
            policy_id="POL-SALES-EXPORT-APPROVAL",
            name="Require Approval for Customer Data Export",
            description="Customer record exports (up to 100 records) require human supervisor approval.",
            outcome=PolicyOutcome.REQUIRE_APPROVAL,
            priority=100,
            target_agents=["agent_sales_1", "agent_sales_2", "agent_sales_3"],
            target_tools=["export_customer_records"],
            target_actions=["export"],
            target_resources=["crm", "crm:customers"],
            conditions={"max_limit": 100},
            risk_level=RiskLevel.HIGH,
            enabled=True,
        ),
        # 5. Bulk search (51-100 records): Requires supervisor approval
        PolicyRule(
            policy_id="POL-SALES-SEARCH-BULK-APPROVAL",
            name="Require Approval for Large Search Results",
            description="Customer search requests exceeding 50 records require supervisor approval.",
            outcome=PolicyOutcome.REQUIRE_APPROVAL,
            priority=100,
            target_agents=["agent_sales_1", "agent_sales_2", "agent_sales_3"],
            target_tools=["search_customer_records"],
            target_actions=["search", "read"],
            target_resources=["crm", "crm:customers"],
            conditions={"min_limit": 51, "max_limit": 100},
            risk_level=RiskLevel.MEDIUM,
            enabled=True,
        ),
        # 6. Standard search (1-50 records): Allowed
        PolicyRule(
            policy_id="POL-SALES-SEARCH-ALLOW",
            name="Allow Standard Customer Search",
            description="Allows standard customer search queries within allowed record limits (<= 50 records).",
            outcome=PolicyOutcome.ALLOW,
            priority=110,
            target_agents=["agent_sales_1", "agent_sales_2", "agent_sales_3"],
            target_tools=["search_customer_records"],
            target_actions=["search", "read"],
            target_resources=["crm", "crm:customers"],
            conditions={"max_limit": 50},
            risk_level=RiskLevel.LOW,
            enabled=True,
        ),
        # 7. Customer single record lookup: Allowed
        PolicyRule(
            policy_id="POL-SALES-LOOKUP-ALLOW",
            name="Allow Individual Customer Record Lookup",
            description="Allows sales agents to retrieve individual customer details by customer ID.",
            outcome=PolicyOutcome.ALLOW,
            priority=110,
            target_agents=["agent_sales_1", "agent_sales_2", "agent_sales_3"],
            target_tools=["get_customer_by_id", "get_customer"],
            target_actions=["read"],
            target_resources=["crm", "crm:customers"],
            conditions={},
            risk_level=RiskLevel.LOW,
            enabled=True,
        ),
    ]


class PolicyEngine:
    """Deterministic authorization decision engine for AgentGuard."""

    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        load_defaults: bool = True
    ):
        self._rules: Dict[str, PolicyRule] = {}
        if load_defaults:
            for rule in get_default_policies():
                self.add_policy(rule)
        if rules:
            for rule in rules:
                self.add_policy(rule)

    def add_policy(self, rule: PolicyRule) -> None:
        """Register or update a policy rule."""
        if not isinstance(rule, PolicyRule):
            raise TypeError("rule must be an instance of PolicyRule")
        self._rules[rule.policy_id] = rule

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy rule by ID. Returns True if removed, False otherwise."""
        return self._rules.pop(policy_id, None) is not None

    def get_policy(self, policy_id: str) -> Optional[PolicyRule]:
        """Retrieve a policy rule by ID."""
        return self._rules.get(policy_id)

    def list_policies(self, enabled_only: bool = False) -> List[PolicyRule]:
        """Return all registered policy rules."""
        if enabled_only:
            return [r for r in self._rules.values() if r.enabled]
        return list(self._rules.values())

    def set_policy_enabled(self, policy_id: str, enabled: bool) -> bool:
        """Enable or disable a specific policy rule dynamically."""
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a boolean")
        rule = self._rules.get(policy_id)
        if rule:
            rule.enabled = enabled
            return True
        return False

    def reset_to_defaults(self) -> None:
        """Reset policy engine to the default baseline policies."""
        self._rules.clear()
        for rule in get_default_policies():
            self.add_policy(rule)

    def evaluate(self, request: PolicyEvaluationRequest) -> PolicyDecision:
        """Deterministically evaluate an incoming tool request against active policies.
        
        Evaluation Algorithm:
        1. Pre-validation:
           - Enforces presence and type of TrustedAgentContext.
           - Rejects malformed tool names or request structures.
           - Fails closed to DENY on any invalid request.
        2. Candidate Match Collection:
           - Gathers all enabled rules matching agent, role, tool, action, resource, and conditions.
        3. Deterministic Precedence Ordering:
           - Priority ascending (lower integer = higher precedence).
           - Outcome precedence on priority collision: DENY > REQUIRE_APPROVAL > ALLOW.
           - Specificity precedence on outcome collision: Specific agent > Wildcard agent, Specific tool > Wildcard tool.
           - Lexical sort on policy_id as final deterministic tie-break.
        4. Decision Selection:
           - Selects top candidate rule.
           - If no candidate matches, enforces fail-closed default DENY.
        """
        now = time.time()

        # 1. Validation & Fail-Closed Pre-checks
        if not hasattr(request, "agent_context") or not isinstance(request.agent_context, TrustedAgentContext):
            return PolicyDecision(
                outcome=PolicyOutcome.DENY,
                allowed=False,
                requires_approval=False,
                denied=True,
                policy_id=None,
                rule_name=None,
                reason="Untrusted or missing agent context: agent_context must be a verified TrustedAgentContext instance",
                risk_level=RiskLevel.CRITICAL,
                agent_id="UNTRUSTED",
                tool_name=getattr(request, "tool_name", "UNKNOWN"),
                action=getattr(request, "action", "UNKNOWN"),
                resource=getattr(request, "resource", "UNKNOWN"),
                timestamp=now,
                evaluated_parameters_summary={},
            )

        agent_id = request.agent_context.agent_id
        is_admin = request.agent_context.is_admin

        if not isinstance(request.tool_name, str) or not request.tool_name.strip():
            return PolicyDecision(
                outcome=PolicyOutcome.DENY,
                allowed=False,
                requires_approval=False,
                denied=True,
                policy_id=None,
                rule_name=None,
                reason="Invalid tool_name: tool_name must be a non-empty string",
                risk_level=RiskLevel.HIGH,
                agent_id=agent_id,
                tool_name=str(request.tool_name),
                action=getattr(request, "action", "UNKNOWN"),
                resource=getattr(request, "resource", "UNKNOWN"),
                timestamp=now,
                evaluated_parameters_summary={},
            )

        action = str(request.action or "read").strip().lower()
        resource = str(request.resource or "crm:customers").strip().lower()
        tool_name = request.tool_name.strip()
        params = request.parameters if isinstance(request.parameters, dict) else {}

        # Sanitize parameters for summary (redacting any potential secret/sensitive keys)
        param_summary = {
            k: v for k, v in params.items()
            if not any(s in k.lower() for s in ("password", "secret", "token", "key"))
        }

        # 2. Candidate Match Collection
        candidates: List[PolicyRule] = []
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            if not self._matches_agent(rule, agent_id, is_admin):
                continue
            if not self._matches_tool(rule, tool_name):
                continue
            if not self._matches_action(rule, action):
                continue
            if not self._matches_resource(rule, resource):
                continue
            if not self._matches_conditions(rule, params):
                continue
            candidates.append(rule)

        # 3. Decision Selection with Precedence
        if not candidates:
            return PolicyDecision(
                outcome=PolicyOutcome.DENY,
                allowed=False,
                requires_approval=False,
                denied=True,
                policy_id=None,
                rule_name=None,
                reason=f"No matching policy rule found for agent '{agent_id}' invoking '{tool_name}'; default deny enforced (fail-closed)",
                risk_level=RiskLevel.HIGH,
                agent_id=agent_id,
                tool_name=tool_name,
                action=action,
                resource=resource,
                timestamp=now,
                evaluated_parameters_summary=param_summary,
            )

        # Sort candidates using deterministic precedence:
        # 1. priority: ascending integer (1 is highest priority)
        # 2. outcome collision: DENY (0) > REQUIRE_APPROVAL (1) > ALLOW (2)
        # 3. agent specificity: exact agent (0) > wildcard '*' (1)
        # 4. tool specificity: exact tool (0) > wildcard '*' (1)
        # 5. resource specificity: exact resource (0) > wildcard '*' (1)
        # 6. policy_id: lexical ascending string
        outcome_weights = {
            PolicyOutcome.DENY: 0,
            PolicyOutcome.REQUIRE_APPROVAL: 1,
            PolicyOutcome.ALLOW: 2,
        }

        def sort_key(r: PolicyRule):
            agent_spec = 1 if "*" in r.target_agents else 0
            tool_spec = 1 if "*" in r.target_tools else 0
            res_spec = 1 if "*" in r.target_resources else 0
            return (
                r.priority,
                outcome_weights.get(r.outcome, 99),
                agent_spec,
                tool_spec,
                res_spec,
                r.policy_id,
            )

        candidates.sort(key=sort_key)
        winning_rule = candidates[0]

        is_allowed = winning_rule.outcome == PolicyOutcome.ALLOW
        is_approval = winning_rule.outcome == PolicyOutcome.REQUIRE_APPROVAL
        is_denied = winning_rule.outcome == PolicyOutcome.DENY

        return PolicyDecision(
            outcome=winning_rule.outcome,
            allowed=is_allowed,
            requires_approval=is_approval,
            denied=is_denied,
            policy_id=winning_rule.policy_id,
            rule_name=winning_rule.name,
            reason=winning_rule.description,
            risk_level=winning_rule.risk_level,
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            timestamp=now,
            evaluated_parameters_summary=param_summary,
        )

    # Internal matching helpers

    @staticmethod
    def _matches_agent(rule: PolicyRule, agent_id: str, is_admin: bool) -> bool:
        # If the rule specifically targets roles (e.g. ["admin"])
        if rule.target_roles:
            if "admin" in rule.target_roles and is_admin:
                return True
            # Non-admin cannot match via admin role; check if explicit agent_id matches
            if rule.target_agents and (agent_id in rule.target_agents):
                return True
            return False

        # Non-role-specific rule: check target_agents
        if "*" in rule.target_agents:
            return True
        return agent_id in rule.target_agents

    @staticmethod
    def _matches_tool(rule: PolicyRule, tool_name: str) -> bool:
        if "*" in rule.target_tools:
            return True
        return tool_name in rule.target_tools

    @staticmethod
    def _matches_action(rule: PolicyRule, action: str) -> bool:
        if "*" in rule.target_actions:
            return True
        rule_actions = [a.lower() for a in rule.target_actions]
        return action.lower() in rule_actions

    @staticmethod
    def _matches_resource(rule: PolicyRule, resource: str) -> bool:
        if "*" in rule.target_resources:
            return True
        res_lower = resource.lower()
        for tr in rule.target_resources:
            tr_lower = tr.lower()
            if tr_lower == res_lower:
                return True
            # Wildcard prefix matching e.g. "crm:*" matches "crm:customers"
            if tr_lower.endswith(":*") and res_lower.startswith(tr_lower[:-2]):
                return True
            # Handle resource equivalence between "crm" and "crm:customers"
            if tr_lower == "crm" and res_lower == "crm:customers":
                return True
            if tr_lower == "crm:customers" and res_lower == "crm":
                return True
        return False

    @staticmethod
    def _matches_conditions(rule: PolicyRule, params: Dict[str, Any]) -> bool:
        conditions = rule.conditions
        if not conditions:
            return True

        # Numeric limits
        limit_val = params.get("limit")
        if limit_val is not None and isinstance(limit_val, (int, float)) and not isinstance(limit_val, bool):
            if "max_limit" in conditions and limit_val > conditions["max_limit"]:
                return False
            if "min_limit" in conditions and limit_val < conditions["min_limit"]:
                return False

        # Allowed formats (for export tools)
        if "allowed_formats" in conditions:
            requested_format = str(params.get("format", "")).lower()
            allowed = [f.lower() for f in conditions["allowed_formats"]]
            if requested_format not in allowed:
                return False

        # Exact parameter matches
        if "exact_parameters" in conditions:
            for k, expected_v in conditions["exact_parameters"].items():
                if params.get(k) != expected_v:
                    return False

        # Prefix matching on parameter values (e.g. customer_id)
        if "parameter_prefix" in conditions:
            for param_key, required_prefix in conditions["parameter_prefix"].items():
                actual_val = str(params.get(param_key, ""))
                if not actual_val.startswith(required_prefix):
                    return False

        return True
