"""Authenticated, policy-enforced MCP Streamable HTTP gateway."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from backend.app.audit.audit_store import AuditStore
from backend.app.config import get_db_path
from backend.app.crm_repository import CrmRepository, TrustedAgentContext
from backend.app.database import init_db
from backend.app.policy_engine import (
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluationRequest,
    PolicyOutcome,
    RiskLevel,
)
from backend.app.security.auth import (
    AgentAuthenticationMiddleware,
    AgentAuthenticator,
    current_trusted_context,
    initialize_agent_registry,
)


def _fallback_deny(context: TrustedAgentContext, tool: str, action: str, resource: str) -> PolicyDecision:
    return PolicyDecision(
        outcome=PolicyOutcome.DENY,
        allowed=False,
        requires_approval=False,
        denied=True,
        policy_id=None,
        rule_name=None,
        reason="Policy evaluation failed; default deny enforced",
        risk_level=RiskLevel.CRITICAL,
        agent_id=context.agent_id,
        tool_name=tool,
        action=action,
        resource=resource,
        timestamp=time.time(),
        evaluated_parameters_summary={},
    )


def _govern_and_execute(
    *,
    context: TrustedAgentContext,
    policy_engine: PolicyEngine,
    repository: CrmRepository,
    audit: AuditStore,
    tool_name: str,
    action: str,
    parameters: dict[str, Any],
    operation,
) -> Any:
    resource = "crm:customers"
    try:
        decision = policy_engine.evaluate(
            PolicyEvaluationRequest(
                agent_context=context,
                tool_name=tool_name,
                action=action,
                resource=resource,
                parameters=parameters,
            )
        )
    except Exception:
        decision = _fallback_deny(context, tool_name, action, resource)

    if decision.outcome == PolicyOutcome.DENY:
        try:
            audit.record_decision(decision, "DENIED")
        except Exception:
            raise ToolError("Request denied; audit persistence failed.") from None
        raise ToolError("Request denied by AgentGuard policy.")
    if decision.outcome == PolicyOutcome.REQUIRE_APPROVAL:
        try:
            audit.record_decision(decision, "PENDING_APPROVAL")
        except Exception:
            raise ToolError("Request blocked; audit persistence failed.") from None
        raise ToolError("Request requires human approval; protected data was not accessed.")

    try:
        event_id = audit.record_decision(decision, "STARTED")
    except Exception:
        raise ToolError("Request blocked because the authorization audit could not be saved.") from None

    try:
        result = operation(repository, context)
    except Exception as error:
        try:
            audit.record_outcome(event_id, "FAILED", type(error).__name__)
        except Exception:
            raise ToolError("Protected operation failed; audit outcome could not be saved.") from None
        raise ToolError("Protected operation failed.") from None
    try:
        audit.record_outcome(event_id, "SUCCEEDED")
    except Exception:
        raise ToolError("Protected operation completed, but its audit outcome could not be saved.") from None
    return result


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _admin_required() -> Response | None:
    try:
        context = current_trusted_context()
    except RuntimeError:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not context.is_admin:
        return JSONResponse({"error": "admin role required"}, status_code=403)
    return None


def create_gateway_app(
    db_path: str | Path | None = None,
    *,
    policy_engine: PolicyEngine | None = None,
    repository: CrmRepository | None = None,
) -> ASGIApp:
    """Create the Starlette ASGI app with request auth ahead of the MCP endpoint."""
    resolved_path = get_db_path(db_path)
    init_db(resolved_path)
    initialize_agent_registry(resolved_path)
    engine = policy_engine or PolicyEngine()
    crm = repository or CrmRepository(resolved_path)
    audit = AuditStore(resolved_path)
    server = MCPServer(
        "AgentGuard",
        version="0.1.0",
        instructions=(
            "AgentGuard governs only tool calls routed through this server. "
            "Identity is derived from the HTTP bearer credential; do not supply identity arguments."
        ),
    )

    @server.tool(description="Search synthetic CRM customer records within the authenticated agent's scope.")
    async def search_customer_records(query: str, limit: int = 10) -> str:
        context = _current_context()
        return await asyncio.to_thread(
            _govern_and_execute,
            context=context,
            policy_engine=engine,
            repository=crm,
            audit=audit,
            tool_name="search_customer_records",
            action="search",
            parameters={"query": query, "limit": limit},
            operation=lambda repo, agent: json.dumps(repo.search_customer_records(query, agent, limit)),
        )

    @server.tool(description="Retrieve one synthetic CRM customer record within the authenticated agent's scope.")
    async def get_customer(customer_id: str) -> str:
        context = _current_context()
        return await asyncio.to_thread(
            _govern_and_execute,
            context=context,
            policy_engine=engine,
            repository=crm,
            audit=audit,
            tool_name="get_customer",
            action="read",
            parameters={"customer_id": customer_id},
            operation=lambda repo, agent: json.dumps(repo.get_customer_by_id(customer_id, agent)),
        )

    @server.tool(description="Export scoped synthetic CRM records; this action may be denied or require approval.")
    async def export_customer_records(format: str = "json", limit: int = 100) -> str:
        context = _current_context()
        return await asyncio.to_thread(
            _govern_and_execute,
            context=context,
            policy_engine=engine,
            repository=crm,
            audit=audit,
            tool_name="export_customer_records",
            action="export",
            parameters={"format": format, "limit": limit},
            operation=lambda repo, agent: repo.export_customer_records(agent, format, limit),
        )

    @server.custom_route("/api/overview", methods=["GET"], include_in_schema=False)
    async def overview(request: Request) -> Response:
        denied = _admin_required()
        if denied:
            return denied
        with closing(sqlite3.connect(resolved_path, timeout=15.0)) as conn:
            active_agents = conn.execute(
                "SELECT COUNT(DISTINCT agent_id) FROM agent_credentials WHERE active=1"
            ).fetchone()[0]
            audit_event_count = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            decisions = dict(conn.execute(
                "SELECT decision, COUNT(*) FROM audit_events GROUP BY decision"
            ).fetchall())
        counters = repository or crm
        from backend.app.crm_repository import get_invocation_counts

        invocation_counts = get_invocation_counts(counters.db_path)
        return JSONResponse({
            "active_agents": active_agents,
            "policy_rules": len(engine.list_policies()),
            "resource_invocations_started": invocation_counts["total_invocations"],
            "resource_executions_succeeded": invocation_counts["successful_invocations"],
            "audit_event_count": audit_event_count,
            "decisions": decisions,
        })

    @server.custom_route("/api/agents", methods=["GET"], include_in_schema=False)
    async def agents(request: Request) -> Response:
        denied = _admin_required()
        if denied:
            return denied
        with closing(sqlite3.connect(resolved_path, timeout=15.0)) as conn:
            rows = conn.execute(
                """SELECT agent_id,
                          MAX(CASE WHEN active=1 THEN is_admin ELSE 0 END),
                          MAX(active), COUNT(*)
                   FROM agent_credentials GROUP BY agent_id ORDER BY agent_id"""
            ).fetchall()
        return JSONResponse({
            "agents": [
                {"agent_id": row[0], "is_admin": bool(row[1]), "active": bool(row[2]), "credential_count": row[3]}
                for row in rows
            ]
        })

    @server.custom_route("/api/policies", methods=["GET"], include_in_schema=False)
    async def policies(request: Request) -> Response:
        denied = _admin_required()
        if denied:
            return denied
        return JSONResponse({"policies": [
            {
                "policy_id": rule.policy_id,
                "name": rule.name,
                "description": rule.description,
                "outcome": rule.outcome.value,
                "priority": rule.priority,
                "enabled": rule.enabled,
                "risk_level": rule.risk_level.value,
                "target_agents": list(rule.target_agents),
                "target_roles": list(rule.target_roles),
                "target_tools": list(rule.target_tools),
                "target_actions": list(rule.target_actions),
                "target_resources": list(rule.target_resources),
                "conditions": _jsonable(rule.conditions),
            }
            for rule in engine.list_policies()
        ]})

    @server.custom_route("/api/audit", methods=["GET"], include_in_schema=False)
    async def audit_events(request: Request) -> Response:
        denied = _admin_required()
        if denied:
            return denied
        try:
            limit = int(request.query_params.get("limit", "100"))
            events = audit.list_events(limit)
        except (TypeError, ValueError):
            return JSONResponse({"error": "limit must be an integer from 1 to 1000"}, status_code=400)
        return JSONResponse({"events": events})

    mcp_app = server.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        max_request_body_size=1_048_576,
    )
    authenticated = AgentAuthenticationMiddleware(mcp_app, AgentAuthenticator(resolved_path))
    return CORSMiddleware(
        authenticated,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )


def _current_context() -> TrustedAgentContext:
    from backend.app.security.auth import current_trusted_context

    try:
        return current_trusted_context()
    except RuntimeError:
        raise ToolError("Authenticated HTTP agent context is required.") from None


app = create_gateway_app()
