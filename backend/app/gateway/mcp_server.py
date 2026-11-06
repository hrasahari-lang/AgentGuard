"""Authenticated, policy-enforced MCP Streamable HTTP gateway."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
import time
import uuid
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from backend.app.audit.audit_store import AuditStore
from backend.app.config import get_cors_origins, get_db_path, get_mcp_allowed_hosts
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
    AuthenticationFailureRateLimiter,
    AuthenticationRequestRateLimiter,
    bootstrap_environment_credentials,
    current_trusted_context,
    initialize_agent_registry,
)

logger = logging.getLogger(__name__)


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


def _request_fingerprint(
    *, agent_id: str, tool_name: str, action: str, resource: str, parameters: dict[str, Any]
) -> str:
    payload = json.dumps(
        {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "action": action,
            "resource": resource,
            "parameters": parameters,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _request_id_digest(request_id: str) -> str:
    return hashlib.sha256(request_id.encode("utf-8")).hexdigest()


def _resolve_request_id(request_id: str | None, *, require_stable_key: bool = False) -> str:
    if request_id is None:
        if require_stable_key:
            raise ToolError("A stable request_id is required for this protected operation.")
        return uuid.uuid4().hex
    if (
        not isinstance(request_id, str)
        or not request_id
        or len(request_id) > 128
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in request_id)
    ):
        raise ToolError("request_id must contain 1 to 128 printable ASCII characters.")
    return request_id


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
    request_id: str,
    mcp_request_id: str,
) -> Any:
    resource = "crm:customers"
    if (
        not isinstance(request_id, str)
        or not request_id
        or len(request_id) > 128
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in request_id)
    ):
        raise ToolError("The MCP request ID is invalid; the protected operation was not started.")
    try:
        persisted_request_id = _request_id_digest(request_id)
        persisted_mcp_request_id = _request_id_digest(mcp_request_id)
        request_hash = _request_fingerprint(
            agent_id=context.agent_id,
            tool_name=tool_name,
            action=action,
            resource=resource,
            parameters=parameters,
        )
    except (TypeError, ValueError):
        raise ToolError("The MCP request could not be safely identified; the protected operation was not started.") from None
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
            audit.record_decision(
                decision, "DENIED", persisted_request_id, request_hash, persisted_mcp_request_id
            )
        except Exception:
            raise ToolError("Request denied; audit persistence failed.") from None
        raise ToolError("Request denied by AgentGuard policy.")
    if decision.outcome == PolicyOutcome.REQUIRE_APPROVAL:
        try:
            audit.record_decision(
                decision, "PENDING_APPROVAL", persisted_request_id, request_hash, persisted_mcp_request_id
            )
        except Exception:
            raise ToolError("Request blocked; audit persistence failed.") from None
        raise ToolError("Request requires human approval; protected data was not accessed.")

    try:
        event_id = audit.record_decision(
            decision, "DECISION_RECORDED", persisted_request_id, request_hash, persisted_mcp_request_id
        )
    except Exception:
        raise ToolError("Authorization decision could not be saved; execution did not start.") from None

    try:
        claimed, prior_status, same_request = audit.claim_request(
            context.agent_id, persisted_request_id, request_hash, event_id
        )
    except Exception:
        raise ToolError("Authorization was recorded, but idempotency could not be established; execution did not start.") from None
    if not claimed:
        rejected_as = "DUPLICATE_REQUEST" if same_request else "REQUEST_ID_CONFLICT"
        try:
            audit.mark_request_rejected(event_id, rejected_as)
        except Exception:
            raise ToolError("This request ID was already claimed; this invocation was not started.") from None
        detail = "already used" if same_request else "reused for different request content"
        raise ToolError(
            f"Request ID {detail}; this invocation was not re-executed. "
            f"Prior execution state: {prior_status or 'unknown'}."
        )

    try:
        audit.mark_execution_started(event_id, context.agent_id, persisted_request_id)
    except Exception:
        raise ToolError("Execution-start audit could not be saved; the protected operation did not start.") from None

    try:
        result = operation(repository, context)
    except Exception as error:
        try:
            audit.record_outcome(event_id, "FAILED", type(error).__name__)
        except Exception:
            try:
                audit.record_outcome_audit_failure(event_id)
            except Exception:
                logger.error("Execution outcome audit failed for event %s", event_id)
            raise ToolError(
                "The protected operation may have partially completed; its final audit status could not be confirmed. "
                "Do not retry it with a new request ID."
            ) from None
        raise ToolError("The protected operation raised an error; partial effects may have occurred.") from None
    try:
        audit.record_outcome(event_id, "SUCCEEDED")
    except Exception:
        try:
            audit.record_outcome_audit_failure(event_id)
        except Exception:
            logger.error("Execution outcome audit failed for event %s", event_id)
        raise ToolError(
            "The protected operation completed, but its final audit status could not be confirmed. "
            "Do not retry it with a new request ID."
        ) from None
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


class _HealthzBypass:
    """Serve only the non-sensitive liveness endpoint outside bearer auth."""

    def __init__(self, authenticated_app: ASGIApp) -> None:
        self.authenticated_app = authenticated_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope.get("type") == "http"
            and scope.get("method") == "GET"
            and scope.get("path") == "/healthz"
        ):
            await JSONResponse({"status": "ok"})(scope, receive, send)
            return
        await self.authenticated_app(scope, receive, send)


def create_gateway_app(
    db_path: str | Path | None = None,
    *,
    policy_engine: PolicyEngine | None = None,
    repository: CrmRepository | None = None,
    auth_failure_limiter: AuthenticationFailureRateLimiter | None = None,
    auth_request_limiter: AuthenticationRequestRateLimiter | None = None,
) -> ASGIApp:
    """Create the Starlette ASGI app with request auth ahead of the MCP endpoint."""
    cors_origins = get_cors_origins()
    mcp_allowed_hosts = get_mcp_allowed_hosts()
    resolved_path = get_db_path(db_path)
    init_db(resolved_path)
    initialize_agent_registry(resolved_path)
    bootstrap_environment_credentials(resolved_path)
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

    @server.tool(description="Search scoped synthetic CRM records. Supply a stable request_id to deduplicate retries.")
    async def search_customer_records(
        ctx: Context, query: str, limit: int = 10, request_id: str | None = None
    ) -> str:
        context = _current_context()
        idempotency_id = _resolve_request_id(request_id)
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
            request_id=idempotency_id,
            mcp_request_id=ctx.request_id,
        )

    @server.tool(description="Retrieve a scoped synthetic CRM record. Supply a stable request_id to deduplicate retries.")
    async def get_customer(
        ctx: Context, customer_id: str, request_id: str | None = None
    ) -> str:
        context = _current_context()
        idempotency_id = _resolve_request_id(request_id)
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
            request_id=idempotency_id,
            mcp_request_id=ctx.request_id,
        )

    @server.tool(description="Export scoped records. Supply a stable request_id to deduplicate retries; policy may deny or require approval.")
    async def export_customer_records(
        ctx: Context, format: str = "json", limit: int = 100, request_id: str | None = None
    ) -> str:
        context = _current_context()
        idempotency_id = _resolve_request_id(request_id)
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
            request_id=idempotency_id,
            mcp_request_id=ctx.request_id,
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
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=mcp_allowed_hosts,
            allowed_origins=cors_origins,
        ),
    )
    authenticated = AgentAuthenticationMiddleware(
        mcp_app,
        AgentAuthenticator(resolved_path),
        audit,
        auth_failure_limiter,
        request_limiter=auth_request_limiter,
    )
    return CORSMiddleware(
        _HealthzBypass(authenticated),
        allow_origins=cors_origins,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Mcp-Protocol-Version",
            "Mcp-Method",
            "Mcp-Name",
            "Mcp-Session-Id",
            "Last-Event-ID",
        ],
    )


def _current_context() -> TrustedAgentContext:
    from backend.app.security.auth import current_trusted_context

    try:
        return current_trusted_context()
    except RuntimeError:
        raise ToolError("Authenticated HTTP agent context is required.") from None


app = create_gateway_app()
