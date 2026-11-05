"""Registry-backed bearer authentication for the local MCP gateway prototype."""
from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from contextlib import closing

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from backend.app.config import get_db_path
from backend.app.crm_repository import TrustedAgentContext, _TRUSTED_CONTEXT_AUTHORITY
from backend.app.audit.audit_store import AuditStore

_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_AGENT_PRINCIPAL_AUTHORITY = object()
logger = logging.getLogger(__name__)
_trusted_context: contextvars.ContextVar[TrustedAgentContext | None] = contextvars.ContextVar(
    "agentguard_trusted_context", default=None
)


@dataclass(frozen=True, init=False)
class AgentPrincipal:
    agent_id: str
    is_admin: bool

    def __init__(self, agent_id: str, is_admin: bool, *, _authority: object | None = None):
        if _authority is not _AGENT_PRINCIPAL_AUTHORITY:
            raise TypeError("AgentPrincipal can only be created by AgentAuthenticator")
        object.__setattr__(self, "agent_id", agent_id)
        object.__setattr__(self, "is_admin", is_admin)

    def to_trusted_context(self) -> TrustedAgentContext:
        """Construct trusted identity only from an active stored credential."""
        return TrustedAgentContext(
            agent_id=self.agent_id,
            is_admin=self.is_admin,
            _authority=_TRUSTED_CONTEXT_AUTHORITY,
        )


def initialize_agent_registry(db_path: str | Path | None = None) -> Path:
    path = get_db_path(db_path)
    with closing(sqlite3.connect(path, timeout=15.0)) as conn:
        with conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS agent_credentials (
                    credential_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
                    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                    created_at REAL NOT NULL
                )"""
            )
    return path


def issue_agent_token(
    agent_id: str,
    *,
    is_admin: bool = False,
    db_path: str | Path | None = None,
) -> str:
    """Create a random bearer token; persist only its SHA-256 hash and return it once."""
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValueError("agent_id must be non-empty")
    if not isinstance(is_admin, bool):
        raise TypeError("is_admin must be boolean")
    path = initialize_agent_registry(db_path)
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with closing(sqlite3.connect(path, timeout=15.0)) as conn:
        with conn:
            # A newly issued credential rotates the agent's previous active token.
            conn.execute(
                "UPDATE agent_credentials SET active=0 WHERE agent_id=? AND active=1",
                (agent_id.strip(),),
            )
            conn.execute(
                "INSERT INTO agent_credentials(agent_id, token_hash, is_admin, active, created_at) VALUES (?, ?, ?, 1, strftime('%s','now'))",
                (agent_id.strip(), token_hash, int(is_admin)),
            )
    return token


def revoke_agent_credentials(agent_id: str, *, db_path: str | Path | None = None) -> int:
    path = initialize_agent_registry(db_path)
    with closing(sqlite3.connect(path, timeout=15.0)) as conn:
        with conn:
            cursor = conn.execute(
                "UPDATE agent_credentials SET active=0 WHERE agent_id=? AND active=1", (agent_id,)
            )
            return cursor.rowcount


class AgentAuthenticator:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = initialize_agent_registry(db_path)

    def authenticate(self, token: str) -> tuple[AgentPrincipal | None, str | None]:
        if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
            return None, "MALFORMED_BEARER"
        candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with closing(sqlite3.connect(self.db_path, timeout=15.0)) as conn:
            rows = conn.execute(
                "SELECT agent_id, token_hash, is_admin, active FROM agent_credentials"
            ).fetchall()
        match: AgentPrincipal | None = None
        revoked = False
        # Compare every active hash to avoid disclosing which credential matched by position.
        for agent_id, stored_hash, is_admin, active in rows:
            if hmac.compare_digest(candidate, stored_hash):
                if active:
                    match = AgentPrincipal(
                        agent_id=agent_id,
                        is_admin=bool(is_admin),
                        _authority=_AGENT_PRINCIPAL_AUTHORITY,
                    )
                else:
                    revoked = True
        if match is not None:
            return match, None
        return None, "REVOKED_CREDENTIAL" if revoked else "INVALID_TOKEN"

    def verify(self, token: str) -> AgentPrincipal | None:
        """Compatibility helper returning a principal only for active credentials."""
        principal, _failure = self.authenticate(token)
        return principal


def current_trusted_context() -> TrustedAgentContext:
    context = _trusted_context.get()
    if context is None:
        raise RuntimeError("authenticated HTTP agent context is required")
    return context


class AgentAuthenticationMiddleware:
    """Authenticate every HTTP request before MCP routing or tool handlers."""

    def __init__(self, app: ASGIApp, authenticator: AgentAuthenticator, audit: AuditStore):
        self.app = app
        self.authenticator = authenticator
        self.audit = audit

    async def _reject(self, scope: Scope, receive: Receive, send: Send, reason: str) -> None:
        try:
            await asyncio.to_thread(self.audit.record_authentication_failure, reason)
        except Exception:
            # The request remains denied; fallback logging contains only a fixed category.
            logger.error("Authentication failure audit could not be persisted (%s)", reason)
        response = JSONResponse(
            {"error": "unauthorized"}, status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )
        await response(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        authorization_headers = [
            value for key, value in scope.get("headers", []) if key.lower() == b"authorization"
        ]
        if not authorization_headers:
            await self._reject(scope, receive, send, "MISSING_CREDENTIAL")
            return
        if len(authorization_headers) != 1:
            await self._reject(scope, receive, send, "DUPLICATE_AUTHORIZATION")
            return
        authorization = authorization_headers[0].decode("latin-1")
        scheme, separator, credential = authorization.partition(" ")
        principal = None
        if not separator or scheme.lower() != "bearer" or not credential or " " in credential:
            await self._reject(scope, receive, send, "MALFORMED_BEARER")
            return
        try:
            principal, failure = await asyncio.to_thread(self.authenticator.authenticate, credential)
        except Exception:
            await self._reject(scope, receive, send, "CREDENTIAL_REGISTRY_FAILURE")
            return
        if principal is None:
            await self._reject(scope, receive, send, failure or "INVALID_TOKEN")
            return

        context = principal.to_trusted_context()
        token = _trusted_context.set(context)
        try:
            await self.app(scope, receive, send)
        finally:
            _trusted_context.reset(token)
