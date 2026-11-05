"""Explicit unit-test identity fixture that goes through the real credential verifier."""
from __future__ import annotations

import tempfile
from pathlib import Path

from backend.app.security.auth import AgentAuthenticator, issue_agent_token
from backend.app.crm_repository import TrustedAgentContext


def authenticated_test_context(agent_id: str, *, is_admin: bool = False) -> TrustedAgentContext:
    """Create an isolated credential and return its verified context for unit tests."""
    with tempfile.TemporaryDirectory() as directory:
        db_path = Path(directory) / "identity-fixture.db"
        token = issue_agent_token(agent_id, is_admin=is_admin, db_path=db_path)
        principal = AgentAuthenticator(db_path).verify(token)
        if principal is None:
            raise AssertionError("test credential did not verify")
        return principal.to_trusted_context()
