"""Unit tests for bounded authentication abuse controls and audit retention."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from backend.app.audit.audit_store import AuditStore
from backend.app.config import get_auth_failure_settings
from backend.app.security.auth import (
    AgentAuthenticator,
    AuthenticationFailureRateLimiter,
    issue_agent_token,
)


class TestAuthenticationFailureRateLimiter(unittest.TestCase):
    def test_limit_is_per_peer_and_expires_after_window(self):
        now = [100.0]
        limiter = AuthenticationFailureRateLimiter(
            max_failures=2, window_seconds=30, max_client_buckets=4, clock=lambda: now[0]
        )
        self.assertEqual(limiter.allow("192.0.2.1"), (True, 0.0))
        self.assertEqual(limiter.allow("192.0.2.1"), (True, 0.0))
        allowed, retry_after = limiter.allow("192.0.2.1")
        self.assertFalse(allowed)
        self.assertEqual(retry_after, 30.0)
        self.assertEqual(limiter.allow("192.0.2.2"), (True, 0.0))
        now[0] = 130.0
        self.assertEqual(limiter.allow("192.0.2.1"), (True, 0.0))

    def test_concurrent_requests_do_not_exceed_limit_and_peer_cache_is_bounded(self):
        limiter = AuthenticationFailureRateLimiter(
            max_failures=7, window_seconds=60, max_client_buckets=3
        )
        with ThreadPoolExecutor(max_workers=16) as executor:
            outcomes = list(executor.map(lambda _index: limiter.allow("192.0.2.10")[0], range(40)))
        self.assertEqual(sum(outcomes), 7)

        for index in range(12):
            limiter.allow(f"192.0.2.{index + 20}")
        self.assertLessEqual(len(limiter._failures), 3)

    def test_environment_limits_are_configurable_and_invalid_values_fail_closed(self):
        values = {
            "AGENTGUARD_AUTH_FAILURE_LIMIT": "5",
            "AGENTGUARD_AUTH_FAILURE_WINDOW_SECONDS": "45",
            "AGENTGUARD_AUTH_FAILURE_MAX_CLIENTS": "32",
            "AGENTGUARD_AUTH_FAILURE_RETENTION": "250",
        }
        with patch.dict(os.environ, values):
            settings = get_auth_failure_settings()
        self.assertEqual((settings.max_failures, settings.window_seconds), (5, 45))
        self.assertEqual((settings.max_client_buckets, settings.retention_events), (32, 250))
        with patch.dict(os.environ, {"AGENTGUARD_AUTH_FAILURE_LIMIT": "0"}):
            with self.assertRaises(ValueError):
                get_auth_failure_settings()


class TestAuthenticationFailureStorage(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "auth-audit.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_retention_bounds_only_auth_failure_rows_under_concurrency(self):
        store = AuditStore(self.db_path, auth_failure_retention=5)
        with closing(sqlite3.connect(self.db_path)) as connection:
            connection.execute(
                """INSERT INTO audit_events
                   (event_id, agent_id, tool_name, action, resource, decision, policy_id,
                    execution_status, error_type, timestamp)
                   VALUES ('decision-1', 'agent', 'tool', 'read', 'crm', 'ALLOW', NULL,
                           'SUCCEEDED', NULL, 1.0)"""
            )
            connection.commit()

        with ThreadPoolExecutor(max_workers=8) as executor:
            failures = [executor.submit(store.record_authentication_failure, "INVALID_TOKEN")
                        for _ in range(40)]
            for future in failures:
                future.result(timeout=10)

        with closing(sqlite3.connect(self.db_path)) as connection:
            retained = connection.execute(
                "SELECT failure_type FROM authentication_failure_events"
            ).fetchall()
            decisions = connection.execute("SELECT event_id FROM audit_events").fetchall()
        self.assertEqual(len(retained), 5)
        self.assertEqual({row[0] for row in retained}, {"INVALID_TOKEN"})
        self.assertEqual(decisions, [("decision-1",)])

    def test_credential_authentication_uses_unique_hash_index(self):
        token = issue_agent_token("indexed-agent", db_path=self.db_path)
        authenticator = AgentAuthenticator(self.db_path)
        principal, failure = authenticator.authenticate(token)
        self.assertIsNone(failure)
        self.assertEqual(principal.agent_id, "indexed-agent")
        with closing(sqlite3.connect(self.db_path)) as connection:
            plan = connection.execute(
                "EXPLAIN QUERY PLAN SELECT agent_id, token_hash, is_admin, active "
                "FROM agent_credentials WHERE token_hash=?",
                ("0" * 64,),
            ).fetchall()
        self.assertIn("INDEX", " ".join(str(row[-1]) for row in plan).upper())


if __name__ == "__main__":
    unittest.main()
