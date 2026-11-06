"""Unit tests for bounded authentication abuse controls and audit retention."""
from __future__ import annotations

import asyncio
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from starlette.responses import Response

from backend.app.audit.audit_store import AuditStore
from backend.app.config import get_auth_failure_settings
from backend.app.security.auth import (
    AgentAuthenticator,
    AgentAuthenticationMiddleware,
    AuthenticationFailureRateLimiter,
    AuthenticationRequestRateLimiter,
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

    def test_full_bucket_table_uses_overflow_without_evicting_active_peer(self):
        now = [100.0]
        limiter = AuthenticationFailureRateLimiter(
            max_failures=2, window_seconds=10, max_client_buckets=2, clock=lambda: now[0]
        )
        self.assertEqual(limiter.allow("192.0.2.1"), (True, 0.0))
        self.assertEqual(limiter.allow("192.0.2.1"), (True, 0.0))
        self.assertFalse(limiter.allow("192.0.2.1")[0])

        # Only one named peer bucket plus one shared overflow bucket are retained.
        self.assertEqual(limiter.allow("192.0.2.2"), (True, 0.0))
        self.assertEqual(limiter.allow("192.0.2.3"), (True, 0.0))
        self.assertLessEqual(len(limiter._failures), 2)
        for index in range(10, 20):
            limiter.allow(f"192.0.2.{index}")
        self.assertFalse(limiter.allow("192.0.2.1")[0])

        # Once the old window expires, a bounded sweep reclaims stale peer buckets.
        now[0] = 111.0
        self.assertEqual(limiter.allow("192.0.2.99"), (True, 0.0))
        self.assertLessEqual(len(limiter._failures), 2)

    def test_environment_limits_are_configurable_and_invalid_values_fail_closed(self):
        values = {
            "AGENTGUARD_AUTH_FAILURE_LIMIT": "5",
            "AGENTGUARD_AUTH_REQUEST_LIMIT": "600",
            "AGENTGUARD_AUTH_FAILURE_WINDOW_SECONDS": "45",
            "AGENTGUARD_AUTH_FAILURE_MAX_CLIENTS": "32",
            "AGENTGUARD_AUTH_FAILURE_RETENTION": "250",
        }
        with patch.dict(os.environ, values):
            settings = get_auth_failure_settings()
        self.assertEqual((settings.max_failures, settings.window_seconds), (5, 45))
        self.assertEqual(settings.max_auth_requests, 600)
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

    def test_early_request_limit_suppresses_registry_lookup_without_valid_token_bypass(self):
        token = issue_agent_token("early-limit-agent", db_path=self.db_path)
        authenticator = AgentAuthenticator(self.db_path)
        audit = type("MemoryAudit", (), {
            "__init__": lambda self: setattr(self, "failures", []),
            "record_authentication_failure": lambda self, reason: self.failures.append(reason),
        })()

        async def downstream(scope, receive, send):
            await Response(status_code=204)(scope, receive, send)

        middleware = AgentAuthenticationMiddleware(
            downstream,
            authenticator,
            audit,
            AuthenticationFailureRateLimiter(
                max_failures=10, window_seconds=60, max_client_buckets=4
            ),
            request_limiter=AuthenticationRequestRateLimiter(
                max_requests=2, window_seconds=60, max_client_buckets=4
            ),
        )

        async def send_request(bearer: str, extra_headers=()) -> int:
            messages = []
            headers = [(b"authorization", f"Bearer {bearer}".encode("ascii")), *extra_headers]
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/api/overview",
                "raw_path": b"/api/overview",
                "query_string": b"",
                "headers": headers,
                "client": ("198.51.100.30", 40000),
                "server": ("127.0.0.1", 8000),
            }

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                messages.append(message)

            await middleware(scope, receive, send)
            return next(message["status"] for message in messages if message["type"] == "http.response.start")

        with patch.object(authenticator, "authenticate", wraps=authenticator.authenticate) as lookup:
            statuses = asyncio.run(
                self._send_limited_sequence(send_request, token)
            )

        self.assertEqual(statuses, [204, 401, 429])
        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(audit.failures, ["INVALID_TOKEN"])

    @staticmethod
    async def _send_limited_sequence(send_request, token):
        return [
            await send_request(token),
            await send_request("x" * 43),
            # Neither a valid token nor a spoofed forwarding header bypasses the budget.
            await send_request(token, [(b"x-forwarded-for", b"203.0.113.99")]),
        ]


if __name__ == "__main__":
    unittest.main()
