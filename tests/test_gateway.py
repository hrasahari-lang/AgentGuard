"""HTTP integration tests for the authenticated MCP gateway vertical slice."""
from __future__ import annotations

import asyncio
import http.client
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch
from contextlib import closing

import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from backend.app.crm_repository import CrmRepository, get_total_invocations
from backend.app.gateway.mcp_server import create_gateway_app
from backend.app.gateway.mcp_server import _resolve_request_id
from mcp.server.mcpserver.exceptions import ToolError
from backend.app.security.auth import (
    AgentAuthenticator,
    AgentPrincipal,
    AuthenticationFailureRateLimiter,
    issue_agent_token,
    revoke_agent_credentials,
)
from backend.app.crm_repository import TrustedAgentContext


class TestAuthenticatedMcpGateway(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "gateway.db"
        self.repo = CrmRepository(self.db_path)
        # Create and seed the CRM tables before provisioning credentials.
        from backend.app.database import init_db

        init_db(self.db_path)
        self.token = issue_agent_token("agent_sales_1", db_path=self.db_path)
        self.auth_failure_limiter = AuthenticationFailureRateLimiter(
            max_failures=20, window_seconds=60, max_client_buckets=16
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        self.port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        self.server = uvicorn.Server(uvicorn.Config(
            create_gateway_app(self.db_path, auth_failure_limiter=self.auth_failure_limiter),
            host="127.0.0.1", port=self.port,
            log_level="critical", lifespan="on", proxy_headers=False,
        ))
        self.thread = threading.Thread(target=self.server.run, kwargs={"sockets": [sock]}, daemon=True)
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started and self.thread.is_alive() and time.time() < deadline:
            time.sleep(0.02)
        if not self.server.started:
            self.server.should_exit = True
            self.thread.join(timeout=2)
            self.temp_dir.cleanup()
            self.fail("MCP gateway did not start")

    def tearDown(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)
        self.temp_dir.cleanup()

    def _call_tool(self, tool_name, arguments, token=None):
        async def call():
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            async with httpx2.AsyncClient(headers=headers) as http_client:
                transport = streamable_http_client(self.url, http_client=http_client)
                async with Client(transport) as client:
                    listing = await client.list_tools()
                    self.discovered_tool_names = {tool.name for tool in listing.tools}
                    return await client.call_tool(tool_name, arguments)

        return asyncio.run(call())

    def _raw_request(self, method, path, headers=(), body=b""):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.putrequest(method, path)
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_http_auth_precedes_mcp_and_protected_operations(self):
        request = Request(self.url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as raised:
            urlopen(request, timeout=3)
        self.assertEqual(raised.exception.code, 401)
        invalid = Request(
            self.url,
            data=b"{}",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {'x' * 43}"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as invalid_response:
            urlopen(invalid, timeout=3)
        self.assertEqual(invalid_response.exception.code, 401)
        self.assertEqual(revoke_agent_credentials("agent_sales_1", db_path=self.db_path), 1)
        revoked = Request(
            self.url,
            data=b"{}",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as revoked_response:
            urlopen(revoked, timeout=3)
        self.assertEqual(revoked_response.exception.code, 401)
        self.assertEqual(get_total_invocations(self.db_path), 0)

        connection = sqlite3.connect(self.db_path)
        try:
            stored_hashes = [row[0] for row in connection.execute("SELECT token_hash FROM agent_credentials")]
        finally:
            connection.close()
        self.assertNotIn(self.token, stored_hashes)

    def test_authenticated_identity_is_the_only_context_factory(self):
        with self.assertRaises(TypeError):
            TrustedAgentContext("agent_admin", is_admin=True)
        with self.assertRaises(TypeError):
            AgentPrincipal("agent_admin", is_admin=True)
        with self.assertRaises(RuntimeError):
            from backend.app.security.auth import current_trusted_context
            current_trusted_context()

    def test_authentication_failures_are_categorized_without_secrets(self):
        statuses = []
        statuses.append(self._raw_request("GET", "/api/overview")[0])
        statuses.append(self._raw_request("GET", "/api/overview", [("Authorization", "Basic secret-value")])[0])
        statuses.append(self._raw_request("GET", "/api/overview", [
            ("Authorization", "Bearer " + "a" * 43),
            ("Authorization", "Bearer " + "b" * 43),
        ])[0])
        statuses.append(self._raw_request(
            "GET", "/api/overview", [("Authorization", "Bearer " + "x" * 43)]
        )[0])
        self.assertEqual(statuses, [401, 401, 401, 401])

        revoke_agent_credentials("agent_sales_1", db_path=self.db_path)
        statuses.append(self._raw_request(
            "GET", "/api/overview", [("Authorization", f"Bearer {self.token}")]
        )[0])
        self.assertEqual(statuses[-1], 401)

        with patch.object(AgentAuthenticator, "authenticate", side_effect=sqlite3.OperationalError("registry unavailable")):
            statuses.append(self._raw_request(
                "GET", "/api/overview", [("Authorization", "Bearer " + "z" * 43)]
            )[0])
        self.assertEqual(statuses[-1], 401)

        with closing(sqlite3.connect(self.db_path)) as connection:
            rows = connection.execute(
                "SELECT failure_type FROM authentication_failure_events ORDER BY rowid"
            ).fetchall()
        self.assertEqual([row[0] for row in rows], [
            "MISSING_CREDENTIAL", "MALFORMED_BEARER", "DUPLICATE_AUTHORIZATION",
            "INVALID_TOKEN", "REVOKED_CREDENTIAL", "CREDENTIAL_REGISTRY_FAILURE",
        ])
        with closing(sqlite3.connect(self.db_path)) as connection:
            persisted = connection.execute("SELECT * FROM authentication_failure_events").fetchall()
        persisted_text = repr(persisted)
        for secret in (self.token, "secret-value", "a" * 43, "b" * 43, "x" * 43, "z" * 43):
            self.assertNotIn(secret, persisted_text)

    def test_authentication_audit_failure_still_rejects_request(self):
        from backend.app.audit.audit_store import AuditStore

        with patch.object(AuditStore, "record_authentication_failure", side_effect=OSError("disk unavailable")):
            status, _body = self._raw_request("GET", "/api/overview")
        self.assertEqual(status, 401)
        self.assertEqual(get_total_invocations(self.db_path), 0)

    def test_authentication_failures_are_rate_limited_before_audit_and_valid_auth_still_works(self):
        statuses = [self._raw_request("GET", "/api/overview")[0] for _ in range(20)]
        self.assertEqual(statuses, [401] * 20)
        # Forwarded headers are untrusted and cannot create a fresh limiter bucket.
        limited_status, _ = self._raw_request(
            "GET", "/api/overview", [("X-Forwarded-For", "198.51.100.99")]
        )
        self.assertEqual(limited_status, 429)

        with closing(sqlite3.connect(self.db_path)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM authentication_failure_events"
            ).fetchone()[0]
        self.assertEqual(count, 20)

        # A valid credential remains usable even when its peer has exhausted the failure bucket.
        result = self._call_tool("search_customer_records", {"query": "Acme", "limit": 10}, self.token)
        self.assertFalse(result.is_error)

    def test_allow_executes_and_deny_never_reaches_crm(self):
        allowed = self._call_tool(
            "search_customer_records",
            {"query": "Acme", "limit": 10, "agent_id": "admin_service", "is_admin": True},
            self.token,
        )
        self.assertEqual(
            self.discovered_tool_names,
            {"search_customer_records", "get_customer", "export_customer_records"},
        )
        self.assertFalse(allowed.is_error)
        self.assertIn("CUST-101", "".join(item.text for item in allowed.content if hasattr(item, "text")))
        self.assertEqual(get_total_invocations(self.db_path), 1)

        denied = self._call_tool(
            "export_customer_records", {"format": "json", "limit": 101}, self.token
        )
        self.assertTrue(denied.is_error)
        self.assertEqual(get_total_invocations(self.db_path), 1)

        from backend.app.audit.audit_store import AuditStore

        events = AuditStore(self.db_path).list_events()
        self.assertEqual([event["decision"] for event in events], ["ALLOW", "DENY"])
        self.assertEqual([event["execution_status"] for event in events], ["SUCCEEDED", "DENIED"])
        self.assertTrue(all(event["agent_id"] == "agent_sales_1" for event in events))
        self.assertTrue(all(event["error_type"] is None for event in events))

    def test_tool_arguments_cannot_spoof_identity_or_scope(self):
        result = self._call_tool(
            "get_customer",
            {"customer_id": "CUST-104", "agent_id": "agent_admin", "is_admin": True},
            self.token,
        )
        self.assertFalse(result.is_error)
        self.assertEqual("".join(item.text for item in result.content if hasattr(item, "text")), "null")
        self.assertEqual(get_total_invocations(self.db_path), 1)
        from backend.app.audit.audit_store import AuditStore

        event = AuditStore(self.db_path).list_events()[0]
        self.assertEqual(event["agent_id"], "agent_sales_1")

    def test_issuing_a_new_credential_rotates_the_old_token(self):
        replacement = issue_agent_token("agent_sales_1", db_path=self.db_path)
        authenticator = AgentAuthenticator(self.db_path)
        self.assertIsNone(authenticator.verify(self.token))
        self.assertEqual(authenticator.verify(replacement).agent_id, "agent_sales_1")

    def test_standalone_external_agent_demo(self):
        environment = os.environ.copy()
        environment["AGENTGUARD_TOKEN"] = self.token
        environment["AGENTGUARD_MCP_URL"] = self.url
        result = subprocess.run(
            [sys.executable, "-m", "demo.external_agent"],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("search_customer_records", result.stdout)
        self.assertIn("CUST-101", result.stdout)
        self.assertIn("Request denied by AgentGuard policy", result.stdout)
        self.assertNotIn(self.token, result.stdout + result.stderr)

    def test_managed_agent_uses_gateway_auth_policy_execution_and_audit(self):
        request_id = "managed-agent-search-1"
        environment = os.environ.copy()
        environment["AGENTGUARD_TOKEN"] = self.token
        environment["AGENTGUARD_MCP_URL"] = self.url
        command = [
            sys.executable, "-m", "demo.managed_agent", "--query", "Acme",
            "--request-id", request_id,
        ]
        result = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(request_id, result.stdout)
        self.assertIn("CUST-101", result.stdout)
        self.assertNotIn(self.token, result.stdout + result.stderr)
        self.assertEqual(get_total_invocations(self.db_path), 1)

        retry = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertNotEqual(retry.returncode, 0)
        self.assertIn("not re-executed", retry.stderr)
        self.assertEqual(get_total_invocations(self.db_path), 1)

        from backend.app.audit.audit_store import AuditStore

        events = AuditStore(self.db_path).list_events()
        self.assertEqual(
            [event["execution_status"] for event in events],
            ["SUCCEEDED", "DUPLICATE_REQUEST"],
        )
        self.assertTrue(all(event["decision"] == "ALLOW" for event in events))
        self.assertTrue(all(event["agent_id"] == "agent_sales_1" for event in events))
        expected_request_hash = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        self.assertTrue(all(event["request_id"] == expected_request_hash for event in events))

    def test_admin_read_api_returns_real_dashboard_data(self):
        root = self.url.rsplit("/mcp", 1)[0]
        sales_request = Request(
            f"{root}/api/overview", headers={"Authorization": f"Bearer {self.token}"}
        )
        with self.assertRaises(HTTPError) as sales_response:
            urlopen(sales_request, timeout=3)
        self.assertEqual(sales_response.exception.code, 403)

        admin_token = issue_agent_token("agent_admin", is_admin=True, db_path=self.db_path)
        dashboard_request = Request(
            f"{root}/api/overview", headers={"Authorization": f"Bearer {admin_token}"}
        )
        with urlopen(dashboard_request, timeout=3) as response:
            overview = json.loads(response.read())
        self.assertEqual(overview["active_agents"], 2)
        self.assertEqual(overview["resource_invocations_started"], 0)
        self.assertEqual(overview["audit_event_count"], 0)
        with urlopen(Request(
            f"{root}/api/policies", headers={"Authorization": f"Bearer {admin_token}"}
        ), timeout=3) as response:
            policies = json.loads(response.read())["policies"]
        self.assertGreaterEqual(len(policies), 1)

        preflight = Request(
            f"{root}/api/overview",
            headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
            method="OPTIONS",
        )
        with urlopen(preflight, timeout=3) as response:
            self.assertEqual(response.headers["access-control-allow-origin"], "http://localhost:5173")

    def test_every_admin_endpoint_enforces_auth_and_excludes_sensitive_data(self):
        self._call_tool("search_customer_records", {"query": "Acme", "limit": 5}, self.token)
        root = self.url.rsplit("/mcp", 1)[0]
        admin_token = issue_agent_token("agent_admin", is_admin=True, db_path=self.db_path)
        endpoints = ("/api/overview", "/api/agents", "/api/policies", "/api/audit?limit=100")
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint, identity="none"):
                status, _body = self._raw_request("GET", endpoint)
                self.assertEqual(status, 401)
            with self.subTest(endpoint=endpoint, identity="invalid"):
                status, _body = self._raw_request(
                    "GET", endpoint, [("Authorization", "Bearer " + "q" * 43)]
                )
                self.assertEqual(status, 401)
            with self.subTest(endpoint=endpoint, identity="ordinary-agent"):
                status, _body = self._raw_request(
                    "GET", endpoint, [("Authorization", f"Bearer {self.token}")]
                )
                self.assertEqual(status, 403)
            with self.subTest(endpoint=endpoint, identity="admin"):
                status, body = self._raw_request(
                    "GET", endpoint, [("Authorization", f"Bearer {admin_token}")]
                )
                self.assertEqual(status, 200)
                body_text = body.decode("utf-8")
                for sensitive in (self.token, admin_token, "CUST-101", "Acme Industrial", "example.com"):
                    self.assertNotIn(sensitive, body_text)

        # Identity fields in public payloads cannot grant access to an admin route.
        status, _body = self._raw_request(
            "GET", "/api/agents",
            [("Content-Type", "application/json")],
            b'{"agent_id":"agent_admin","is_admin":true}',
        )
        self.assertEqual(status, 401)

    def test_audit_failure_blocks_allowed_resource_execution(self):
        from backend.app.audit.audit_store import AuditStore

        with patch.object(AuditStore, "record_decision", side_effect=OSError("audit unavailable")):
            result = self._call_tool(
                "search_customer_records", {"query": "Acme", "limit": 10}, self.token
            )
        self.assertTrue(result.is_error)
        self.assertEqual(get_total_invocations(self.db_path), 0)

    def test_execution_failure_is_recorded_separately_from_allow_decision(self):
        from backend.app.audit.audit_store import AuditStore

        with patch.object(CrmRepository, "search_customer_records", side_effect=RuntimeError("synthetic failure")):
            result = self._call_tool(
                "search_customer_records", {"query": "Acme", "limit": 10}, self.token
            )
        self.assertTrue(result.is_error)
        event = AuditStore(self.db_path).list_events()[0]
        self.assertEqual(event["decision"], "ALLOW")
        self.assertEqual(event["execution_status"], "FAILED")
        self.assertEqual(event["error_type"], "RuntimeError")

    def test_request_id_prevents_duplicate_execution_and_detects_conflict(self):
        request_id = "retry-allowed-search-1"
        first = self._call_tool("search_customer_records", {
            "query": "Acme", "limit": 10, "request_id": request_id,
        }, self.token)
        second = self._call_tool("search_customer_records", {
            "query": "Acme", "limit": 10, "request_id": request_id,
        }, self.token)
        conflict = self._call_tool("search_customer_records", {
            "query": "BioPulse", "limit": 10, "request_id": request_id,
        }, self.token)
        self.assertFalse(first.is_error)
        self.assertTrue(second.is_error)
        self.assertTrue(conflict.is_error)
        self.assertIn("not re-executed", "".join(item.text for item in second.content if hasattr(item, "text")))
        self.assertEqual(get_total_invocations(self.db_path), 1)
        from backend.app.audit.audit_store import AuditStore

        events = AuditStore(self.db_path).list_events()
        self.assertEqual([event["execution_status"] for event in events], [
            "SUCCEEDED", "DUPLICATE_REQUEST", "REQUEST_ID_CONFLICT",
        ])
        request_id_hash = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        self.assertTrue(all(event["request_id"] == request_id_hash for event in events))
        self.assertTrue(all(event["mcp_request_id"] for event in events))

    def test_future_mutating_operation_must_require_stable_request_id(self):
        with self.assertRaises(ToolError):
            _resolve_request_id(None, require_stable_key=True)
        with self.assertRaises(ToolError):
            _resolve_request_id("contains\ncontrol", require_stable_key=True)
        self.assertEqual(
            _resolve_request_id("stable-mutation-1", require_stable_key=True),
            "stable-mutation-1",
        )

    def test_request_identifiers_are_hashed_before_audit_persistence(self):
        result = self._call_tool("search_customer_records", {
            "query": "Acme", "limit": 10, "request_id": self.token,
        }, self.token)
        self.assertFalse(result.is_error)
        with closing(sqlite3.connect(self.db_path)) as connection:
            contents = repr(connection.execute(
                "SELECT request_id, mcp_request_id, request_hash FROM audit_events"
            ).fetchall())
        self.assertNotIn(self.token, contents)

    def test_execution_outcome_audit_failure_is_ambiguous_and_cannot_replay(self):
        from backend.app.audit.audit_store import AuditStore

        with patch.object(AuditStore, "record_outcome", side_effect=OSError("audit unavailable")):
            result = self._call_tool("search_customer_records", {
                "query": "Acme", "limit": 10, "request_id": "outcome-audit-failure-1",
            }, self.token)
        self.assertTrue(result.is_error)
        message = "".join(item.text for item in result.content if hasattr(item, "text"))
        self.assertIn("completed", message)
        self.assertIn("Do not retry", message)
        self.assertEqual(get_total_invocations(self.db_path), 1)
        event = AuditStore(self.db_path).list_events()[0]
        self.assertEqual(event["decision"], "ALLOW")
        self.assertEqual(event["execution_status"], "OUTCOME_AUDIT_FAILED")
        self.assertIsNotNone(event["execution_started_at"])
        self.assertIsNone(event["execution_completed_at"])

        replay = self._call_tool("search_customer_records", {
            "query": "Acme", "limit": 10, "request_id": "outcome-audit-failure-1",
        }, self.token)
        self.assertTrue(replay.is_error)
        self.assertEqual(get_total_invocations(self.db_path), 1)

    def test_unwritable_outcome_audit_leaves_started_state_and_blocks_replay(self):
        from backend.app.audit.audit_store import AuditStore

        with patch.object(AuditStore, "record_outcome", side_effect=OSError("audit unavailable")), \
             patch.object(AuditStore, "record_outcome_audit_failure", side_effect=OSError("audit unavailable")):
            result = self._call_tool("search_customer_records", {
                "query": "Acme", "limit": 10, "request_id": "unwritable-outcome-audit-1",
            }, self.token)
        self.assertTrue(result.is_error)
        event = AuditStore(self.db_path).list_events()[0]
        self.assertEqual(event["execution_status"], "STARTED")
        replay = self._call_tool("search_customer_records", {
            "query": "Acme", "limit": 10, "request_id": "unwritable-outcome-audit-1",
        }, self.token)
        self.assertTrue(replay.is_error)
        self.assertEqual(get_total_invocations(self.db_path), 1)

    def test_execution_start_audit_failure_prevents_resource_access(self):
        from backend.app.audit.audit_store import AuditStore

        with patch.object(AuditStore, "mark_execution_started", side_effect=OSError("audit unavailable")):
            result = self._call_tool("search_customer_records", {
                "query": "Acme", "limit": 10, "request_id": "start-audit-failure-1",
            }, self.token)
        self.assertTrue(result.is_error)
        self.assertEqual(get_total_invocations(self.db_path), 0)
        event = AuditStore(self.db_path).list_events()[0]
        self.assertEqual(event["execution_status"], "DECISION_RECORDED")

    def test_approval_required_does_not_execute(self):
        result = self._call_tool(
            "export_customer_records", {"format": "json", "limit": 100}, self.token
        )
        self.assertTrue(result.is_error)
        self.assertEqual(get_total_invocations(self.db_path), 0)
        from backend.app.audit.audit_store import AuditStore

        event = AuditStore(self.db_path).list_events()[0]
        self.assertEqual(event["decision"], "REQUIRE_APPROVAL")
        self.assertEqual(event["execution_status"], "PENDING_APPROVAL")


if __name__ == "__main__":
    unittest.main()
