"""HTTP integration tests for the authenticated MCP gateway vertical slice."""
from __future__ import annotations

import asyncio
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

import httpx2
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from backend.app.crm_repository import CrmRepository, get_total_invocations
from backend.app.gateway.mcp_server import create_gateway_app
from backend.app.security.auth import AgentAuthenticator, issue_agent_token, revoke_agent_credentials


class TestAuthenticatedMcpGateway(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "gateway.db"
        self.repo = CrmRepository(self.db_path)
        # Create and seed the CRM tables before provisioning credentials.
        from backend.app.database import init_db

        init_db(self.db_path)
        self.token = issue_agent_token("agent_sales_1", db_path=self.db_path)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        self.port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        self.server = uvicorn.Server(uvicorn.Config(
            create_gateway_app(self.db_path), host="127.0.0.1", port=self.port,
            log_level="critical", lifespan="on",
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
