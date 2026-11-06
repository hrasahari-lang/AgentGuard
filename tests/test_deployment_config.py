"""Focused tests for hosted CORS and environment credential bootstrap."""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from backend.app.config import (
    DEFAULT_CORS_ORIGINS,
    DEFAULT_MCP_ALLOWED_HOSTS,
    get_cors_origins,
    get_mcp_allowed_hosts,
)
from backend.app.gateway.mcp_server import create_gateway_app
from backend.app.security.auth import (
    AgentAuthenticator,
    bootstrap_environment_credentials,
    revoke_agent_credentials,
)


class TestCorsOriginConfiguration(unittest.TestCase):
    def test_exact_frontend_origin_is_read_from_environment(self):
        with patch.dict(os.environ, {
            "AGENTGUARD_CORS_ORIGINS": "https://agent-guard-duo-x.vercel.app",
        }):
            self.assertEqual(get_cors_origins(), ["https://agent-guard-duo-x.vercel.app"])

    def test_unset_cors_setting_keeps_local_development_origins(self):
        with patch.dict(os.environ):
            os.environ.pop("AGENTGUARD_CORS_ORIGINS", None)
            self.assertEqual(get_cors_origins(), list(DEFAULT_CORS_ORIGINS))

    def test_cors_rejects_wildcards_paths_and_remote_http(self):
        for value in (
            "*",
            "https://agent-guard-duo-x.vercel.app/path",
            "http://dashboard.example.com",
            "https://dashboard.example.com:443",
            "https://good.example.com,",
        ):
            with self.subTest(value=value), patch.dict(
                os.environ, {"AGENTGUARD_CORS_ORIGINS": value}
            ), self.assertRaises(ValueError):
                get_cors_origins()


class TestMcpHostConfiguration(unittest.TestCase):
    def test_default_allowlist_has_local_development_and_the_configured_render_host(self):
        with patch.dict(os.environ):
            os.environ.pop("AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS", None)
            hosts = get_mcp_allowed_hosts()
        self.assertEqual(hosts, list(DEFAULT_MCP_ALLOWED_HOSTS))
        self.assertIn("agentguard-api-g87x.onrender.com", hosts)

    def test_configured_mcp_hostnames_are_exact_and_canonical(self):
        with patch.dict(os.environ, {
            "AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS": "gateway.example.com,agentguard.example.net",
        }):
            hosts = get_mcp_allowed_hosts()
        self.assertIn("gateway.example.com", hosts)
        self.assertIn("agentguard.example.net", hosts)
        self.assertNotIn("*.example.com", hosts)
        self.assertNotIn("agentguard-api-g87x.onrender.com", hosts)

    def test_mcp_host_allowlist_rejects_wildcards_urls_ports_and_noncanonical_names(self):
        for value in (
            "*.example.com",
            "https://gateway.example.com",
            "gateway.example.com:443",
            "gateway.example.com.",
            "Gateway.example.com",
            "gateway.example.com,",
            "gateway.example.com,gateway.example.com",
        ):
            with self.subTest(value=value), patch.dict(
                os.environ, {"AGENTGUARD_MCP_SERVER_ALLOWED_HOSTS": value}
            ), self.assertRaises(ValueError):
                get_mcp_allowed_hosts()


class TestEnvironmentCredentialBootstrap(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "bootstrap.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    @staticmethod
    def _token() -> str:
        return secrets.token_urlsafe(32)

    def _configured(self, admin_token: str, demo_token: str):
        return patch.dict(os.environ, {
            "AGENTGUARD_BOOTSTRAP_ADMIN_TOKEN": admin_token,
            "AGENTGUARD_BOOTSTRAP_DEMO_AGENT_TOKEN": demo_token,
        })

    def test_bootstrap_is_idempotent_and_persists_only_hashes(self):
        admin_token, demo_token = self._token(), self._token()
        with self._configured(admin_token, demo_token):
            create_gateway_app(self.db_path)
            create_gateway_app(self.db_path)

        authenticator = AgentAuthenticator(self.db_path)
        admin, admin_failure = authenticator.authenticate(admin_token)
        demo, demo_failure = authenticator.authenticate(demo_token)
        self.assertIsNone(admin_failure)
        self.assertIsNone(demo_failure)
        self.assertEqual((admin.agent_id, admin.is_admin), ("agent_admin", True))
        self.assertEqual((demo.agent_id, demo.is_admin), ("agent_sales_1", False))

        with closing(sqlite3.connect(self.db_path)) as connection:
            rows = connection.execute(
                "SELECT agent_id, token_hash, is_admin, active FROM agent_credentials"
            ).fetchall()
        self.assertEqual(len(rows), 2)
        hashes = {row[1] for row in rows}
        self.assertEqual(hashes, {
            hashlib.sha256(admin_token.encode()).hexdigest(),
            hashlib.sha256(demo_token.encode()).hexdigest(),
        })
        self.assertNotIn(admin_token, repr(rows))
        self.assertNotIn(demo_token, repr(rows))

    def test_rotating_environment_tokens_deactivates_previous_credentials(self):
        old_admin, old_demo = self._token(), self._token()
        new_admin, new_demo = self._token(), self._token()
        with self._configured(old_admin, old_demo):
            bootstrap_environment_credentials(self.db_path)
        with self._configured(new_admin, new_demo):
            bootstrap_environment_credentials(self.db_path)

        authenticator = AgentAuthenticator(self.db_path)
        self.assertIsNone(authenticator.authenticate(old_admin)[0])
        self.assertIsNone(authenticator.authenticate(old_demo)[0])
        self.assertEqual(authenticator.authenticate(new_admin)[0].agent_id, "agent_admin")
        self.assertEqual(authenticator.authenticate(new_demo)[0].agent_id, "agent_sales_1")
        with closing(sqlite3.connect(self.db_path)) as connection:
            active = connection.execute(
                "SELECT agent_id, COUNT(*) FROM agent_credentials WHERE active=1 GROUP BY agent_id"
            ).fetchall()
        self.assertEqual(dict(active), {"agent_admin": 1, "agent_sales_1": 1})

    def test_bootstrap_does_not_reactivate_a_revoked_token_on_restart(self):
        admin_token, demo_token = self._token(), self._token()
        with self._configured(admin_token, demo_token):
            bootstrap_environment_credentials(self.db_path)
            self.assertEqual(revoke_agent_credentials("agent_admin", db_path=self.db_path), 1)
            bootstrap_environment_credentials(self.db_path)

        authenticator = AgentAuthenticator(self.db_path)
        self.assertIsNone(authenticator.authenticate(admin_token)[0])
        self.assertEqual(authenticator.authenticate(demo_token)[0].agent_id, "agent_sales_1")

    def test_partial_duplicate_or_weak_bootstrap_configuration_fails_closed(self):
        with patch.dict(os.environ, {
            "AGENTGUARD_BOOTSTRAP_ADMIN_TOKEN": self._token(),
        }), self.assertRaisesRegex(ValueError, "Both bootstrap"):
            bootstrap_environment_credentials(self.db_path)

        token = self._token()
        with self._configured(token, token), self.assertRaisesRegex(ValueError, "distinct"):
            bootstrap_environment_credentials(self.db_path)

        with self._configured("too-short", self._token()), self.assertRaisesRegex(ValueError, "43 characters"):
            bootstrap_environment_credentials(self.db_path)


if __name__ == "__main__":
    unittest.main()
