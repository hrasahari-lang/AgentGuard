"""Regression tests for MCP endpoints configured on bearer-token clients."""
from __future__ import annotations

import asyncio
import os
import unittest
from argparse import Namespace
from unittest.mock import patch

from demo.endpoint_validation import EndpointValidationError, validate_mcp_endpoint


class TestMcpEndpointValidation(unittest.TestCase):
    def test_loopback_http_and_remote_https_are_accepted(self):
        accepted = (
            "http://localhost:8000/mcp",
            "http://127.0.0.1:8000/mcp",
            "http://127.42.0.9:8000/mcp",
            "http://[::1]:8000/mcp",
            "https://gateway.example.com/mcp",
            "https://203.0.113.20/mcp",
        )
        for endpoint in accepted:
            with self.subTest(endpoint=endpoint):
                self.assertEqual(validate_mcp_endpoint(endpoint), endpoint)

    def test_remote_http_unsupported_schemes_and_ambiguous_urls_are_rejected(self):
        rejected = (
            "http://gateway.example.com/mcp",
            "http://2130706433/mcp",
            "http://0177.0.0.1/mcp",
            "ftp://gateway.example.com/mcp",
            "//gateway.example.com/mcp",
            "https://user:password@gateway.example.com/mcp",
            "https://gateway.example.com:/mcp",
            "https://[2001:db8::1/mcp",
            "https://gateway.example.com/mcp?token=x",
            "https://gateway.example.com\\@127.0.0.1/mcp",
            "https://gateway.example.com./mcp",
            " https://gateway.example.com/mcp",
        )
        for endpoint in rejected:
            with self.subTest(endpoint=endpoint), self.assertRaises(EndpointValidationError):
                validate_mcp_endpoint(endpoint)

    def test_both_agents_reject_remote_http_before_constructing_http_client(self):
        env = {"AGENTGUARD_TOKEN": "test-token", "AGENTGUARD_MCP_URL": "http://gateway.example.com/mcp"}
        with patch.dict(os.environ, env, clear=False):
            with patch("demo.managed_agent.parse_args", return_value=Namespace(limit=10, request_id=None, query="Acme")):
                with patch("demo.managed_agent.httpx2.AsyncClient") as client:
                    self.assertEqual(asyncio.run(self._managed_run()), 2)
                    client.assert_not_called()
            with patch("demo.external_agent.httpx2.AsyncClient") as client:
                self.assertEqual(asyncio.run(self._external_run()), 2)
                client.assert_not_called()

    @staticmethod
    async def _managed_run():
        from demo.managed_agent import run

        return await run()

    @staticmethod
    async def _external_run():
        from demo.external_agent import run

        return await run()


if __name__ == "__main__":
    unittest.main()
