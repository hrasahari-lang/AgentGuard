"""Strict URL validation for MCP clients carrying AgentGuard credentials."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


class EndpointValidationError(ValueError):
    """Raised when an MCP endpoint could expose a bearer credential."""


_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_NUMERIC_LABEL = re.compile(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)\Z")


def validate_mcp_endpoint(endpoint: str) -> str:
    """Accept HTTPS endpoints, or HTTP only for unambiguous loopback hosts."""
    if not isinstance(endpoint, str) or not endpoint or endpoint != endpoint.strip():
        raise EndpointValidationError("MCP endpoint must be an absolute URL.")
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in endpoint) or "\\" in endpoint:
        raise EndpointValidationError("MCP endpoint contains invalid characters.")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise EndpointValidationError("MCP endpoint is malformed.") from None

    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise EndpointValidationError("MCP endpoint must use HTTP or HTTPS and include a host.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise EndpointValidationError("MCP endpoint must not contain embedded credentials.")
    if any(mark in endpoint for mark in "?#") or parsed.query or parsed.fragment:
        raise EndpointValidationError("MCP endpoint must not contain a query or fragment.")
    if "%" in parsed.netloc or parsed.netloc.endswith(":") or port == 0:
        raise EndpointValidationError("MCP endpoint contains an ambiguous host or port.")

    host = hostname.lower()
    if host.endswith(".") or "[" in host or "]" in host:
        raise EndpointValidationError("MCP endpoint contains an ambiguous host representation.")

    loopback = host == "localhost"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.version == 4 and str(address) != host:
            raise EndpointValidationError("MCP endpoint contains a non-canonical IP address.")
        if address.version == 6 and not parsed.netloc.startswith("["):
            raise EndpointValidationError("IPv6 MCP endpoints must use brackets.")
        loopback = address.is_loopback
    else:
        labels = host.split(".")
        if not all(_DNS_LABEL.fullmatch(label) for label in labels):
            raise EndpointValidationError("MCP endpoint contains an invalid hostname.")
        if len(host) > 253 or all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
            raise EndpointValidationError("MCP endpoint contains an ambiguous numeric hostname.")

    if parsed.scheme == "http" and not loopback:
        raise EndpointValidationError("Remote MCP endpoints must use HTTPS.")
    return endpoint
