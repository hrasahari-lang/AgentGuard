"""Strict URL validation for MCP clients carrying AgentGuard credentials."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit


class EndpointValidationError(ValueError):
    """Raised when an MCP endpoint could expose a bearer credential."""


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_ENDPOINT_VALIDATION_AUTHORITY = object()


@dataclass(frozen=True, init=False)
class ValidatedMcpEndpoint:
    """An endpoint and the literal destinations approved during validation."""

    url: str
    scheme: str
    hostname: str
    port: int
    host_header: str
    addresses: tuple[IPAddress, ...]

    def __init__(
        self,
        *,
        url: str,
        scheme: str,
        hostname: str,
        port: int,
        host_header: str,
        addresses: tuple[IPAddress, ...],
        _authority: object | None = None,
    ) -> None:
        if _authority is not _ENDPOINT_VALIDATION_AUTHORITY:
            raise TypeError("Validated MCP endpoints are issued only by the endpoint resolver.")
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "port", port)
        object.__setattr__(self, "host_header", host_header)
        object.__setattr__(self, "addresses", addresses)


_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_NUMERIC_LABEL = re.compile(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)\Z")
_IPV6_6TO4 = ipaddress.IPv6Network("2002::/16")


def _normalize_configured_hosts(values: Iterable[str] | str | None, env_name: str) -> set[str]:
    if values is None:
        raw = os.getenv(env_name, "")
        entries = [] if not raw.strip() else raw.split(",")
    elif isinstance(values, str):
        entries = [] if not values.strip() else values.split(",")
    else:
        entries = list(values)

    hosts: set[str] = set()
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            raise EndpointValidationError(f"{env_name} contains an empty or invalid host.")
        host = entry.strip().lower()
        if host != entry.strip() or host.startswith("[") or host.endswith("]"):
            raise EndpointValidationError(f"{env_name} must contain bare canonical hosts.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if host.endswith(".") or len(host) > 253:
                raise EndpointValidationError(f"{env_name} contains an invalid hostname.") from None
            labels = host.split(".")
            if not all(_DNS_LABEL.fullmatch(label) for label in labels):
                raise EndpointValidationError(f"{env_name} contains an invalid hostname.")
            if all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
                raise EndpointValidationError(f"{env_name} contains an ambiguous numeric hostname.")
            hosts.add(host)
        else:
            hosts.add(address.compressed)
    return hosts


def _resolve_addresses(
    host: str,
    port: int,
    resolver: Callable[..., Iterable[tuple]] | None,
) -> tuple[IPAddress, ...]:
    resolve = resolver or socket.getaddrinfo
    try:
        records = resolve(host, port, type=socket.SOCK_STREAM)
        addresses = {ipaddress.ip_address(record[4][0]) for record in records}
        if any(isinstance(address, ipaddress.IPv6Address) and address.scope_id for address in addresses):
            raise ValueError("scoped IPv6 answers are not accepted")
    except (OSError, ValueError, IndexError, TypeError):
        raise EndpointValidationError("MCP endpoint DNS resolution failed or returned invalid addresses.") from None
    if not addresses:
        raise EndpointValidationError("MCP endpoint DNS resolution returned no addresses.")
    return tuple(sorted(addresses, key=lambda address: (address.version, int(address))))


def _is_public_address(address: IPAddress) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return _is_public_address(address.ipv4_mapped)
    if isinstance(address, ipaddress.IPv6Address) and address in _IPV6_6TO4:
        # 6to4 embeds an IPv4 destination; reject the transition range rather
        # than risk an encapsulated route to a non-public IPv4 address.
        return False
    return address.is_global and not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    )


def _make_validated_endpoint(endpoint: str, scheme: str, host: str, port: int, addresses: Iterable[IPAddress]) -> ValidatedMcpEndpoint:
    default_port = 443 if scheme == "https" else 80
    host_header = f"[{host}]" if ":" in host else host
    if port != default_port:
        host_header = f"{host_header}:{port}"
    return ValidatedMcpEndpoint(
        url=endpoint,
        scheme=scheme,
        hostname=host,
        port=port,
        host_header=host_header,
        addresses=tuple(addresses),
        _authority=_ENDPOINT_VALIDATION_AUTHORITY,
    )


def resolve_mcp_endpoint(
    endpoint: str,
    *,
    trusted_hosts: Iterable[str] | str | None = None,
    resolver: Callable[..., Iterable[tuple]] | None = None,
) -> ValidatedMcpEndpoint:
    """Validate endpoint trust and retain only the exact addresses to dial.

    Remote HTTPS hosts must be named in ``AGENTGUARD_TRUSTED_MCP_HOSTS``. Hosts
    must resolve only to globally routable addresses. The returned address set
    is used by the HTTP transport as literal socket destinations, while the
    original hostname remains the HTTP Host authority and TLS verification name.
    HTTP is limited to verified loopback destinations for local development.
    """
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
        host_key = address.compressed
        loopback = address.is_loopback
    else:
        labels = host.split(".")
        if not all(_DNS_LABEL.fullmatch(label) for label in labels):
            raise EndpointValidationError("MCP endpoint contains an invalid hostname.")
        if len(host) > 253 or all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
            raise EndpointValidationError("MCP endpoint contains an ambiguous numeric hostname.")
        host_key = host

    port_for_resolution = port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "http":
        if not loopback:
            raise EndpointValidationError("Remote MCP endpoints must use HTTPS.")
        if address is None:
            addresses = _resolve_addresses(host_key, port_for_resolution, resolver)
            if not all(resolved.is_loopback for resolved in addresses):
                raise EndpointValidationError("HTTP development endpoints must resolve only to loopback addresses.")
        else:
            addresses = (address,)
        return _make_validated_endpoint(endpoint, parsed.scheme, host_key, port_for_resolution, addresses)

    approved_hosts = _normalize_configured_hosts(trusted_hosts, "AGENTGUARD_TRUSTED_MCP_HOSTS")
    if host_key not in approved_hosts:
        raise EndpointValidationError("Remote MCP endpoint host is not explicitly trusted.")

    addresses = (address,) if address is not None else _resolve_addresses(host_key, port_for_resolution, resolver)
    if any(not _is_public_address(resolved) for resolved in addresses):
        raise EndpointValidationError(
            "Remote MCP endpoints must resolve only to globally routable addresses."
        )
    return _make_validated_endpoint(endpoint, parsed.scheme, host_key, port_for_resolution, addresses)


def validate_mcp_endpoint(
    endpoint: str,
    *,
    trusted_hosts: Iterable[str] | str | None = None,
    resolver: Callable[..., Iterable[tuple]] | None = None,
) -> str:
    """Compatibility validator returning the original URL after full resolution."""
    return resolve_mcp_endpoint(endpoint, trusted_hosts=trusted_hosts, resolver=resolver).url
