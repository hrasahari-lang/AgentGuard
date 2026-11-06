"""HTTP transport that dials only the addresses accepted by endpoint validation."""
from __future__ import annotations

import httpx2

from demo.endpoint_validation import ValidatedMcpEndpoint


class PinnedAddressTransport(httpx2.AsyncBaseTransport):
    """Dial one validated literal IP while retaining the configured HTTP/TLS host.

    The inner transport receives a URL whose host is the selected validated IP,
    so it cannot perform a second DNS lookup for the configured hostname. The
    original hostname is retained in Host and the ``sni_hostname`` extension;
    httpcore2 uses that value as TLS server_hostname, preserving SNI and
    certificate hostname verification. Ambient proxy settings are disabled.
    """

    def __init__(
        self,
        endpoint: ValidatedMcpEndpoint,
        *,
        inner_transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        if not isinstance(endpoint, ValidatedMcpEndpoint) or not endpoint.addresses:
            raise ValueError("A resolved and validated MCP endpoint is required.")
        self._endpoint = endpoint
        # Never retry via a hostname or an address outside the validated set.
        self._pinned_host = endpoint.addresses[0].compressed
        self._inner = inner_transport or httpx2.AsyncHTTPTransport(trust_env=False)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        request_port = request.url.port or (443 if request.url.scheme == "https" else 80)
        if (
            request.url.scheme != self._endpoint.scheme
            or request.url.host.lower() != self._endpoint.hostname
            or request_port != self._endpoint.port
            or bool(request.url.username)
            or bool(request.url.password)
        ):
            raise httpx2.RequestError(
                "MCP request escaped the validated endpoint origin.", request=request
            )

        headers = request.headers.copy()
        headers["Host"] = self._endpoint.host_header
        extensions = dict(request.extensions)
        if self._endpoint.scheme == "https":
            extensions["sni_hostname"] = self._endpoint.hostname
        else:
            extensions.pop("sni_hostname", None)

        pinned_request = httpx2.Request(
            request.method,
            request.url.copy_with(host=self._pinned_host),
            headers=headers,
            stream=request.stream,
            extensions=extensions,
        )
        return await self._inner.handle_async_request(pinned_request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def create_pinned_mcp_http_client(endpoint: ValidatedMcpEndpoint, token: str) -> httpx2.AsyncClient:
    """Create the shared bearer client used by both bundled MCP agents."""
    if not token:
        raise ValueError("A non-empty AgentGuard bearer credential is required.")
    return httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        follow_redirects=False,
        trust_env=False,
        transport=PinnedAddressTransport(endpoint),
    )
