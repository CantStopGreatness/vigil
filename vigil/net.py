"""Outbound HTTP for scans: SSRF-safe connections and size-capped downloads.

Checking a hostname and then letting the HTTP library resolve it again leaves a
window for DNS rebinding: a hostile DNS server answers the check with a public
IP and the real connection with 127.0.0.1. GuardedTransport closes that window
by resolving once, validating every address, and connecting to exactly the
address it validated (TLS still verifies the certificate against the hostname
via SNI).
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl

import httpx

from .target import resolve_host

MAX_PAGE_BYTES = 2 * 1024 * 1024
_MAX_ADDRESSES_TRIED = 3


def legacy_ssl_context(max_tls1_1: bool = False) -> ssl.SSLContext | None:
    """An unverified context that can still talk to TLS 1.0/1.1-only servers.

    Returns None if the local OpenSSL build cannot speak legacy TLS at all.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        if max_tls1_1:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    return ctx


def _ipv4_first(ips: list[str]) -> list[str]:
    return sorted(ips, key=lambda ip: ipaddress.ip_address(ip).version)


class GuardedTransport(httpx.AsyncBaseTransport):
    """Validate the host of every request (including redirects) and pin the connection to it.

    `inner` is a test hook: requests are still validated, then handed to it unchanged.
    """

    def __init__(
        self,
        *,
        allow_private: bool = False,
        verify: ssl.SSLContext | bool = True,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._allow_private = allow_private
        self._verify = verify
        self._inner = inner
        # One pool per hostname: connections are keyed by IP, and two hostnames on the
        # same IP must never share a TLS connection negotiated for the other's SNI.
        self._pools: dict[str, httpx.AsyncHTTPTransport] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        ips = await asyncio.to_thread(resolve_host, host, self._allow_private)
        if self._inner is not None:
            return await self._inner.handle_async_request(request)

        pool = self._pools.get(host)
        if pool is None:
            pool = self._pools[host] = httpx.AsyncHTTPTransport(verify=self._verify, retries=0)
        last_error: httpx.ConnectError | None = None
        for ip in _ipv4_first(ips)[:_MAX_ADDRESSES_TRIED]:
            pinned = httpx.Request(
                request.method,
                request.url.copy_with(host=ip),
                headers=request.headers,  # keeps the original Host header
                stream=request.stream,
                extensions={**request.extensions, "sni_hostname": host},
            )
            try:
                return await pool.handle_async_request(pinned)
            except httpx.ConnectError as e:
                last_error = e
        assert last_error is not None
        raise last_error

    async def aclose(self) -> None:
        for pool in self._pools.values():
            await pool.aclose()
        self._pools.clear()


def make_client(
    *,
    allow_private: bool,
    timeout: float,
    user_agent: str,
    verify: ssl.SSLContext | bool = True,
    inner: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=GuardedTransport(allow_private=allow_private, verify=verify, inner=inner),
        timeout=timeout,
        follow_redirects=True,
        max_redirects=5,
        headers={"User-Agent": user_agent},
        trust_env=False,  # never route scans through an env-configured proxy; pinning needs direct connections
    )


async def fetch_capped(
    client: httpx.AsyncClient, url: str, limit: int = MAX_PAGE_BYTES, **kwargs
) -> httpx.Response:
    """GET url but keep at most `limit` body bytes, so a huge page can't exhaust memory."""
    async with client.stream("GET", url, **kwargs) as r:
        buf = bytearray()
        async for chunk in r.aiter_bytes():
            buf += chunk
            if len(buf) >= limit:
                break
        # The body is already decoded, so drop headers that describe the wire encoding.
        headers = [(k, v) for k, v in r.headers.multi_items()
                   if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
        response = httpx.Response(r.status_code, headers=headers, content=bytes(buf[:limit]), request=r.request)
        response.history = r.history
        return response
