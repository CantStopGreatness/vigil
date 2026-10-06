import socket

import httpx
import pytest

from vigil.checks import tls
from vigil.context import ScanContext
from vigil.net import GuardedTransport, fetch_capped, make_client
from vigil.target import UnsafeTargetError, normalize_target


@pytest.fixture
def captured(monkeypatch):
    """Record what the pinned inner transport is asked to connect to, without any network."""
    seen: list[httpx.Request] = []

    async def fake_handle(self, request):
        seen.append(request)
        return httpx.Response(200, content=b"ok")

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", fake_handle)
    return seen


async def test_connection_is_pinned_to_the_validated_ip(captured):
    async with httpx.AsyncClient(transport=GuardedTransport()) as c:
        r = await c.get("https://example.com:8443/path")
    req = captured[0]
    assert req.url.host == "93.184.216.34" and req.url.port == 8443  # the IP we checked, not a fresh lookup
    assert req.headers["host"] == "example.com:8443"
    assert req.extensions["sni_hostname"] == "example.com"  # cert still verified against the name
    assert str(r.url) == "https://example.com:8443/path"  # callers still see the real URL


async def test_dns_rebinding_cannot_swap_in_a_private_ip(monkeypatch, captured):
    answers = iter(["93.184.216.34", "127.0.0.1"])  # public for the check, private afterwards

    def rebinding(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers), 0))]

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    async with httpx.AsyncClient(transport=GuardedTransport()) as c:
        await c.get("http://rebind.example/")
    assert [r.url.host for r in captured] == ["93.184.216.34"]


async def test_private_answers_are_refused_before_connecting(monkeypatch, captured):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", 0))])
    async with httpx.AsyncClient(transport=GuardedTransport()) as c:
        with pytest.raises(UnsafeTargetError):
            await c.get("http://internal.example/")
    assert captured == []


async def test_fetch_capped_limits_body_and_keeps_headers():
    t = httpx.MockTransport(lambda r: httpx.Response(
        200, content=b"x" * 10_000, headers=[("set-cookie", "a=1"), ("set-cookie", "b=2")]))
    async with make_client(allow_private=False, timeout=5, user_agent="t", inner=t) as c:
        r = await fetch_capped(c, "https://example.com/", limit=100)
    assert len(r.content) == 100
    assert r.headers.get_list("set-cookie") == ["a=1", "b=2"]
    assert str(r.url) == "https://example.com/"


@pytest.mark.parametrize("host,domain", [
    ("www.example.com", "example.com"),
    ("blog.example.co.uk", "example.co.uk"),
    ("example.com", "example.com"),
    ("93.184.216.34", "93.184.216.34"),
])
def test_registrable_domain_uses_public_suffix_list(host, domain):
    assert ScanContext(target=normalize_target(host), client=None).registrable_domain == domain


def test_tls_only_legacy_server_is_reported(monkeypatch):
    def handshake(host, port, ctx, ip=None):
        raise __import__("ssl").SSLError("unsupported protocol")
    monkeypatch.setattr(tls, "_handshake", handshake)
    monkeypatch.setattr(tls, "_legacy_supported", lambda *a: "TLSv1")
    assert [f.title for f in tls.inspect("example.com", 443)] == ["Server only supports obsolete TLSv1"]
