"""End-to-end scans against a fake site served by httpx.MockTransport (no network)."""

import socket

import httpx
import pytest

from vigil.checks import cookies, disclosure, exposure, headers, transport
from vigil.models import Finding, Severity
from vigil.report import render_html
from vigil.scanner import scan
from vigil.scoring import score
from vigil.target import UnsafeTargetError

OFFLINE_CHECKS = [transport, headers, cookies, disclosure, exposure]  # skip raw-socket TLS and DNS


def site(routes, default=(404, b"not found")):
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.startswith("http://"):
            return httpx.Response(301, headers={"location": url.replace("http://", "https://", 1)})
        status, body, *hdrs = routes.get(request.url.path, default)
        return httpx.Response(status, content=body, headers=hdrs[0] if hdrs else {})
    return httpx.MockTransport(handler)


HARDENED = {
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
}


async def test_hardened_site_gets_an_a():
    t = site({
        "/": (200, b"<html>hi</html>", HARDENED),
        "/.well-known/security.txt": (200, b"Contact: mailto:sec@example.com\n"),
    })
    r = await scan("example.com", checks=OFFLINE_CHECKS, transport=t)
    assert r.grade == "A" and r.score == 100
    assert r.findings == []
    assert set(r.passed) == {c.NAME for c in OFFLINE_CHECKS}


async def test_leaky_site_is_capped_and_secrets_are_masked():
    t = site({
        "/": (200, b"<html>hi</html>", HARDENED),
        "/.env": (200, b"DB_PASSWORD=supersecret123\n"),
    })
    r = await scan("example.com", checks=OFFLINE_CHECKS, transport=t)
    env = next(f for f in r.findings if f.title == "Environment file exposed")
    assert env.severity is Severity.CRITICAL
    assert "supersecret123" not in env.evidence
    assert r.score <= 50 and r.grade == "F"
    assert r.findings[0].severity is Severity.CRITICAL  # sorted most severe first


async def test_soft_404_site_has_no_exposure_false_positives():
    t = site({}, default=(200, b"<!doctype html><html>Not found</html>", HARDENED))
    r = await scan("example.com", checks=[exposure], transport=t)
    assert [f.title for f in r.findings] == ["No security.txt"]


async def test_redirect_to_private_ip_is_blocked(monkeypatch):
    def fake(host, *a, **k):
        ip = "127.0.0.1" if host == "internal.example" else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake)

    def handler(request):
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "http://internal.example/admin"})
        return httpx.Response(200, content=b"secret admin panel")

    with pytest.raises(UnsafeTargetError):
        await scan("example.com", checks=OFFLINE_CHECKS, transport=httpx.MockTransport(handler))


async def test_crashing_check_is_reported_not_fatal():
    class Boom:
        NAME = "Boom"

        @staticmethod
        async def run(ctx):
            raise RuntimeError("kaboom")

    t = site({"/": (200, b"ok", HARDENED)})
    r = await scan("example.com", checks=[headers, Boom], transport=t)
    assert any("kaboom" in e for e in r.errors)
    assert "Boom" not in r.passed


def test_scoring():
    f = lambda s: Finding("x", "t", s, "d")  # noqa: E731
    assert score([]) == (100, "A")
    assert score([f(Severity.MEDIUM)] * 2) == (84, "B")
    assert score([f(Severity.CRITICAL)]) == (50, "F")
    assert score([f(Severity.HIGH)] * 10) == (0, "F")


async def test_html_report_escapes_attacker_content():
    t = site({"/": (200, b"x", {"server": "<script>alert(1)</script>/1.0"})})
    r = await scan("example.com", checks=[disclosure], transport=t)
    html = render_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


async def test_secrets_with_short_or_spaced_values_are_masked():
    t = site({
        "/": (200, b"<html>hi</html>", HARDENED),
        "/.env": (200, b"DB_PASSWORD=my secret phrase\nPIN=42\n"),
    })
    r = await scan("example.com", checks=[exposure], transport=t)
    env = next(f for f in r.findings if f.title == "Environment file exposed")
    assert "secret" not in env.evidence and "42" not in env.evidence


async def test_unreachable_site_raises_connection_error():
    def handler(request):
        raise httpx.ConnectError("All connection attempts failed", request=request)

    with pytest.raises(ConnectionError):
        await scan("example.com", checks=OFFLINE_CHECKS, transport=httpx.MockTransport(handler))
