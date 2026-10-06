import httpx
import pytest

from vigil.context import ScanContext
from vigil.target import normalize_target


def make_response(url="https://example.com/", status=200, headers=None, body=b"<html></html>"):
    return httpx.Response(status, headers=headers or {}, content=body, request=httpx.Request("GET", url))


@pytest.fixture
def ctx_factory():
    """Build a ScanContext around a canned response, with no network."""
    def build(headers=None, body=b"<html></html>", url="https://example.com/", http_response=None):
        target = normalize_target(url)
        return ScanContext(
            target=target,
            client=None,  # checks under test don't make requests
            response=make_response(url, headers=headers, body=body),
            http_response=http_response,
        )
    return build


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch):
    """Pretend every hostname resolves to a public IP so tests never hit real DNS."""
    import socket

    def fake_getaddrinfo(host, *a, **k):
        ip = host if host.replace(".", "").isdigit() else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
