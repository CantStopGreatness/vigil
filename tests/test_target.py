import socket

import pytest

from vigil.target import (
    InvalidTargetError,
    UnsafeTargetError,
    assert_public_host,
    is_public_ip,
    normalize_target,
)


@pytest.mark.parametrize("raw,url", [
    ("example.com", "https://example.com/"),
    ("HTTPS://Example.COM/some/path?q=1", "https://example.com/"),
    ("http://example.com:8080", "http://example.com:8080/"),
    ("https://example.com:443", "https://example.com/"),
])
def test_normalize(raw, url):
    assert normalize_target(raw).url == url


@pytest.mark.parametrize("raw", ["", "ftp://example.com", "https://user:pw@example.com", "https://exa mple.com",
                                 "javascript:alert(1)"])
def test_rejects_bad_input(raw):
    with pytest.raises(InvalidTargetError):
        normalize_target(raw)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0",
                                "::ffff:127.0.0.1", "100.64.0.1"])
def test_private_ips_are_not_public(ip):
    assert not is_public_ip(ip)


def test_public_ip():
    assert is_public_ip("93.184.216.34")


def test_blocks_host_resolving_to_metadata_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))])
    with pytest.raises(UnsafeTargetError):
        assert_public_host("evil.example")


def test_blocks_if_any_record_is_private(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
    ])
    with pytest.raises(UnsafeTargetError):
        assert_public_host("mixed.example")


def test_ipv6_literal_is_bracketed_in_url():
    assert normalize_target("http://[2001:db8::1]:8080/x").url == "http://[2001:db8::1]:8080/"
