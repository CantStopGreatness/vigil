"""Target parsing and SSRF protection.

When the scanner runs as a public web service, users control the URL we fetch.
Without a guard, someone could point it at http://169.254.169.254/ (cloud
metadata) or http://localhost:6379/ and use *our* server to reach internal
systems. That is Server-Side Request Forgery (SSRF). We resolve every hostname
and refuse anything that lands on a non-public address.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class InvalidTargetError(ValueError):
    pass


class UnsafeTargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int

    @property
    def url_host(self) -> str:
        """Host as it must appear in a URL (IPv6 literals need brackets)."""
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{self.url_host}{port}/"

    @property
    def origin(self) -> str:
        return self.url.rstrip("/")


def normalize_target(raw: str) -> Target:
    """Turn user input like 'example.com' or 'https://Example.com/path' into a Target."""
    raw = (raw or "").strip()
    if not raw:
        raise InvalidTargetError("No target given")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise InvalidTargetError(f"Unsupported scheme: {parts.scheme}")
    if parts.username or parts.password:
        raise InvalidTargetError("Credentials in URLs are not allowed")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise InvalidTargetError("Missing hostname")
    if not (_is_ip(host) or _HOST_RE.match(host)):
        raise InvalidTargetError(f"Invalid hostname: {host}")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as e:
        raise InvalidTargetError(str(e)) from e
    return Target(scheme=parts.scheme, host=host, port=port)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def _resolve(host: str) -> list[str]:
    if _is_ip(host):
        return [host]
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise InvalidTargetError(f"Could not resolve {host}") from e
    return sorted({info[4][0].split("%", 1)[0] for info in infos})


def assert_public_host(host: str) -> list[str]:
    """Resolve host and raise UnsafeTargetError if any address is non-public.

    Returns the resolved addresses. Checking *every* address matters: a host
    with one public and one private A record should still be rejected.
    """
    ips = _resolve(host)
    blocked = [ip for ip in ips if not is_public_ip(ip)]
    if blocked:
        raise UnsafeTargetError(f"{host} resolves to non-public address {blocked[0]}; refusing to scan")
    return ips


def resolve_host(host: str, allow_private: bool = False) -> list[str]:
    """Resolve host to the addresses a scan may connect to."""
    return _resolve(host) if allow_private else assert_public_host(host)
