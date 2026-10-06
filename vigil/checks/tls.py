"""TLS certificate validity, expiry and protocol versions."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

import certifi

from ..context import ScanContext
from ..models import Finding, Severity
from ..net import legacy_ssl_context
from ..target import resolve_host

NAME = "TLS / certificate"
TIMEOUT = 8


def _handshake(host: str, port: int, ctx: ssl.SSLContext, ip: str | None = None) -> tuple[str | None, dict]:
    # Connect to the already-validated IP (no second DNS lookup), but verify the cert for `host`.
    with socket.create_connection((ip or host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version(), tls.getpeercert() or {}


def _legacy_supported(host: str, port: int, ip: str | None = None) -> str | None:
    """Return 'TLSv1'/'TLSv1.1' if the server still accepts it, else None."""
    ctx = legacy_ssl_context(max_tls1_1=True)
    if ctx is None:
        return None  # local OpenSSL can't even speak legacy TLS; can't test
    try:
        version, _ = _handshake(host, port, ctx, ip)
        return version
    except (OSError, ssl.SSLError):
        return None


def inspect(host: str, port: int, now: datetime | None = None, ip: str | None = None) -> list[Finding]:
    now = now or datetime.now(UTC)
    out: list[Finding] = []
    try:
        # Use the same CA bundle as httpx; the OS store can be empty (e.g. python.org macOS builds).
        version, cert = _handshake(host, port, ssl.create_default_context(cafile=certifi.where()), ip)
    except ssl.SSLCertVerificationError as e:
        return [Finding(
            NAME, "Invalid TLS certificate", Severity.CRITICAL,
            "Browsers will show a full-page security warning, and users who click through are open "
            "to interception.",
            "Install a certificate that is valid for this hostname and signed by a trusted CA.",
            evidence=e.verify_message or str(e),
        )]
    except (OSError, ssl.SSLError) as e:
        legacy = _legacy_supported(host, port, ip) if isinstance(e, ssl.SSLError) else None
        if legacy:
            return [Finding(
                NAME, f"Server only supports obsolete {legacy}", Severity.HIGH,
                "TLS 1.0/1.1 are deprecated (RFC 8996); modern browsers refuse to connect to this site at all.",
                "Enable TLS 1.2 and 1.3, then disable TLS 1.0 and 1.1.",
                evidence=str(e),
            )]
        return [Finding(
            NAME, "TLS handshake failed", Severity.HIGH,
            "Could not establish a TLS connection on this port.",
            "Check the server's TLS configuration.",
            evidence=str(e),
        )]

    not_after = cert.get("notAfter")
    if not_after:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
        days = (expires - now).days
        if days < 14:
            out.append(Finding(
                NAME, "Certificate expires very soon", Severity.HIGH,
                f"The certificate expires in {days} day(s). After that, every visitor sees a security error.",
                "Renew now and automate renewal (e.g. certbot / ACME).", evidence=f"notAfter={not_after}",
            ))
        elif days < 30:
            out.append(Finding(
                NAME, "Certificate expires within 30 days", Severity.MEDIUM,
                f"The certificate expires in {days} days.",
                "Renew soon and confirm automatic renewal works.", evidence=f"notAfter={not_after}",
            ))

    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding(
            NAME, f"Negotiated obsolete protocol {version}", Severity.HIGH,
            "TLS 1.0/1.1 are deprecated (RFC 8996) and have known weaknesses.",
            "Disable TLS 1.0/1.1; support TLS 1.2 and 1.3 only.",
        ))
    else:
        legacy = _legacy_supported(host, port, ip)
        if legacy:
            out.append(Finding(
                NAME, f"Server still accepts {legacy}", Severity.MEDIUM,
                "TLS 1.0/1.1 are deprecated (RFC 8996). Supporting them enables downgrade-style attacks "
                "and fails compliance standards such as PCI DSS.",
                "Disable TLS 1.0 and 1.1 in the server configuration.",
            ))
    return out


async def run(ctx: ScanContext) -> list[Finding] | None:
    if not ctx.is_https:
        return None  # not applicable; the transport check reports plain HTTP
    if ctx.response is not None:
        u = ctx.response.url
        host, port = u.host, u.port or 443
    else:
        host, port = ctx.target.host, ctx.target.port
    ips = await asyncio.to_thread(resolve_host, host, ctx.allow_private)
    return await asyncio.to_thread(inspect, host, port, None, ips[0])
