"""Scan orchestration: fetch the target once, then run every check concurrently."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import httpx

from . import __version__
from .checks import ALL_CHECKS
from .context import ScanContext
from .models import ScanResult, Severity
from .net import fetch_capped, legacy_ssl_context, make_client
from .scoring import score
from .target import normalize_target, resolve_host

USER_AGENT = f"Vigil/{__version__} (+https://github.com/CantStopGreatness/vigil; authorized security scan)"


def _tls_problem(e: Exception) -> bool:
    msg = str(e).upper()
    return any(k in msg for k in ("CERTIFICATE", "SSL", "TLS", "HANDSHAKE"))


async def scan(
    raw_target: str,
    *,
    checks=None,
    allow_private: bool = False,
    timeout: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ScanResult:
    target = normalize_target(raw_target)
    await asyncio.to_thread(resolve_host, target.host, allow_private)

    started = datetime.now(UTC)
    t0 = time.perf_counter()
    errors: list[str] = []

    def client(verify=True) -> httpx.AsyncClient:
        return make_client(allow_private=allow_private, timeout=timeout, user_agent=USER_AGENT,
                           verify=verify, inner=transport)

    async with client() as http:
        ctx = ScanContext(target=target, client=http, allow_private=allow_private)

        try:
            ctx.response = await fetch_capped(http, target.url)
        except httpx.ConnectError as e:
            # Usually an invalid certificate or a server that only speaks TLS 1.0/1.1.
            # Fetch without verification (and with legacy protocols allowed) so the other
            # checks can still run; the TLS check reports the underlying problem itself.
            if target.scheme != "https" or not _tls_problem(e):
                raise ConnectionError(f"Could not fetch {target.url}: {e}") from e
            try:
                async with client(verify=legacy_ssl_context() or False) as insecure:
                    ctx.response = await fetch_capped(insecure, target.url)
            except httpx.HTTPError as e2:
                raise ConnectionError(f"Could not fetch {target.url}: {e2}") from e2
            errors.append("TLS verification or negotiation failed; page fetched without verification")
        except httpx.HTTPError as e:
            raise ConnectionError(f"Could not fetch {target.url}: {e}") from e

        if target.scheme == "https":
            http_url = f"http://{target.url_host}/"
            try:
                ctx.http_response = await fetch_capped(http, http_url, limit=65536)
            except httpx.HTTPError:
                # The chain broke somewhere (e.g. bad cert on the HTTPS hop); judge the first hop alone.
                try:
                    ctx.http_response = await fetch_capped(http, http_url, limit=65536, follow_redirects=False)
                except httpx.HTTPError as e:
                    ctx.http_error = str(e)

        selected = checks or ALL_CHECKS
        results = await asyncio.gather(*(c.run(ctx) for c in selected), return_exceptions=True)

    findings, passed = [], []
    for check, res in zip(selected, results, strict=True):
        if isinstance(res, BaseException):
            errors.append(f"{check.NAME}: {type(res).__name__}: {res}")
            continue
        if res is None:  # check not applicable to this target (e.g. TLS on an http:// site)
            continue
        findings.extend(res)
        if not any(f.severity is not Severity.INFO for f in res):
            passed.append(check.NAME)
    errors.extend(ctx.notes)

    findings.sort(key=lambda f: (f.severity.rank, f.check))
    total, grade = score(findings)
    return ScanResult(
        target=target.url,
        final_url=str(ctx.response.url) if ctx.response is not None else target.url,
        started_at=started.isoformat(timespec="seconds"),
        duration_ms=int((time.perf_counter() - t0) * 1000),
        score=total,
        grade=grade,
        findings=findings,
        passed=passed,
        errors=errors,
    )
