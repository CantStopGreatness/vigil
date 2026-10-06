"""Information disclosure: software versions leaked in headers or HTML."""

from __future__ import annotations

import re

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "Information disclosure"
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


async def run(ctx: ScanContext) -> list[Finding]:
    if ctx.response is None:
        return []
    h = ctx.response.headers
    leaks = []

    server = h.get("server", "")
    if re.search(r"\d", server):  # "nginx" is fine, "nginx/1.18.0" leaks a version
        leaks.append(f"Server: {server}")
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        if h.get(name):
            leaks.append(f"{name}: {h[name]}")

    out: list[Finding] = []
    if leaks:
        out.append(Finding(
            NAME, "Server software versions disclosed", Severity.LOW,
            "Version banners tell attackers exactly which known vulnerabilities (CVEs) to try.",
            "Remove or genericise these headers (e.g. `server_tokens off;` in nginx, "
            "`expose_php = Off` in PHP, `app.disable('x-powered-by')` in Express).",
            evidence="; ".join(leaks),
        ))

    ctype = h.get("content-type", "")
    if "html" in ctype:
        m = GENERATOR_RE.search(ctx.response.text[:200_000])
        if m and re.search(r"\d", m.group(1)):
            out.append(Finding(
                NAME, "CMS version disclosed in HTML", Severity.INFO,
                "A <meta name=\"generator\"> tag reveals the CMS and its version.",
                "Remove the generator tag and keep the CMS fully patched.",
                evidence=m.group(1),
            ))
    return out
