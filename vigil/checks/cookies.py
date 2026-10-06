"""Cookie security attributes."""

from __future__ import annotations

import re

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "Cookies"
SESSIONISH = re.compile(r"sess|sid|auth|token|login|jwt|remember", re.I)


def parse_set_cookie(header: str) -> tuple[str, set[str], dict[str, str]]:
    """Return (cookie name, lower-cased flag names, attribute values)."""
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    flags: set[str] = set()
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
            flags.add(k.strip().lower())
        elif p:
            flags.add(p.lower())
    return name, flags, attrs


async def run(ctx: ScanContext) -> list[Finding]:
    if ctx.response is None:
        return []
    cookies = ctx.response.headers.get_list("set-cookie")
    if not cookies:
        return []

    no_secure, no_httponly, no_samesite = [], [], []
    for raw in cookies:
        name, flags, attrs = parse_set_cookie(raw)
        if "secure" not in flags:
            no_secure.append(name)
        if "httponly" not in flags and SESSIONISH.search(name):
            no_httponly.append(name)
        samesite_none_insecure = attrs.get("samesite", "").lower() == "none" and "secure" not in flags
        if "samesite" not in flags or samesite_none_insecure:
            no_samesite.append(name)

    out: list[Finding] = []
    if no_secure and ctx.is_https:
        out.append(Finding(
            NAME, "Cookies missing the Secure flag", Severity.MEDIUM,
            "These cookies can be sent over plain HTTP, where anyone on the network can read them.",
            "Set the `Secure` attribute on every cookie served over HTTPS.",
            evidence=", ".join(no_secure),
        ))
    if no_httponly:
        out.append(Finding(
            NAME, "Session-like cookies missing HttpOnly", Severity.MEDIUM,
            "JavaScript can read these cookies, so a single XSS bug lets an attacker steal sessions.",
            "Set `HttpOnly` on session and auth cookies.",
            evidence=", ".join(no_httponly),
        ))
    if no_samesite:
        out.append(Finding(
            NAME, "Cookies without an explicit SameSite policy", Severity.LOW,
            "SameSite limits when cookies are sent on cross-site requests, which mitigates CSRF.",
            "Set `SameSite=Lax` (or `Strict`) unless cross-site use is required.",
            evidence=", ".join(no_samesite),
        ))
    return out
