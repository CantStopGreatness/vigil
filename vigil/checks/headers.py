"""HTTP security response headers."""

from __future__ import annotations

import re

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "Security headers"
SIX_MONTHS = 15_552_000


def _csp_directive(csp: str, name: str) -> str | None:
    for part in csp.split(";"):
        bits = part.strip().split(None, 1)
        if bits and bits[0].lower() == name:
            return bits[1] if len(bits) > 1 else ""
    return None


async def run(ctx: ScanContext) -> list[Finding]:
    if ctx.response is None:
        return []
    h = ctx.response.headers
    out: list[Finding] = []

    # --- HSTS -------------------------------------------------------------
    if ctx.is_https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(Finding(
                NAME, "Missing Strict-Transport-Security (HSTS)", Severity.MEDIUM,
                "Without HSTS, a user typing the domain can be downgraded to HTTP by an attacker on "
                "the same network (SSL stripping).",
                "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            ))
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < SIX_MONTHS:
                out.append(Finding(
                    NAME, "HSTS max-age is too short", Severity.LOW,
                    f"HSTS max-age is {age} seconds; browsers forget the policy quickly.",
                    "Use a max-age of at least 15552000 (180 days); 31536000 is common.",
                    evidence=hsts,
                ))

    # --- CSP --------------------------------------------------------------
    csp = h.get("content-security-policy")
    if not csp:
        out.append(Finding(
            NAME, "Missing Content-Security-Policy", Severity.MEDIUM,
            "A CSP is the main browser-side defence against cross-site scripting (XSS): it limits "
            "where scripts can be loaded from.",
            "Start with a report-only policy (`Content-Security-Policy-Report-Only`), then enforce it.",
        ))
    else:
        script_src = _csp_directive(csp, "script-src") or _csp_directive(csp, "default-src") or ""
        if "'unsafe-inline'" in script_src and "'nonce-" not in script_src and "'strict-dynamic'" not in script_src:
            out.append(Finding(
                NAME, "CSP allows inline scripts", Severity.LOW,
                "`'unsafe-inline'` in script-src lets injected <script> tags run, which removes most "
                "of the XSS protection a CSP provides.",
                "Replace 'unsafe-inline' with nonces or hashes.",
                evidence=f"script-src {script_src}",
            ))

    # --- Clickjacking -----------------------------------------------------
    has_frame_ancestors = bool(csp) and _csp_directive(csp, "frame-ancestors") is not None
    if not h.get("x-frame-options") and not has_frame_ancestors:
        out.append(Finding(
            NAME, "No clickjacking protection", Severity.MEDIUM,
            "The page can be embedded in an invisible iframe on another site, tricking users into "
            "clicking buttons they cannot see.",
            "Add `X-Frame-Options: DENY` or the CSP directive `frame-ancestors 'none'`.",
        ))

    # --- MIME sniffing ----------------------------------------------------
    if (h.get("x-content-type-options") or "").strip().lower() != "nosniff":
        out.append(Finding(
            NAME, "Missing X-Content-Type-Options: nosniff", Severity.LOW,
            "Browsers may guess ('sniff') content types, which can turn an uploaded file into executable script.",
            "Add `X-Content-Type-Options: nosniff`.",
        ))

    # --- Referrer leakage -------------------------------------------------
    if not h.get("referrer-policy"):
        out.append(Finding(
            NAME, "Missing Referrer-Policy", Severity.LOW,
            "Full URLs (which can contain tokens or IDs) may leak to third-party sites via the Referer header.",
            "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
        ))

    if not h.get("permissions-policy"):
        out.append(Finding(
            NAME, "Missing Permissions-Policy", Severity.INFO,
            "Permissions-Policy restricts powerful browser features (camera, geolocation, etc.).",
            "Add e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
        ))
    return out
