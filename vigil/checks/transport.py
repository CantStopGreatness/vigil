"""HTTPS availability and HTTP -> HTTPS redirect."""

from __future__ import annotations

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "HTTPS transport"


async def run(ctx: ScanContext) -> list[Finding]:
    out: list[Finding] = []

    if ctx.response is not None and not ctx.is_https:
        out.append(Finding(
            NAME, "Site is served over plain HTTP", Severity.HIGH,
            "Traffic, including passwords and cookies, travels unencrypted and can be read or modified in transit.",
            "Serve the site over HTTPS (Let's Encrypt certificates are free) and redirect all HTTP traffic.",
            evidence=str(ctx.response.url),
        ))
        return out

    r = ctx.http_response
    if r is None:
        # Port 80 closed or unreachable is fine: there is nothing to downgrade to.
        return out

    # Follow the whole chain: http://example.com -> http://www.example.com -> https://... is fine.
    first = r.history[0] if r.history else r
    location = first.headers.get("location", "")
    reached_https = r.url.scheme == "https" or (
        r.is_redirect and r.headers.get("location", "").lower().startswith("https://"))
    if reached_https:
        if first.status_code not in (301, 308):
            out.append(Finding(
                NAME, "HTTP redirect to HTTPS is temporary", Severity.INFO,
                f"HTTP redirects with {first.status_code}; a permanent redirect (301/308) is cached by browsers.",
                "Use a 301 or 308 redirect.",
            ))
        return out

    out.append(Finding(
        NAME, "HTTP is not redirected to HTTPS", Severity.HIGH,
        "Visitors who arrive via http:// stay on an unencrypted connection.",
        "Redirect every HTTP request to its HTTPS equivalent with a 301.",
        evidence=f"http://{ctx.target.url_host}/ -> {first.status_code} {location}".strip(),
    ))
    return out
