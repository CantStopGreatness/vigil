"""Web dashboard + JSON API.

Run locally:  uvicorn vigil.web.app:app --reload

Behind a reverse proxy, start uvicorn with FORWARDED_ALLOW_IPS=<proxy address> so
request.client is the real visitor (rate limiting depends on it). Run a single
worker process: the rate limiter and concurrency cap live in memory.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from collections import defaultdict, deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__, db
from ..checks import CHECKS_BY_KEY
from ..export import SECTIONS, ReportOptions, download_name, render_docx, render_pdf, tailor
from ..models import ScanResult, Severity
from ..report import render_html
from ..scanner import scan
from ..target import InvalidTargetError, UnsafeTargetError

STATIC = Path(__file__).parent / "static"
RATE_LIMIT = int(os.environ.get("VIGIL_RATE_LIMIT", "5"))  # scans per client per minute
MAX_CONCURRENT_SCANS = int(os.environ.get("VIGIL_MAX_CONCURRENT_SCANS", "4"))
SCAN_TIMEOUT = float(os.environ.get("VIGIL_SCAN_TIMEOUT", "60"))  # seconds, whole scan
# Local development only. Never enable on a public deployment (re-opens SSRF).
ALLOW_PRIVATE = os.environ.get("VIGIL_ALLOW_PRIVATE") == "1"
# e.g. "mailto:security@example.com"; published at /.well-known/security.txt (RFC 9116) when set.
SECURITY_CONTACT = os.environ.get("VIGIL_SECURITY_CONTACT")

APP_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
# Reports are self-contained HTML with one inline <style> and no scripts at all.
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"

app = FastAPI(title="Vigil", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
_hits: dict[str, deque[float]] = defaultdict(deque)
_scan_slots = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h.setdefault("Content-Security-Policy", APP_CSP)
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")  # report URLs carry a secret token
    h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        # Revalidate on every load (cheap 304s via ETag) so users never run stale JS after an upgrade.
        h.setdefault("Cache-Control", "no-cache")
    if request.url.scheme == "https":
        h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _client_key(request: Request) -> str:
    """Rate-limit key. IPv6 users usually control a whole /64, so bucket by that."""
    host = request.client.host if request.client else "unknown"
    if os.environ.get("VERCEL"):  # Vercel sets x-real-ip to the visitor's address and strips client copies
        host = request.headers.get("x-real-ip", host)
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return host


def _rate_limited(client: str) -> bool:
    """Shared across instances via Redis when it's configured (e.g. on Vercel), else in-memory."""
    if db._redis():
        try:
            return _rate_limited_redis(client)
        except httpx.HTTPError:
            pass  # Redis unreachable: fall back to this instance's own limiter rather than block everyone
    return _rate_limited_local(client)


def _rate_limited_redis(client: str) -> bool:
    # ponytail: fixed one-minute window, so a burst straddling a minute boundary can reach 2x the limit.
    key = f"vigil:rl:{client}:{int(time.time() // 60)}"
    n = db._redis_cmd("INCR", key)
    if n == 1:
        db._redis_cmd("EXPIRE", key, 120)
    return n > RATE_LIMIT


def _rate_limited_local(client: str) -> bool:
    """Sliding-window limiter. In-memory, so it's per-process."""
    now = time.monotonic()
    q = _hits[client]
    while q and now - q[0] > 60:
        q.popleft()
    if len(_hits) > 10_000:  # drop idle clients so the dict can't grow without bound
        for k in [k for k, v in _hits.items() if not v and k != client]:
            del _hits[k]
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


class ScanRequest(BaseModel):
    url: str = Field(..., max_length=2048)
    authorized: bool = False
    checks: list[str] | None = Field(None, max_length=len(CHECKS_BY_KEY))  # None = run every check


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.post("/api/scans")
async def create_scan(body: ScanRequest, request: Request) -> dict:
    if not body.authorized:
        raise HTTPException(400, "Confirm that you own or are authorized to test this site.")
    unknown = [k for k in body.checks or [] if k not in CHECKS_BY_KEY]
    if unknown or body.checks == []:
        raise HTTPException(400, f"Choose checks from: {', '.join(CHECKS_BY_KEY)}.")
    checks = [CHECKS_BY_KEY[k] for k in body.checks] if body.checks else None
    if await asyncio.to_thread(_rate_limited, _client_key(request)):
        raise HTTPException(429, "Too many scans. Try again in a minute.")
    if _scan_slots.locked():
        raise HTTPException(503, "The scanner is busy. Try again in a few seconds.")
    async with _scan_slots:
        try:
            result = await asyncio.wait_for(scan(body.url, checks=checks, allow_private=ALLOW_PRIVATE), SCAN_TIMEOUT)
        except (InvalidTargetError, UnsafeTargetError) as e:
            raise HTTPException(400, str(e)) from e
        except ConnectionError as e:
            raise HTTPException(502, str(e)) from e
        except TimeoutError as e:
            raise HTTPException(504, f"Scan did not finish within {SCAN_TIMEOUT:.0f} seconds.") from e
    data = result.to_dict()
    data["id"] = await asyncio.to_thread(db.save, data)
    return data


@app.get("/api/scans/{token}")
def get_scan(token: str) -> dict:
    data = db.get(token)
    if data is None:
        raise HTTPException(404, "Scan not found")
    return data


def report_options(sections: str = Query(",".join(SECTIONS)), min: str = "info",  # noqa: A002
                   evidence: bool = True) -> ReportOptions:
    """Parse ?sections=summary,details&min=medium&evidence=0 from a report link."""
    chosen = frozenset(filter(None, sections.split(","))) - {"overview"}  # merged into "details"; old links still work
    if not chosen <= set(SECTIONS) or min not in Severity.__members__.values():
        raise HTTPException(400, f"sections must be from {', '.join(SECTIONS)}; min must be a severity.")
    return ReportOptions(sections=chosen, min_severity=Severity(min), evidence=evidence)


Options = Annotated[ReportOptions, Depends(report_options)]


@app.get("/scans/{token}/report", response_class=HTMLResponse)
def html_report(token: str, opts: Options) -> HTMLResponse:
    data = db.get(token)
    if data is None:
        raise HTTPException(404, "Scan not found")
    result = tailor(ScanResult.from_dict(data), opts)
    if "passed" not in opts.sections:
        result = replace(result, passed=[])
    # Rebuilt from the parsed options rather than echoed, so only known values reach the page.
    query = "?" + urlencode({"sections": ",".join(s for s in SECTIONS if s in opts.sections),
                             "min": opts.min_severity.value, "evidence": int(opts.evidence)})
    return HTMLResponse(render_html(result, token=token, query=query),
                        headers={"Content-Security-Policy": REPORT_CSP, "X-Robots-Tag": "noindex"})


DOWNLOADS = {
    "pdf": ("application/pdf", render_pdf),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", render_docx),
}


@app.get("/scans/{token}/report.{fmt}")
def download_report(token: str, fmt: str, opts: Options, preview: bool = False) -> Response:
    if fmt not in DOWNLOADS:
        raise HTTPException(404, "Unknown format")
    data = db.get(token)
    if data is None:
        raise HTTPException(404, "Scan not found")
    media_type, render = DOWNLOADS[fmt]
    result = ScanResult.from_dict(data)
    headers = {
        "Content-Disposition": f'attachment; filename="{download_name(result, fmt)}"',
        "X-Robots-Tag": "noindex",
        "Cache-Control": "private, max-age=3600",
    }
    if preview and fmt == "pdf":
        # Shown inside the dashboard's preview dialog: inline, and frameable by our own pages only.
        # No other CSP directives here: browsers' built-in PDF viewers break under object-src/sandbox.
        headers |= {"Content-Disposition": f'inline; filename="{download_name(result, fmt)}"',
                    "Content-Security-Policy": "frame-ancestors 'self'", "X-Frame-Options": "SAMEORIGIN"}
    return Response(render(result, opts), media_type=media_type, headers=headers)


@app.get("/.well-known/security.txt", include_in_schema=False)
def security_txt() -> PlainTextResponse:
    if not SECURITY_CONTACT:
        raise HTTPException(404)
    expires = (datetime.now(UTC) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return PlainTextResponse(f"Contact: {SECURITY_CONTACT}\nExpires: {expires}\n")


@app.api_route("/healthz", methods=["GET", "HEAD"], include_in_schema=False)
def health() -> dict:
    return {"ok": True}
