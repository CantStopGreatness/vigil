"""Sensitive files and panels left publicly reachable.

Each probe has a *content validator*. Many sites return HTTP 200 with a
"not found" page for every path (a "soft 404"), so trusting the status code
alone produces a flood of false positives. We only report a file when its
body actually looks like the thing we were looking for.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "Exposed files"
MAX_BYTES = 8192


def _text(b: bytes) -> str:
    return b.decode("utf-8", "replace")


def _not_html(b: bytes) -> bool:
    head = _text(b[:512]).lower()
    return "<html" not in head and "<!doctype" not in head


@dataclass(frozen=True)
class Probe:
    path: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    looks_valid: Callable[[bytes], bool]


PROBES: list[Probe] = [
    Probe(
        "/.git/HEAD", "Git repository exposed", Severity.CRITICAL,
        "The .git directory is public. Attackers can download the full source code and history, "
        "often including hard-coded secrets.",
        "Block access to /.git in the web server config and remove it from the web root.",
        lambda b: _text(b).startswith("ref: refs/") or re.fullmatch(rb"[0-9a-f]{40}\s*", b) is not None,
    ),
    Probe(
        "/.env", "Environment file exposed", Severity.CRITICAL,
        "A .env file usually contains database passwords, API keys and other secrets.",
        "Remove .env from the web root, block dotfiles, and rotate every secret it contained.",
        lambda b: _not_html(b) and re.search(rb"^[A-Z][A-Z0-9_]{2,}=", b, re.M) is not None,
    ),
    Probe(
        "/.htpasswd", "Password file (.htpasswd) exposed", Severity.HIGH,
        "Password hashes can be downloaded and cracked offline.",
        "Move .htpasswd outside the web root and block dotfiles.",
        lambda b: _not_html(b) and re.search(rb"^[\w.-]+:(\$apr1\$|\$2[aby]\$|\{SHA\})", b, re.M) is not None,
    ),
    Probe(
        "/.svn/entries", "Subversion metadata exposed", Severity.HIGH,
        "SVN metadata can reveal file names and source code.",
        "Block access to /.svn and remove it from the web root.",
        lambda b: _not_html(b) and (b[:3].strip().isdigit() or b"svn" in b[:200].lower()),
    ),
    Probe(
        "/backup.sql", "Database dump exposed", Severity.CRITICAL,
        "A SQL dump can contain every user record and password hash.",
        "Delete the file and never store backups in the web root.",
        lambda b: _not_html(b) and re.search(rb"CREATE TABLE|INSERT INTO|-- MySQL dump", b, re.I) is not None,
    ),
    Probe(
        "/backup.zip", "Backup archive exposed", Severity.HIGH,
        "Archives in the web root often contain source code and configuration.",
        "Delete the file and keep backups off the public server.",
        lambda b: b.startswith(b"PK\x03\x04"),
    ),
    Probe(
        "/wp-config.php.bak", "WordPress config backup exposed", Severity.CRITICAL,
        "The backup is served as plain text, exposing database credentials.",
        "Delete the backup and rotate the database password.",
        lambda b: b"DB_PASSWORD" in b or b"<?php" in b,
    ),
    Probe(
        "/.DS_Store", "macOS .DS_Store file exposed", Severity.LOW,
        ".DS_Store files list the names of files in a directory, revealing hidden paths.",
        "Delete .DS_Store files from the server and add them to .gitignore.",
        lambda b: b[4:8] == b"Bud1",
    ),
    Probe(
        "/phpinfo.php", "phpinfo() page exposed", Severity.MEDIUM,
        "phpinfo() reveals PHP version, modules, paths and sometimes environment variables.",
        "Delete the file.",
        lambda b: b"PHP Version" in b and b"phpinfo" in b.lower(),
    ),
    Probe(
        "/server-status", "Apache server-status exposed", Severity.MEDIUM,
        "Shows live requests, client IPs and internal URLs.",
        "Restrict /server-status to localhost or disable mod_status.",
        lambda b: b"Apache Server Status" in b,
    ),
    Probe(
        "/phpmyadmin/", "phpMyAdmin panel exposed", Severity.MEDIUM,
        "A public database admin panel is a prime brute-force and exploit target.",
        "Restrict it by IP / VPN or remove it.",
        lambda b: b"phpMyAdmin" in b,
    ),
]


async def _fetch_prefix(client: httpx.AsyncClient, url: str) -> tuple[int, bytes] | None:
    """GET a URL but read at most MAX_BYTES, so a 2 GB backup.zip doesn't hurt us."""
    try:
        async with client.stream("GET", url, follow_redirects=False) as r:
            buf = b""
            async for chunk in r.aiter_bytes():
                buf += chunk
                if len(buf) >= MAX_BYTES:
                    break
            return r.status_code, buf[:MAX_BYTES]
    except httpx.HTTPError:
        return None


async def _probe(ctx: ScanContext, base: str, probe: Probe) -> Finding | None:
    res = await _fetch_prefix(ctx.client, base + probe.path)
    if res is None:
        return None
    status, body = res
    if status != 200 or not body or not probe.looks_valid(body):
        return None
    # Never echo secrets back in reports: mask everything after the first '=' or ':' on each line.
    lines = _text(body[:120]).split("\n")
    preview = "\\n".join(re.sub(r"([=:]).*", r"\1****", line, count=1) for line in lines)
    return Finding(NAME, probe.title, probe.severity, probe.description, probe.recommendation,
                   evidence=f"{probe.path} (HTTP 200) {preview}")


async def run(ctx: ScanContext) -> list[Finding]:
    if ctx.response is None:
        return []
    u = ctx.response.url
    base = f"{u.scheme}://{u.netloc.decode()}"
    results = await asyncio.gather(*(_probe(ctx, base, p) for p in PROBES))
    out = [f for f in results if f]

    # security.txt (RFC 9116) tells researchers how to report vulnerabilities.
    st = await _fetch_prefix(ctx.client, base + "/.well-known/security.txt")
    if not (st and st[0] == 200 and b"contact:" in st[1].lower()):
        out.append(Finding(
            NAME, "No security.txt", Severity.INFO,
            "security.txt (RFC 9116) tells security researchers how to report vulnerabilities to you.",
            "Publish /.well-known/security.txt with at least `Contact:` and `Expires:` fields.",
        ))
    return out
