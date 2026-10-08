"""Known vulnerabilities: match software versions the site discloses against the NVD.

Banner matching can't see patches that Linux distributions backport without changing the
version number, so findings are worded as "may be affected" and capped at high severity.
"""

from __future__ import annotations

import asyncio
import os
import re

import httpx

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "Known vulnerabilities (CVEs)"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
VERSION = r"(\d+(?:\.\d+)+[a-z]?)"
# Banner name -> (display name, NVD CPE vendor:product). nginx moved vendor to F5, so match any vendor.
PRODUCTS = {
    "nginx": ("nginx", "*:nginx"),
    "apache": ("Apache httpd", "apache:http_server"),
    "php": ("PHP", "php:php"),
    "openssl": ("OpenSSL", "openssl:openssl"),
    "lighttpd": ("lighttpd", "lighttpd:lighttpd"),
    "wordpress": ("WordPress", "wordpress:wordpress"),
    "drupal": ("Drupal", "drupal:drupal"),
}
BANNER_RE = re.compile(rf"\b(nginx|apache|php|openssl|lighttpd)/{VERSION}", re.I)
CMS_RE = re.compile(rf"\b(wordpress|drupal)\s+{VERSION}", re.I)
# CVSS severity of the worst CVE -> finding severity (one step down: a banner match isn't proof).
SEVERITY = {"CRITICAL": Severity.HIGH, "HIGH": Severity.MEDIUM}

# ponytail: per-process cache, so repeat versions in a batch don't re-query NVD; fine at this scale.
_cache: dict[tuple[str, str], list[tuple[str, float, str]]] = {}


def detect(headers: httpx.Headers, html: str) -> list[tuple[str, str]]:
    """(banner name, version) pairs from Server / X-Powered-By headers and the CMS generator tag."""
    text = " ".join(headers.get(h, "") for h in ("server", "x-powered-by"))
    found = BANNER_RE.findall(text)
    if m := GENERATOR_RE.search(html[:200_000]):
        found += CMS_RE.findall(m.group(1))
    return list(dict.fromkeys((name.lower(), version) for name, version in found))


def _worst_metric(cve: dict) -> tuple[float, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            return m["cvssData"].get("baseScore", 0.0), (m["cvssData"].get("baseSeverity") or m.get("baseSeverity", ""))
    return 0.0, ""


async def lookup(cpe: str, version: str) -> list[tuple[str, float, str]]:
    """[(CVE id, CVSS score, CVSS severity)] for a product version, worst first."""
    if (cpe, version) in _cache:
        return _cache[(cpe, version)]
    key = os.environ.get("NVD_API_KEY")  # raises the NVD rate limit from 5 to 50 requests per 30s
    async with httpx.AsyncClient(timeout=15, headers={"apiKey": key} if key else {}) as client:
        r = await client.get(NVD_URL, params={"virtualMatchString": f"cpe:2.3:a:{cpe}:{version}",
                                              "noRejected": "", "resultsPerPage": 2000})
    if r.status_code in (403, 429):
        raise RuntimeError("NVD rate limit reached; try again shortly or set NVD_API_KEY")
    r.raise_for_status()
    cves = sorted(((v["cve"]["id"], *_worst_metric(v["cve"])) for v in r.json().get("vulnerabilities", [])),
                  key=lambda c: -c[1])
    _cache[(cpe, version)] = cves
    return cves


def evaluate(product: str, version: str, cves: list[tuple[str, float, str]]) -> Finding | None:
    if not cves:
        return None
    critical = sum(1 for c in cves if c[2] == "CRITICAL")
    title = f"{product} {version} has {len(cves)} known {'vulnerability' if len(cves) == 1 else 'vulnerabilities'}"
    if critical:
        title += f" ({critical} critical)"
    return Finding(
        NAME, title, SEVERITY.get(cves[0][2], Severity.LOW),
        "This version matches published CVEs in the National Vulnerability Database. Distributions sometimes "
        "backport fixes without changing the version, so confirm with your vendor's advisories.",
        f"Upgrade {product} to the latest supported release, then hide the version banner.",
        evidence=" · ".join(f"{cid} ({score:g} {sev.lower()})" for cid, score, sev in cves[:3])
        + (f" · and {len(cves) - 3} more" if len(cves) > 3 else ""),
    )


async def run(ctx: ScanContext) -> list[Finding] | None:
    if ctx.response is None:
        return None
    html = ctx.response.text if "html" in ctx.response.headers.get("content-type", "") else ""
    found = [(PRODUCTS[name], version) for name, version in detect(ctx.response.headers, html)]
    if not found:
        return None  # no versions disclosed, nothing to match
    results = await asyncio.gather(*(lookup(cpe, v) for (_, cpe), v in found), return_exceptions=True)
    out = []
    for ((product, _), version), res in zip(found, results, strict=True):
        if isinstance(res, BaseException):
            ctx.notes.append(f"{NAME}: could not look up {product} {version}: {res}")
        elif finding := evaluate(product, version, res):
            out.append(finding)
    if all(isinstance(res, BaseException) for res in results):
        return None  # couldn't check anything, so don't report it as passed
    return out
