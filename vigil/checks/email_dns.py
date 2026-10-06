"""Email spoofing protection: SPF and DMARC DNS records."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..context import ScanContext
from ..models import Finding, Severity

NAME = "Email spoofing (SPF/DMARC)"


async def _txt(name: str) -> list[str] | None:
    """Return TXT strings for name, [] if none exist, None if DNS itself failed."""
    try:
        answer = await dns.asyncresolver.resolve(name, "TXT", lifetime=6)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def evaluate(domain: str, root_txt: list[str], dmarc_txt: list[str]) -> list[Finding]:
    out: list[Finding] = []
    spf = [t for t in root_txt if t.lower().split()[:1] == ["v=spf1"]]
    if not spf:
        out.append(Finding(
            NAME, "No SPF record", Severity.MEDIUM,
            f"Anyone can send email that claims to be from @{domain}, which makes phishing your "
            "customers trivial.",
            f"Publish a TXT record on {domain} such as `v=spf1 include:_spf.google.com -all` "
            "(listing the services that send your mail).",
        ))
    elif len(spf) > 1:
        out.append(Finding(
            NAME, "Multiple SPF records", Severity.MEDIUM,
            "More than one SPF record is a permanent error (RFC 7208); receivers treat SPF as broken.",
            "Merge them into a single `v=spf1` record.", evidence=" | ".join(spf),
        ))
    else:
        terms = spf[0].lower().split()
        if "+all" in terms or "all" in terms:  # a bare "all" has the implicit "+" qualifier
            out.append(Finding(
                NAME, "SPF allows every server (+all)", Severity.HIGH,
                "`+all` authorises the entire internet to send mail as this domain.",
                "End the record with `-all` or `~all`.", evidence=spf[0],
            ))
        elif "?all" in terms or not any(t in ("-all", "~all") or t.startswith("redirect=") for t in terms):
            out.append(Finding(
                NAME, "SPF policy is neutral", Severity.LOW,
                "The SPF record does not tell receivers to reject unauthorised senders.",
                "End the record with `-all` (or `~all` while testing).", evidence=spf[0],
            ))

    dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        out.append(Finding(
            NAME, "No DMARC record", Severity.MEDIUM,
            "Without DMARC, receivers have no instruction on what to do with mail that fails SPF/DKIM, "
            "and you get no reports of spoofing attempts.",
            f"Publish `_dmarc.{domain}` TXT `v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}`.",
        ))
    else:
        tags = dict(
            (k.strip().lower(), v.strip().lower())
            for k, _, v in (p.partition("=") for p in dmarc[0].split(";")) if k.strip()
        )
        if tags.get("p", "none") == "none":
            out.append(Finding(
                NAME, "DMARC policy is monitor-only (p=none)", Severity.LOW,
                "Spoofed mail is still delivered; p=none only collects reports.",
                "Once reports look clean, move to `p=quarantine`, then `p=reject`.", evidence=dmarc[0],
            ))
    return out


async def run(ctx: ScanContext) -> list[Finding] | None:
    domain = ctx.registrable_domain
    if domain.replace(".", "").isdigit() or ":" in domain:
        return None  # IP address target: not applicable
    root, dmarc = await asyncio.gather(_txt(domain), _txt(f"_dmarc.{domain}"))
    if root is None or dmarc is None:
        ctx.notes.append(f"{NAME}: DNS lookup failed, check skipped")
        return None
    return evaluate(domain, root, dmarc)
