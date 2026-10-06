"""Shared state handed to every check, so the target is only fetched once."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import tldextract

from .target import Target

# Bundled PSL snapshot only: no network fetch or disk cache at runtime.
_psl = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass
class ScanContext:
    target: Target
    client: httpx.AsyncClient
    # GET of the target over its own scheme, following redirects.
    response: httpx.Response | None = None
    # GET of http://host/ WITHOUT following redirects (to test HTTPS upgrade).
    http_response: httpx.Response | None = None
    http_error: str | None = None
    allow_private: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def is_https(self) -> bool:
        if self.response is not None:
            return self.response.url.scheme == "https"
        return self.target.scheme == "https"

    @property
    def registrable_domain(self) -> str:
        """The organizational domain, per the Public Suffix List (blog.example.co.uk -> example.co.uk).

        SPF and DMARC records live on the domain people send mail from, not on www or other subdomains.
        """
        ext = _psl(self.target.host)
        return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else self.target.host
