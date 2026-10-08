import httpx

from vigil.checks import cves
from vigil.models import Severity

NGINX = [("CVE-2021-23017", 7.7, "HIGH"), ("CVE-2021-3618", 7.4, "HIGH"), ("CVE-2009-0001", 4.3, "MEDIUM")]


def test_detects_versions_from_headers_and_generator():
    h = httpx.Headers({"server": "Apache/2.4.29 (Ubuntu) OpenSSL/1.0.2k", "x-powered-by": "PHP/7.2.1"})
    html = '<meta name="generator" content="WordPress 5.2.1">'
    assert cves.detect(h, html) == [("apache", "2.4.29"), ("openssl", "1.0.2k"), ("php", "7.2.1"),
                                    ("wordpress", "5.2.1")]
    assert cves.detect(httpx.Headers({"server": "nginx"}), "") == []  # no version, nothing to look up


def test_finding_is_one_step_below_worst_cvss_and_lists_worst_first():
    f = cves.evaluate("nginx", "1.18.0", NGINX)
    assert f.title == "nginx 1.18.0 has 3 known vulnerabilities" and f.severity is Severity.MEDIUM
    assert f.evidence.startswith("CVE-2021-23017 (7.7 high)")
    critical = cves.evaluate("PHP", "7.2.1", [("CVE-1", 9.8, "CRITICAL")] * 7)
    assert critical.severity is Severity.HIGH and "(7 critical)" in critical.title
    assert critical.evidence.endswith("and 4 more")
    assert cves.evaluate("PHP", "8.3.0", []) is None


async def test_run_reports_lookup_failures_as_notes(ctx_factory, monkeypatch):
    async def fake_lookup(cpe, version):
        if cpe == "php:php":
            raise RuntimeError("NVD rate limit reached")
        return NGINX

    monkeypatch.setattr(cves, "lookup", fake_lookup)
    ctx = ctx_factory(headers={"server": "nginx/1.18.0", "x-powered-by": "PHP/7.2.1"})
    out = await cves.run(ctx)
    assert [f.title for f in out] == ["nginx 1.18.0 has 3 known vulnerabilities"]
    assert ctx.notes == ["Known vulnerabilities (CVEs): could not look up PHP 7.2.1: NVD rate limit reached"]
    assert await cves.run(ctx_factory(headers={"server": "nginx"})) is None


async def test_lookup_queries_nvd_once_per_version(monkeypatch):
    calls = []

    def handler(request):
        calls.append(request.url.params["virtualMatchString"])
        return httpx.Response(200, json={"vulnerabilities": [
            {"cve": {"id": "CVE-A", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0,
                                                                                   "baseSeverity": "MEDIUM"}}]}}},
            {"cve": {"id": "CVE-B", "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 9.3},
                                                                  "baseSeverity": "HIGH"}]}}}]})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(cves.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(handler), **kw))
    cves._cache.clear()
    assert await cves.lookup("*:nginx", "9.9.9") == [("CVE-B", 9.3, "HIGH"), ("CVE-A", 5.0, "MEDIUM")]
    await cves.lookup("*:nginx", "9.9.9")
    assert calls == ["cpe:2.3:a:*:nginx:9.9.9"]
