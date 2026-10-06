from datetime import UTC, datetime

from conftest import make_response

from vigil.checks import cookies, disclosure, email_dns, headers, transport
from vigil.checks.exposure import PROBES
from vigil.models import Severity

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
}


def titles(findings):
    return {f.title for f in findings}


# --- headers --------------------------------------------------------------

async def test_hardened_site_has_no_header_findings(ctx_factory):
    assert await headers.run(ctx_factory(GOOD_HEADERS)) == []


async def test_bare_site_flags_every_header(ctx_factory):
    t = titles(await headers.run(ctx_factory({})))
    assert "Missing Strict-Transport-Security (HSTS)" in t
    assert "Missing Content-Security-Policy" in t
    assert "No clickjacking protection" in t
    assert "Missing X-Content-Type-Options: nosniff" in t


async def test_frame_ancestors_counts_as_clickjacking_protection(ctx_factory):
    h = {"content-security-policy": "frame-ancestors 'self'"}
    assert "No clickjacking protection" not in titles(await headers.run(ctx_factory(h)))


async def test_short_hsts_and_unsafe_inline(ctx_factory):
    h = {**GOOD_HEADERS, "strict-transport-security": "max-age=300",
         "content-security-policy": "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"}
    t = titles(await headers.run(ctx_factory(h)))
    assert {"HSTS max-age is too short", "CSP allows inline scripts"} <= t


async def test_hsts_not_required_on_plain_http(ctx_factory):
    t = titles(await headers.run(ctx_factory({}, url="http://example.com/")))
    assert "Missing Strict-Transport-Security (HSTS)" not in t


# --- cookies --------------------------------------------------------------

async def test_insecure_session_cookie(ctx_factory):
    ctx = ctx_factory({"set-cookie": "sessionid=abc; Path=/"})
    t = titles(await cookies.run(ctx))
    assert t == {"Cookies missing the Secure flag", "Session-like cookies missing HttpOnly",
                 "Cookies without an explicit SameSite policy"}


async def test_secure_cookie_passes(ctx_factory):
    ctx = ctx_factory({"set-cookie": "sessionid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"})
    assert await cookies.run(ctx) == []


def test_parse_set_cookie():
    name, flags, attrs = cookies.parse_set_cookie("a=1; Secure; SameSite=Strict; Max-Age=60")
    assert name == "a" and "secure" in flags and attrs["samesite"] == "Strict"


# --- transport ------------------------------------------------------------

async def test_http_redirects_to_https(ctx_factory):
    redirect = make_response("http://example.com/", 301, {"location": "https://example.com/"})
    assert await transport.run(ctx_factory(GOOD_HEADERS, http_response=redirect)) == []


async def test_http_redirect_chain_reaching_https(ctx_factory):
    hop = make_response("http://example.com/", 301, {"location": "http://www.example.com/"})
    final = make_response("https://www.example.com/", 200)
    final.history = [hop, make_response("http://www.example.com/", 301, {"location": "https://www.example.com/"})]
    assert await transport.run(ctx_factory(GOOD_HEADERS, http_response=final)) == []


async def test_http_redirect_chain_staying_on_http(ctx_factory):
    final = make_response("http://www.example.com/", 200)
    final.history = [make_response("http://example.com/", 301, {"location": "http://www.example.com/"})]
    t = titles(await transport.run(ctx_factory(GOOD_HEADERS, http_response=final)))
    assert t == {"HTTP is not redirected to HTTPS"}


async def test_http_not_redirected(ctx_factory):
    plain = make_response("http://example.com/", 200)
    t = titles(await transport.run(ctx_factory(GOOD_HEADERS, http_response=plain)))
    assert t == {"HTTP is not redirected to HTTPS"}


async def test_plain_http_site(ctx_factory):
    f = await transport.run(ctx_factory({}, url="http://example.com/"))
    assert f[0].severity is Severity.HIGH


# --- disclosure -----------------------------------------------------------

async def test_version_banners(ctx_factory):
    ctx = ctx_factory({"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4", "content-type": "text/html"},
                      body=b'<meta name="generator" content="WordPress 6.1.1">')
    t = titles(await disclosure.run(ctx))
    assert t == {"Server software versions disclosed", "CMS version disclosed in HTML"}


async def test_versionless_server_header_is_fine(ctx_factory):
    assert await disclosure.run(ctx_factory({"server": "cloudflare"})) == []


# --- exposure validators (no network) -------------------------------------

def probe(path):
    return next(p for p in PROBES if p.path == path)


def test_git_head_validator():
    v = probe("/.git/HEAD").looks_valid
    assert v(b"ref: refs/heads/main\n")
    assert not v(b"<!doctype html><title>Not found</title>")


def test_env_validator_rejects_soft_404():
    v = probe("/.env").looks_valid
    assert v(b"DB_PASSWORD=hunter2\nAPI_KEY=x\n")
    assert not v(b"<html><body>APP_KEY=not really</body></html>")


def test_zip_and_ds_store_magic_bytes():
    assert probe("/backup.zip").looks_valid(b"PK\x03\x04rest")
    assert not probe("/backup.zip").looks_valid(b"<html>")
    assert probe("/.DS_Store").looks_valid(b"\x00\x00\x00\x01Bud1\x00")


# --- SPF / DMARC ----------------------------------------------------------

def test_missing_spf_and_dmarc():
    t = titles(email_dns.evaluate("example.com", [], []))
    assert t == {"No SPF record", "No DMARC record"}


def test_strong_email_config():
    assert email_dns.evaluate("example.com", ["v=spf1 include:_spf.google.com -all"],
                              ["v=DMARC1; p=reject; rua=mailto:d@example.com"]) == []


def test_weak_email_config():
    t = titles(email_dns.evaluate("example.com", ["v=spf1 +all"], ["v=DMARC1; p=none"]))
    assert t == {"SPF allows every server (+all)", "DMARC policy is monitor-only (p=none)"}


def test_multiple_spf_records():
    t = titles(email_dns.evaluate("example.com", ["v=spf1 -all", "v=spf1 ~all"], ["v=DMARC1; p=reject"]))
    assert t == {"Multiple SPF records"}


# --- TLS expiry logic -----------------------------------------------------

def test_tls_expiry(monkeypatch):
    from vigil.checks import tls

    monkeypatch.setattr(tls, "_handshake", lambda *a: ("TLSv1.3", {"notAfter": "Jan 10 00:00:00 2030 GMT"}))
    monkeypatch.setattr(tls, "_legacy_supported", lambda *a: None)
    soon = datetime(2030, 1, 1, tzinfo=UTC)
    later = datetime(2029, 12, 1, tzinfo=UTC)
    assert titles(tls.inspect("example.com", 443, now=soon)) == {"Certificate expires very soon"}
    assert titles(tls.inspect("example.com", 443, now=later)) == set()


def test_spf_bare_all_is_treated_as_plus_all():
    t = titles(email_dns.evaluate("example.com", ["v=spf1 all"], ["v=DMARC1; p=reject"]))
    assert "SPF allows every server (+all)" in t


def test_spf_redirect_is_not_neutral():
    assert email_dns.evaluate("example.com", ["v=spf1 redirect=_spf.example.com"], ["v=DMARC1; p=reject"]) == []


def test_spf_version_must_match_exactly():
    t = titles(email_dns.evaluate("example.com", ["v=spf10 -all"], ["v=DMARC1; p=reject"]))
    assert "No SPF record" in t
