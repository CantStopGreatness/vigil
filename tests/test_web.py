import httpx
import pytest
from fastapi.testclient import TestClient

from vigil.checks import headers
from vigil.web import app as webapp


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_DB", str(tmp_path / "test.db"))
    webapp._hits.clear()

    real_scan = webapp.scan

    async def offline_scan(url, checks=None, **kwargs):
        t = httpx.MockTransport(lambda req: httpx.Response(200, content=b"<html></html>"))
        return await real_scan(url, checks=checks or [headers], transport=t, **kwargs)

    monkeypatch.setattr(webapp, "scan", offline_scan)
    return TestClient(webapp.app)


def test_requires_authorization(client):
    r = client.post("/api/scans", json={"url": "example.com", "authorized": False})
    assert r.status_code == 400


def test_rejects_private_targets(client, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))])
    r = client.post("/api/scans", json={"url": "localhost", "authorized": True})
    assert r.status_code == 400 and "non-public" in r.json()["detail"]


def test_scan_is_saved_and_reportable(client):
    r = client.post("/api/scans", json={"url": "example.com", "authorized": True})
    assert r.status_code == 200
    data = r.json()
    token = data["id"]
    assert data["grade"] in "ABCDF" and len(token) >= 20  # unguessable, not a row number

    assert client.get(f"/api/scans/{token}").json()["score"] == data["score"]
    report = client.get(f"/scans/{token}/report")
    assert report.status_code == 200 and "Missing Content-Security-Policy" in report.text
    assert "script-src" not in report.headers["content-security-policy"]  # reports run no scripts
    assert client.get("/api/scans/1").status_code == 404
    assert client.get("/scans/1/report").status_code == 404


def test_scan_history_is_not_public(client):
    client.post("/api/scans", json={"url": "example.com", "authorized": True})
    assert client.get("/api/scans").status_code in (404, 405)


def test_dashboard_sends_security_headers(client):
    h = client.get("/").headers
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert "unsafe-inline" not in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"
    js = client.get("/static/app.js")
    assert js.status_code == 200 and js.headers["cache-control"] == "no-cache"
    assert client.get("/docs").status_code == 404


def test_unreachable_target_is_502(client, monkeypatch):
    async def failing_scan(url, **kwargs):
        raise ConnectionError("Could not fetch")
    monkeypatch.setattr(webapp, "scan", failing_scan)
    r = client.post("/api/scans", json={"url": "example.com", "authorized": True})
    assert r.status_code == 502


def test_slow_scan_times_out(client, monkeypatch):
    import asyncio

    async def slow_scan(url, **kwargs):
        await asyncio.sleep(5)
    monkeypatch.setattr(webapp, "scan", slow_scan)
    monkeypatch.setattr(webapp, "SCAN_TIMEOUT", 0.05)
    assert client.post("/api/scans", json={"url": "example.com", "authorized": True}).status_code == 504


def test_old_database_is_migrated(tmp_path, monkeypatch):
    import sqlite3

    from vigil import db
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, score INTEGER "
                "NOT NULL, grade TEXT NOT NULL, created_at TEXT NOT NULL, result_json TEXT NOT NULL)")
    old.commit()
    old.close()
    monkeypatch.setenv("VIGIL_DB", str(path))
    token = db.save({"final_url": "https://x/", "score": 90, "grade": "A", "started_at": "2999-01-01T00:00:00+00:00"})
    assert db.get(token)["grade"] == "A"


def test_expired_scans_are_pruned(tmp_path, monkeypatch):
    from vigil import db
    monkeypatch.setenv("VIGIL_DB", str(tmp_path / "p.db"))
    old = db.save({"final_url": "https://x/", "score": 1, "grade": "F", "started_at": "2000-01-01T00:00:00+00:00"})
    db.save({"final_url": "https://y/", "score": 1, "grade": "F", "started_at": "2999-01-01T00:00:00+00:00"})
    assert db.get(old) is None


def test_rate_limit(client, monkeypatch):
    monkeypatch.setattr(webapp, "RATE_LIMIT", 2)
    codes = [client.post("/api/scans", json={"url": "example.com", "authorized": True}).status_code
             for _ in range(3)]
    assert codes == [200, 200, 429]


def test_index_served(client):
    assert "Vigil" in client.get("/").text


def test_security_txt_only_when_configured(client, monkeypatch):
    assert client.get("/.well-known/security.txt").status_code == 404
    monkeypatch.setattr(webapp, "SECURITY_CONTACT", "mailto:sec@example.com")
    r = client.get("/.well-known/security.txt")
    assert r.status_code == 200 and "Contact: mailto:sec@example.com" in r.text and "Expires:" in r.text


def test_report_downloads(client):
    token = client.post("/api/scans", json={"url": "example.com", "authorized": True}).json()["id"]
    pdf = client.get(f"/scans/{token}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert pdf.headers["content-type"] == "application/pdf"
    assert 'attachment; filename="vigil-report-example.com-' in pdf.headers["content-disposition"]
    docx = client.get(f"/scans/{token}/report.docx")
    assert docx.status_code == 200 and docx.content.startswith(b"PK")
    assert client.get(f"/scans/{token}/report.exe").status_code == 404
    assert client.get("/scans/nope/report.pdf").status_code == 404
    page = client.get(f"/scans/{token}/report").text
    assert f"/scans/{token}/report.pdf" in page and f"/scans/{token}/report.docx" in page


def test_scan_runs_only_chosen_checks(client):
    r = client.post("/api/scans", json={"url": "example.com", "authorized": True, "checks": ["cookies"]})
    assert r.status_code == 200
    body = r.json()
    assert set(body["passed"]) | {f["check"] for f in body["findings"]} == {"Cookies"}
    for bad in (["nope"], []):
        r = client.post("/api/scans", json={"url": "example.com", "authorized": True, "checks": bad})
        assert r.status_code == 400


def test_report_options(client):
    token = client.post("/api/scans", json={"url": "example.com", "authorized": True}).json()["id"]
    pdf = client.get(f"/scans/{token}/report.pdf?sections=summary,details&min=high&evidence=0")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    page = client.get(f"/scans/{token}/report?min=critical&sections=details&x=%22%3E").text
    assert "No issues found." in page  # the headers check finds nothing critical
    assert "report.pdf?sections=details&amp;min=critical&amp;evidence=1" in page and "&quot;&gt;" not in page
    assert client.get(f"/scans/{token}/report.pdf?sections=bogus").status_code == 400
    assert client.get(f"/scans/{token}/report.pdf?min=extreme").status_code == 400


def test_pdf_preview_is_inline_and_same_origin_frameable(client):
    token = client.post("/api/scans", json={"url": "example.com", "authorized": True}).json()["id"]
    h = client.get(f"/scans/{token}/report.pdf?preview=1&min=high").headers
    assert h["content-disposition"].startswith("inline;")
    assert h["content-security-policy"] == "frame-ancestors 'self'" and h["x-frame-options"] == "SAMEORIGIN"
    h = client.get(f"/scans/{token}/report.pdf").headers  # plain downloads stay unframeable attachments
    assert h["content-disposition"].startswith("attachment;") and h["x-frame-options"] == "DENY"


def test_scans_are_stored_in_redis_when_configured(client, monkeypatch):
    store = {}

    def fake_cmd(op, key, *rest):
        if op == "SET":
            assert rest[1] == "EX"  # scans expire on their own
            store[key] = rest[0]
            return "OK"
        if op in ("INCR", "EXPIRE"):  # the shared rate limiter
            return 1
        return store.get(key)

    monkeypatch.setenv("KV_REST_API_URL", "https://example.upstash.io")
    monkeypatch.setenv("KV_REST_API_TOKEN", "t")
    monkeypatch.setattr(webapp.db, "_redis_cmd", fake_cmd)
    token = client.post("/api/scans", json={"url": "example.com", "authorized": True}).json()["id"]
    assert f"vigil:scan:{token}" in store
    assert client.get(f"/api/scans/{token}").json()["id"] == token
    assert client.get("/api/scans/missing").status_code == 404


def test_rate_limit_is_shared_through_redis_and_falls_back_when_it_is_down(client, monkeypatch):
    counters, expiries = {}, {}

    def fake_cmd(op, key, *rest):
        if op == "INCR":
            counters[key] = counters.get(key, 0) + 1
            return counters[key]
        if op == "EXPIRE":
            expiries[key] = rest[0]
            return 1
        return None  # GET/SET for scan storage aren't needed here

    monkeypatch.setenv("KV_REST_API_URL", "https://example.upstash.io")
    monkeypatch.setenv("KV_REST_API_TOKEN", "t")
    monkeypatch.setattr(webapp, "RATE_LIMIT", 2)
    monkeypatch.setattr(webapp.db, "_redis_cmd", fake_cmd)
    assert [webapp._rate_limited("1.2.3.4") for _ in range(3)] == [False, False, True]
    assert webapp._hits == {}  # nothing counted in memory: another instance would see the same Redis count
    assert list(expiries.values()) == [120]

    def down(*a):
        raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(webapp.db, "_redis_cmd", down)
    assert [webapp._rate_limited("5.6.7.8") for _ in range(3)] == [False, False, True]


def test_link_preview_uses_this_deployments_origin(client):
    page = client.get("/").text
    assert '<meta property="og:image" content="http://testserver/static/og.png">' in page
    assert "__ORIGIN__" not in page
    hostile = client.get("/", headers={"host": 'evil.com"><script>x</script>'}).text
    assert "<script>x</script>" not in hostile
    assert client.get("/static/favicon.svg").status_code == 200
