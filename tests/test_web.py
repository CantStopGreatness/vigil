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

    async def offline_scan(url, **kwargs):
        t = httpx.MockTransport(lambda req: httpx.Response(200, content=b"<html></html>"))
        return await real_scan(url, checks=[headers], transport=t, **kwargs)

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
