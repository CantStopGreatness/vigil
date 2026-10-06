"""A deliberately misconfigured website, so you can test Vigil legally on your own machine.

    python demo/vulnerable_site.py          # serves http://127.0.0.1:8080
    vigil http://127.0.0.1:8080 --allow-private --html demo-report.html

Every secret below is fake.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILES = {
    "/": (b"<!doctype html><html><head><meta name='generator' content='WordPress 5.2.1'></head>"
          b"<body><h1>Totally Secure Bank</h1></body></html>", "text/html"),
    "/.git/HEAD": (b"ref: refs/heads/main\n", "text/plain"),
    "/.env": (b"APP_ENV=production\nDB_PASSWORD=hunter2\nSTRIPE_SECRET=sk_live_fake\n", "text/plain"),
    "/phpinfo.php": (b"<html><title>phpinfo()</title><h1>PHP Version 7.2.1</h1></html>", "text/html"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.29"
    sys_version = "(Ubuntu)"

    def do_GET(self):  # noqa: N802
        # Soft-404: unknown paths return 200 with an HTML page, to show that
        # Vigil's content validators avoid false positives.
        body, ctype = FILES.get(self.path, (b"<html><body>Page not found</body></html>", "text/html"))
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/7.2.1")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("Vulnerable demo site on http://127.0.0.1:8080  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
