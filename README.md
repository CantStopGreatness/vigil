# Vigil

**Website security posture scanner.** Point it at a domain and in a few seconds you get a graded report covering security headers, TLS, cookies, exposed secrets, and email-spoofing protection, with a plain-English fix for every finding.

![CI](https://github.com/CantStopGreatness/vigil/actions/workflows/ci.yml/badge.svg)

> **Why I built this:** As a cybersecurity analyst at CyberWolfe, I audited 50+ small-business websites by hand and wrote a report for each. Most findings were the same dozen misconfigurations. Vigil automates that audit and produces the report in seconds.

<!-- TODO: add a screenshot or GIF of the dashboard here: docs/screenshot.png -->

## What it checks

| Check | Examples of what it catches |
|---|---|
| **HTTPS transport** | Site served over plain HTTP; HTTP not redirected to HTTPS |
| **TLS / certificate** | Invalid or expiring certificate; server still accepts (or only supports) TLS 1.0/1.1 |
| **Security headers** | Missing HSTS, CSP, clickjacking protection, `nosniff`, Referrer-Policy; CSP with `'unsafe-inline'` |
| **Cookies** | Cookies without `Secure`, session cookies without `HttpOnly`, missing `SameSite` |
| **Information disclosure** | `Server: nginx/1.18.0`, `X-Powered-By: PHP/7.4`, CMS version in `<meta generator>` |
| **Exposed files** | Public `.git/`, `.env`, `.htpasswd`, SQL dumps, backup archives, `phpinfo()`, phpMyAdmin; missing `security.txt` |
| **Email spoofing** | Missing/weak SPF (`+all`, multiple records), missing DMARC or `p=none`; looked up on the organizational domain via the Public Suffix List |

**Downloadable reports.** Every scan can be exported as a formatted PDF or Word document that is ready to hand to a client or manager without editing: a grade badge, a plain-English executive summary, a findings table with suggested fix-by timelines, a detailed card per finding (what was found, evidence, how to fix), the checks that passed, and a methodology and scope section. Page numbers and headers are included, and both formats contain the same content.

Findings are weighted by severity into a **0–100 score and A–F grade**. One critical issue (like a leaked `.env`) caps the score at 50, no matter how good everything else is.

## Quick start

```bash
git clone https://github.com/CantStopGreatness/vigil && cd vigil
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

vigil yoursite.com                                  # coloured terminal output
vigil yoursite.com --html report.html               # shareable HTML report
vigil yoursite.com --pdf report.pdf --docx report.docx  # client-ready PDF / Word report
vigil yoursite.com --json - | jq .score             # machine-readable
vigil yoursite.com --fail-under 80                  # exit 1 if score < 80 (use in CI)
vigil yoursite.com --checks headers,cookies         # run a subset
```

**Web dashboard** (scan form, results, per-browser history, private shareable report links, one-click PDF and Word downloads):

```bash
uvicorn vigil.web.app:app --reload        # http://127.0.0.1:8000
VIGIL_ALLOW_PRIVATE=1 uvicorn vigil.web.app:app   # local dev only: allow scanning localhost
# or
docker build -t vigil . && docker run -p 8000:8000 vigil
```

**Try it safely on a deliberately vulnerable site** that runs on your own machine:

```bash
python demo/vulnerable_site.py &
vigil http://127.0.0.1:8080 --allow-private --html demo-report.html
```

## Architecture

```
            ┌──────────┐     ┌───────────────┐
 CLI ──────▶│          │     │  SSRF guard   │  every request (incl. redirects) must resolve
            │ scanner  │────▶│  (transport)  │  to a public IP; the connection is pinned to
 FastAPI ──▶│          │     └───────────────┘  the address that was checked
            └────┬─────┘
                 │ fetch target once → ScanContext
                 ▼
   ┌─────────────────────────────────────────────┐
   │ checks run concurrently (asyncio.gather)    │
   │ transport · tls · headers · cookies ·       │
   │ disclosure · exposure · email_dns           │
   └────────────────────┬────────────────────────┘
                        ▼
            scoring → ScanResult → terminal / JSON / HTML report / SQLite
```

- **Each check is a small module** with `NAME` and `async def run(ctx) -> list[Finding] | None`. Adding a check means adding one file and one line to `checks/__init__.py`.
- **One crashing check never kills a scan.** Its error is recorded and the rest still run.
- **The target is fetched once** and shared through `ScanContext`, so checks don't make duplicate requests.

## Security design decisions

A security tool that is itself insecure is embarrassing, so these were deliberate:

- **SSRF protection.** A public scanner accepts arbitrary URLs, so someone could ask it to scan `http://169.254.169.254/` (cloud metadata) or `localhost:6379`. Vigil resolves every hostname and rejects private, loopback, link-local and other non-global addresses. It does this on every request, including redirects, because a public site could otherwise 302 the scanner to an internal host.
- **No DNS rebinding.** Checking a name and then letting the HTTP library resolve it again leaves a gap a hostile DNS server can exploit (public IP for the check, `127.0.0.1` for the connection). Vigil's transport resolves once, validates every address, and connects to exactly that IP, while TLS still verifies the certificate against the hostname via SNI. The raw-socket TLS check is pinned the same way, and env-configured proxies are ignored.
- **No false positives from soft 404s.** Many sites return `200 OK` for every path. Every exposed-file probe has a content validator (e.g. `.git/HEAD` must start with `ref: refs/`, a zip must start with `PK\x03\x04`).
- **Secrets are masked in reports.** If a `.env` is found, the evidence shows `DB_PASSWORD=****`, never the value.
- **Bounded downloads and scans.** Probes stream at most 8 KB and the page itself at most 2 MB, so a 2 GB `backup.zip` or an endless homepage can't exhaust memory. Each web scan has a hard time limit and the number of concurrent scans is capped.
- **XSS-safe output.** Evidence contains text from the scanned (possibly hostile) site. The HTML report is auto-escaped by Jinja2, and the dashboard builds the DOM with `textContent` only. There's a test that injects `<script>` through a `Server` header.
- **Private reports.** Reports are addressed by a random 128-bit token, not a row number, so nobody can enumerate other people's scans. There is no public scan list (history is kept in your own browser), report pages send `Referrer-Policy: no-referrer` and `X-Robots-Tag: noindex`, and scans are deleted after `VIGIL_RETENTION_DAYS`.
- **The dashboard passes its own scan.** Strict CSP with no inline script, `frame-ancestors 'none'`, `nosniff`, HSTS over HTTPS, no server banner. `vigil` run against its own dashboard scores A.
- **Authorization gate and rate limiting** on the web API (per client IP, per /64 for IPv6, proxy-aware).

## Deploying publicly

The Docker image is the intended deployment. Put it behind a TLS-terminating reverse proxy (Caddy, nginx, a PaaS load balancer) and mount a volume at `/data` for the SQLite database.

```bash
docker build -t vigil .
docker run -d -p 8000:8000 -v vigil-data:/data \
  -e FORWARDED_ALLOW_IPS=<your proxy's IP> \
  -e VIGIL_SECURITY_CONTACT=mailto:you@example.com \
  vigil
```

| Variable | Default | Purpose |
|---|---|---|
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies whose `X-Forwarded-For` is trusted. Set it to your proxy's address, or every visitor shares one rate-limit bucket. Never use `*` when the container is reachable directly. |
| `VIGIL_RATE_LIMIT` | `5` | Scans per client per minute |
| `VIGIL_MAX_CONCURRENT_SCANS` | `4` | Scans running at once; extra requests get `503` |
| `VIGIL_SCAN_TIMEOUT` | `60` | Seconds before a web scan is abandoned (`504`) |
| `VIGIL_RETENTION_DAYS` | `30` | Stored reports older than this are deleted |
| `VIGIL_SECURITY_CONTACT` | unset | Publishes `/.well-known/security.txt` with this `Contact:` |
| `VIGIL_DB` | `/data/vigil.db` | SQLite path |
| `VIGIL_ALLOW_PRIVATE` | unset | `1` allows scanning private IPs. **Local development only**: it disables SSRF protection. |

Run a single worker (the image does): the rate limiter and concurrency cap are in memory. To scale out, move them to Redis and the database to Postgres (see Roadmap).

## Testing

```bash
pytest -q        # 83 tests, no network needed
ruff check .
```

The suite runs fully offline. HTTP is faked with `httpx.MockTransport` and DNS with a monkeypatched resolver. It covers each check, the scoring, SSRF blocking (including redirects and DNS rebinding), IP pinning, soft-404 handling, secret masking, report escaping, the web API's security headers, private report tokens, timeouts and database migration. CI runs on Python 3.11–3.13 and builds the Docker image.

## Responsible use

Only scan websites you own or have explicit permission to test. Vigil is passive: it makes a few normal `GET` requests and one TLS handshake per protocol version, sends no attack payloads, and identifies itself in its User-Agent. It is a posture check, not a penetration test.

## Roadmap

- [ ] CVE matching: map detected versions (`nginx/1.18.0`) to known CVEs via the NVD API
- [ ] Postgres + Redis (shared rate limits) + background job queue so the web app can run multiple workers
- [ ] Batch scanning from a CSV of domains, with a comparison dashboard
- [ ] Scheduled re-scans and alerts when a grade drops (e.g. cert about to expire)

## What I learned

<!-- Write 3–5 bullets in your own words after you've worked on it: tradeoffs, bugs you hit, what you'd do differently. Recruiters read this section. -->

- **A security scanner is itself an attack surface.** I started out thinking about the sites being scanned, but the bigger risk was the scanner. Checking that a URL is public isn't enough: a redirect or a DNS rebind can point it at internal addresses after the check. Resolving each host once and connecting to exactly that IP was the only reliable fix.
- **Untrusted input shows up in places you don't expect.** Escaping scanned-site text in the HTML report was obvious. Less obvious: the PDF library has its own markup language (including tags that read local files), so the same text needed escaping there too. Every output format is a new place for the same input to cause trouble.
- **Reports are for the reader.** My first version created a PDF with five pages for one site. The reports I did by hand taught me that clients want one or two pages, similar to a resume. You don't want a long list of all the vulnerabilities and minor details, but a summarized list of the major problems, and possible solutions.
- **Serverless changes your assumptions.** SQLite and an in-memory rate limiter worked on a single server. On Vercel, with no persistent disk and many short-lived instances, scans disappeared between requests. I moved storage to Redis with automatic expiry. Next time I'd design the storage layer from the start, and move the rate limiter to Redis, so the limit holds across instances.

## License

MIT
