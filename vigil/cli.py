"""Command-line interface.

    vigil example.com
    vigil example.com --html report.html --json report.json
    vigil example.com --pdf report.pdf --docx report.docx
    vigil example.com --fail-under 80     # exit 1 if score < 80 (handy in CI)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from . import __version__
from .checks import CHECKS_BY_KEY
from .export import render_docx, render_pdf
from .models import ScanResult, Severity
from .report import render_html
from .scanner import scan
from .target import InvalidTargetError, UnsafeTargetError

COLORS = {
    Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[34m", Severity.INFO: "\033[2m",
}
RESET, BOLD, GREEN = "\033[0m", "\033[1m", "\033[32m"


def _c(code: str) -> str:
    return code if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else ""


def print_result(r: ScanResult) -> None:
    print(f"\n{_c(BOLD)}{r.final_url}{_c(RESET)}")
    print(f"Grade {_c(BOLD)}{r.grade}{_c(RESET)}  ·  score {r.score}/100  ·  {r.duration_ms} ms\n")
    for f in r.findings:
        tag = f"{_c(COLORS[f.severity])}{f.severity.value.upper():<8}{_c(RESET)}"
        print(f"  {tag} {f.title}")
        if f.evidence:
            print(f"           {_c(COLORS[Severity.INFO])}{f.evidence[:110]}{_c(RESET)}")
    if r.passed:
        print()
        for p in r.passed:
            print(f"  {_c(GREEN)}PASS{_c(RESET)}     {p}")
    for e in r.errors:
        print(f"  {_c(COLORS[Severity.INFO])}note: {e}{_c(RESET)}")
    print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vigil", description="Website security posture scanner.")
    p.add_argument("target", help="domain or URL, e.g. example.com")
    p.add_argument("--json", metavar="PATH", help="write JSON results ('-' for stdout)")
    p.add_argument("--html", metavar="PATH", help="write an HTML report")
    p.add_argument("--pdf", metavar="PATH", help="write a PDF report")
    p.add_argument("--docx", metavar="PATH", help="write a Word (.docx) report")
    p.add_argument("--checks", help=f"comma-separated subset: {','.join(CHECKS_BY_KEY)}")
    p.add_argument("--fail-under", type=int, metavar="SCORE", help="exit 1 if score is below SCORE")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--allow-private", action="store_true",
                   help="allow localhost/private IPs (for scanning your own dev servers)")
    p.add_argument("--version", action="version", version=f"vigil {__version__}")
    a = p.parse_args(argv)

    checks = None
    if a.checks:
        unknown = [k for k in a.checks.split(",") if k not in CHECKS_BY_KEY]
        if unknown:
            p.error(f"unknown check(s): {', '.join(unknown)}")
        checks = [CHECKS_BY_KEY[k] for k in a.checks.split(",")]

    try:
        result = asyncio.run(scan(a.target, checks=checks, allow_private=a.allow_private, timeout=a.timeout))
    except (InvalidTargetError, UnsafeTargetError, ConnectionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if a.json == "-":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_result(result)
        if a.json:
            Path(a.json).write_text(json.dumps(result.to_dict(), indent=2))
            print(f"JSON written to {a.json}")
    out = sys.stderr if a.json == "-" else sys.stdout
    if a.html:
        Path(a.html).write_text(render_html(result), encoding="utf-8")
        print(f"HTML report written to {a.html}", file=out)
    if a.pdf:
        Path(a.pdf).write_bytes(render_pdf(result))
        print(f"PDF report written to {a.pdf}", file=out)
    if a.docx:
        Path(a.docx).write_bytes(render_docx(result))
        print(f"Word report written to {a.docx}", file=out)

    if a.fail_under is not None and result.score < a.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
