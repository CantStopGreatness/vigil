"""Render a ScanResult as a self-contained HTML report."""

from __future__ import annotations

import re

from jinja2 import Environment, PackageLoader, select_autoescape
from markupsafe import Markup, escape

from . import __version__
from .export import by_severity
from .models import ScanResult


def _md_code(text: str) -> Markup:
    """Turn `backtick` spans into <code>, escaping everything else."""
    parts = re.split(r"`([^`]+)`", text)
    html = "".join(f"<code>{escape(p)}</code>" if i % 2 else str(escape(p)) for i, p in enumerate(parts))
    return Markup(html)


_env = Environment(loader=PackageLoader("vigil", "templates"), autoescape=select_autoescape(["html"]))
_env.filters["md_code"] = _md_code


def render_html(result: ScanResult, token: str | None = None, query: str = "") -> str:
    """token: when served by the web app, show PDF/Word download buttons for this report.
    query: the report options (?sections=...) to carry over to those downloads."""
    return _env.get_template("report.html").render(r=result, groups=by_severity(result.findings), version=__version__,
                                                   token=token, query=query)
