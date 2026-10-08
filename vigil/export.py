"""Downloadable reports (PDF and Word) meant to be handed over as-is, with no editing needed.

Both formats are built from the same content (executive summary, findings grouped by
severity, passed checks, methodology), so they always say the same thing. The layout is
compact so a typical report fits on one or two pages.

Finding text can contain strings copied from the scanned site, which is untrusted.
reportlab's Paragraph understands a small markup language (including <img> tags that
read local files), so every string is XML-escaped before it goes anywhere near it.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from . import __version__
from .models import Finding, ScanResult, Severity

SEV_HEX = {
    Severity.CRITICAL: "B4232A", Severity.HIGH: "D9480F", Severity.MEDIUM: "A87400",
    Severity.LOW: "3B6FB6", Severity.INFO: "6B6B66",
}
GRADE_HEX = {"A": "2F7D4F", "B": "2F7D4F", "C": "A87400", "D": "D9480F", "F": "B4232A"}
TIMELINE = {
    Severity.CRITICAL: "Immediately", Severity.HIGH: "Within 1 week", Severity.MEDIUM: "Within 1 month",
    Severity.LOW: "When convenient", Severity.INFO: "Optional",
}
VERDICT = {
    "A": "The site is well configured, and only minor or optional improvements were identified.",
    "B": "The site is in good shape, with a few improvements recommended.",
    "C": "The site has a reasonable baseline but several gaps that should be addressed.",
    "D": "The site has significant weaknesses that should be fixed soon.",
    "F": "The site has serious security problems that need immediate attention.",
}
METHODOLOGY = [
    ("HTTPS transport", "Whether the site is served over HTTPS and whether plain-HTTP visitors are redirected."),
    ("TLS / certificate", "Certificate validity and expiry, and whether obsolete TLS 1.0/1.1 is still accepted."),
    ("Security headers", "Browser protections: HSTS, Content-Security-Policy, clickjacking, MIME sniffing, "
                         "Referrer-Policy, Permissions-Policy."),
    ("Cookies", "Secure, HttpOnly and SameSite attributes on cookies set by the site."),
    ("Information disclosure", "Software version numbers revealed in response headers or page markup."),
    ("Known vulnerabilities (CVEs)", "Disclosed software versions matched against the National Vulnerability "
                                     "Database. Distributions may have backported fixes, so treat as likely."),
    ("Exposed files", "Well-known sensitive files and admin pages (.git, .env, backups, phpinfo, phpMyAdmin), "
                      "confirmed by content rather than status code alone."),
    ("Email spoofing (SPF/DMARC)", "DNS records that stop others from sending email as the domain."),
]
DISCLAIMER = ("This is an automated, non-intrusive posture check, not a penetration test. It made ordinary "
              "requests to publicly reachable addresses and sent no attack payloads. It does not find flaws in "
              "the site's own application code. Results reflect the site at the time of the scan.")
WEIGHTS = ("Severity weights: critical −40, high −20, medium −8, low −3, info 0. "
           "Any critical finding caps the score at 50.")

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff￾￿]")


# --- shared content ----------------------------------------------------------

def _clean(text: str) -> str:
    """Drop characters that are illegal in XML (both PDF markup and .docx are XML underneath)."""
    return _CONTROL.sub("", text or "")


def _spans(text: str) -> list[tuple[str, bool]]:
    """Split `code` spans out of text: [(chunk, is_code), ...]."""
    parts = re.split(r"`([^`]+)`", _clean(text))
    return [(p, i % 2 == 1) for i, p in enumerate(parts) if p]


def _evidence(text: str) -> str:
    """Evidence stores line breaks as a literal backslash-n (so it stays one line in terminals)."""
    return _clean(text).replace("\\n", "\n").strip()


def _evidence_brief(text: str, limit: int = 200) -> str:
    """Evidence squeezed onto one or two lines for the compact findings table."""
    flat = " · ".join(line.strip() for line in _evidence(text).splitlines() if line.strip())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


def by_severity(findings: list[Finding]) -> list[tuple[Severity, list[Finding]]]:
    """Findings grouped by severity, most severe first, skipping empty levels."""
    return [(s, g) for s in Severity if (g := [f for f in findings if f.severity is s])]


def host_of(r: ScanResult) -> str:
    return urlsplit(r.final_url).hostname or r.final_url


def _when(r: ScanResult) -> str:
    try:
        dt = datetime.fromisoformat(r.started_at)
    except ValueError:
        return r.started_at
    return f"{dt.day} {dt:%B %Y, %H:%M} UTC"


def download_name(r: ScanResult, ext: str) -> str:
    host = re.sub(r"[^a-z0-9.-]+", "-", host_of(r).lower()).strip("-.") or "site"
    return f"vigil-report-{host}-{r.started_at[:10]}.{ext}"


# Report sections a reader can switch off. Title block and scan notes always stay.
SECTIONS = ("summary", "details", "passed", "methodology")


@dataclass(frozen=True)
class ReportOptions:
    sections: frozenset[str] = frozenset(SECTIONS)
    min_severity: Severity = Severity.INFO
    evidence: bool = True

    def scope_note(self) -> str | None:
        if self.min_severity is Severity.INFO:
            return None
        return f"This report lists only findings rated {self.min_severity.value} or higher."


FULL_REPORT = ReportOptions()


def tailor(r: ScanResult, opts: ReportOptions) -> ScanResult:
    """Drop findings below the chosen severity and, if asked, their evidence. Score and grade stay as scanned."""
    keep = [f for f in r.findings if f.severity.rank <= opts.min_severity.rank]
    if not opts.evidence:
        keep = [replace(f, evidence="") for f in keep]
    return replace(r, findings=keep)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def executive_summary(r: ScanResult) -> list[str]:
    counts = r.summary()
    issues = [f"{counts[s.value]} {s.value}" for s in Severity if s is not Severity.INFO and counts[s.value]]
    paras = [f"{host_of(r)} scored {r.score} out of 100 (grade {r.grade}) in an automated security scan on "
             f"{_when(r)}. {VERDICT.get(r.grade, '')}"]
    if issues:
        listed = ", ".join(issues[:-1]) + (" and " if len(issues) > 1 else "") + issues[-1]
        n = sum(counts[s.value] for s in Severity if s is not Severity.INFO)
        line = f"The scan found {_plural(n, 'issue')}: {listed}."
    else:
        line = "The scan found no security issues."
    if counts["info"]:
        line += f" It also made {_plural(counts['info'], 'informational suggestion')}."
    paras.append(line)
    urgent = [f.title for f in r.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if urgent:
        paras.append("Fix first: " + "; ".join(urgent[:3]) + ("; and others listed below." if len(urgent) > 3 else "."))
    if r.passed:
        paras.append("No issues were found in: " + ", ".join(r.passed) + ".")
    return paras


# --- PDF ---------------------------------------------------------------------

def render_pdf(r: ScanResult, opts: ReportOptions = FULL_REPORT) -> bytes:
    r, on = tailor(r, opts), opts.sections
    # Bitstream Vera ships with reportlab and covers far more of Unicode than the built-in Helvetica.
    import reportlab
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    fonts = Path(reportlab.__file__).parent / "fonts"
    for name, file in (("Vera", "Vera.ttf"), ("Vera-Bold", "VeraBd.ttf"), ("Vera-Italic", "VeraIt.ttf"),
                       ("Vera-BoldItalic", "VeraBI.ttf")):
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(fonts / file)))
    pdfmetrics.registerFontFamily("Vera", normal="Vera", bold="Vera-Bold", italic="Vera-Italic",
                                  boldItalic="Vera-BoldItalic")

    margin = 0.6 * inch
    width = LETTER[0] - 2 * margin - 12  # usable width: page minus margins minus the frame's 6pt padding
    ink, muted, line, soft = (colors.HexColor(h) for h in ("#1C1C1A", "#6B6B66", "#DDDDD7", "#F4F4F1"))

    def style(name, **kw):
        base = dict(fontName="Vera", fontSize=9, leading=12.5, textColor=ink)
        return ParagraphStyle(name, **{**base, **kw})

    # Sized to keep a typical report to one or two pages.
    s_title = style("title", fontName="Vera-Bold", fontSize=18, leading=22)
    s_url = style("url", fontName="Vera-Bold", fontSize=10.5, leading=14)
    s_sub = style("sub", fontSize=8.5, leading=12, textColor=muted)
    s_h1 = style("h1", fontName="Vera-Bold", fontSize=12, leading=15, spaceBefore=10, spaceAfter=4)
    s_body = style("body", spaceAfter=3)
    s_small = style("small", fontSize=7.5, leading=10, textColor=muted)
    s_cell = style("cell", fontSize=8.5, leading=11)
    s_group = style("group", fontName="Vera-Bold", fontSize=8.5, leading=11, textColor=colors.white)
    s_ev = style("ev", fontName="Courier", fontSize=7.5, leading=9.5, textColor=muted, wordWrap="CJK")
    s_grade = style("grade", fontName="Vera-Bold", fontSize=30, leading=34, textColor=colors.white,
                    alignment=TA_CENTER)
    s_grade_sub = style("gradesub", fontSize=8, leading=10, textColor=colors.white, alignment=TA_CENTER)

    def rich(text: str) -> str:
        out = []
        for chunk, code in _spans(text):
            chunk = escape(chunk)
            out.append(f'<font name="Courier" size="9">{chunk}</font>' if code else chunk)
        return "".join(out)

    def sev_tag(sev: Severity) -> str:
        return f'<font name="Vera-Bold" color="#{SEV_HEX[sev]}">{sev.value.upper()}</font>'

    story = []

    # Header: title on the left, grade badge on the right.
    title = [Paragraph("Website Security Report", s_title), Spacer(1, 2),
             Paragraph(escape(_clean(r.final_url)), s_url),
             Paragraph(f"Scanned {escape(_when(r))} &nbsp;·&nbsp; Vigil {__version__}", s_sub)]
    badge = Table([[Paragraph(r.grade, s_grade)], [Paragraph(f"{r.score} / 100", s_grade_sub)]],
                  colWidths=[0.95 * inch], rowHeights=[0.48 * inch, 0.24 * inch])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#" + GRADE_HEX.get(r.grade, "6B6B66"))),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    head = Table([[title, badge]], colWidths=[width - 1.1 * inch, 1.1 * inch])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    story += [head, Spacer(1, 8)]

    # Severity counts on one line.
    counts = r.summary()
    strip = Table([[Paragraph(f'<font size="12" name="Vera-Bold" color="#{SEV_HEX[s]}">{counts[s.value]}</font>'
                              f'&nbsp; {s.value.capitalize()}', s_cell) for s in Severity]],
                  colWidths=[width / 5] * 5)
    strip.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), soft), ("BOX", (0, 0), (-1, -1), 0.5, line),
        ("LINEBEFORE", (1, 0), (-1, -1), 0.5, line), ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [strip]
    if note := opts.scope_note():
        story += [Spacer(1, 4), Paragraph(escape(note), s_small)]

    if "summary" in on:
        story.append(Paragraph("Executive summary", s_h1))
        story += [Paragraph(escape(_clean(p)), s_body) for p in executive_summary(r)]

    # Findings grouped by severity: one coloured header per level, then a compact row per finding.
    if r.findings and "details" in on:
        story.append(Paragraph("Findings", s_h1))
        for sev, group in by_severity(r.findings):
            rows = [[Paragraph(f"{sev.value.upper()} &nbsp;·&nbsp; {_plural(len(group), 'finding')} &nbsp;·&nbsp; "
                               f"fix {TIMELINE[sev].lower()}", s_group), ""]]
            for f in group:
                what = [Paragraph(rich(f.description), s_cell)]
                if f.recommendation:
                    what.append(Paragraph("<b>Fix:</b> " + rich(f.recommendation), s_cell))
                if f.evidence:
                    what.append(Paragraph(escape(_evidence_brief(f.evidence)), s_ev))
                rows.append([[Paragraph(f"<b>{escape(_clean(f.title))}</b>", s_cell),
                              Paragraph(escape(f.check), s_small)], what])
            t = Table(rows, colWidths=[1.9 * inch, width - 1.9 * inch], repeatRows=1)
            t.setStyle(TableStyle([
                ("SPAN", (0, 0), (-1, 0)), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#" + SEV_HEX[sev])),
                ("LINEBELOW", (0, 1), (-1, -1), 0.5, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story += [t, Spacer(1, 4)]

    if r.passed and "passed" in on:
        story.append(Paragraph("Checks passed", s_h1))
        story.append(Paragraph('<font color="#2F7D4F">✓</font>&nbsp; ' + " &nbsp;·&nbsp; ".join(map(escape, r.passed)),
                               s_body))
    if r.errors:
        story.append(Paragraph("Scan notes", s_h1))
        story += [Paragraph(escape(_clean(e)), s_cell) for e in r.errors]

    if "methodology" in on:
        story.append(Paragraph("Methodology and scope", s_h1))
        checks = " &nbsp;·&nbsp; ".join(f"<b>{escape(n)}:</b> {escape(d)}" for n, d in METHODOLOGY)
        story += [Paragraph(checks, s_small),
                  Spacer(1, 4), Paragraph(escape(DISCLAIMER) + " " + escape(WEIGHTS), s_small)]

    class NumberedCanvas(rl_canvas.Canvas):
        """Two-pass canvas so the footer can say 'Page X of Y'."""

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._pages = []

        def showPage(self):  # noqa: N802 (reportlab API)
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self.setFont("Vera", 8)
                self.setFillColor(muted)
                self.setStrokeColor(line)
                self.line(margin, 0.55 * inch, LETTER[0] - margin, 0.55 * inch)
                self.drawString(margin, 0.4 * inch, f"Security report · {_clean(host_of(r))}")
                self.drawRightString(LETTER[0] - margin, 0.4 * inch, f"Page {self._pageNumber} of {total}")
                super().showPage()
            super().save()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER, leftMargin=margin, rightMargin=margin, topMargin=0.55 * inch,
        bottomMargin=0.75 * inch, title=f"Security report: {_clean(host_of(r))}", author="Vigil",
        subject="Website security posture scan", creator=f"Vigil {__version__}",
    )
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# --- Word (.docx) --------------------------------------------------------------

def render_docx(r: ScanResult, opts: ReportOptions = FULL_REPORT) -> bytes:
    r, on = tailor(r, opts), opts.sections
    from docx import Document
    from docx.enum.section import WD_ORIENT
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor

    def rgb(h: str) -> RGBColor:
        return RGBColor.from_string(h)

    def shade(cell, hex_color: str) -> None:
        tc_pr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_color)
        tc_pr.append(shd)

    def borders(table, color="DDDDD7", inside=True) -> None:
        tbl_pr = table._tbl.tblPr
        b = OxmlElement("w:tblBorders")
        edges = ("top", "left", "bottom", "right") + (("insideH", "insideV") if inside else ())
        for edge in edges:
            e = OxmlElement(f"w:{edge}")
            e.set(qn("w:val"), "single")
            e.set(qn("w:sz"), "4")
            e.set(qn("w:color"), color)
            b.append(e)
        tbl_pr.append(b)

    def add_rich(p, text: str, size: float = 10) -> None:
        for chunk, code in _spans(text):
            run = p.add_run(chunk)
            run.font.size = Pt(size - 0.5 if code else size)
            if code:
                run.font.name = "Consolas"

    def field(p, instr: str) -> None:
        """Insert a Word field (PAGE / NUMPAGES) so page numbers update automatically."""
        run = p.add_run()
        for tag, attr in (("w:fldChar", "begin"), ("w:instrText", instr), ("w:fldChar", "end")):
            el = OxmlElement(tag)
            if tag == "w:fldChar":
                el.set(qn("w:fldCharType"), attr)
            else:
                el.set(qn("xml:space"), "preserve")
                el.text = attr
            run._r.append(el)
        run.font.size = Pt(8)
        run.font.color.rgb = rgb("6B6B66")

    doc = Document()
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.PORTRAIT
    sec.page_width, sec.page_height = Inches(8.5), Inches(11)
    for side in ("left_margin", "right_margin"):
        setattr(sec, side, Inches(0.6))
    sec.top_margin, sec.bottom_margin = Inches(0.55), Inches(0.6)

    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(9.5)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")
    normal.paragraph_format.space_after = Pt(2)
    for name, size in (("Heading 1", 12.5), ("Heading 2", 11)):
        st = doc.styles[name]
        st.font.name, st.font.size, st.font.bold = "Calibri", Pt(size), True
        st.font.color.rgb = rgb("1C1C1A")
        rfonts = st.element.rPr.rFonts  # theme fonts would override Calibri, so drop them
        for attr in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
            rfonts.attrib.pop(qn(attr), None)
        st.paragraph_format.space_before = Pt(10 if name == "Heading 1" else 4)
        st.paragraph_format.space_after = Pt(3)

    props = doc.core_properties
    props.title = f"Security report: {_clean(host_of(r))}"
    props.author = "Vigil"
    props.subject = "Website security posture scan"

    # Footer: "Security report · host        Page X of Y"
    fp = sec.footer.paragraphs[0]
    fp.text = ""
    lead = fp.add_run(f"Security report · {_clean(host_of(r))}    ·    Page ")
    lead.font.size, lead.font.color.rgb = Pt(8), rgb("6B6B66")
    field(fp, "PAGE")
    mid = fp.add_run(" of ")
    mid.font.size, mid.font.color.rgb = Pt(8), rgb("6B6B66")
    field(fp, "NUMPAGES")

    # Title block with grade badge.
    head = doc.add_table(rows=1, cols=2)
    head.alignment = WD_TABLE_ALIGNMENT.CENTER
    left, right = head.rows[0].cells
    left.width, right.width = Inches(6.2), Inches(1.1)
    p = left.paragraphs[0]
    run = p.add_run("Website Security Report")
    run.bold, run.font.size = True, Pt(18)
    p = left.add_paragraph()
    run = p.add_run(_clean(r.final_url))
    run.bold, run.font.size = True, Pt(11)
    p = left.add_paragraph()
    run = p.add_run(f"Scanned {_when(r)}  ·  Vigil {__version__}")
    run.font.size, run.font.color.rgb = Pt(8.5), rgb("6B6B66")
    shade(right, GRADE_HEX.get(r.grade, "6B6B66"))
    p = right.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(r.grade)
    run.bold, run.font.size, run.font.color.rgb = True, Pt(28), rgb("FFFFFF")
    p = right.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"{r.score} / 100")
    run.font.size, run.font.color.rgb = Pt(8.5), rgb("FFFFFF")
    doc.add_paragraph().paragraph_format.space_after = Pt(0)

    # Severity counts on one line.
    counts = r.summary()
    strip = doc.add_table(rows=1, cols=5)
    borders(strip)
    for i, s in enumerate(Severity):
        cell = strip.cell(0, i)
        shade(cell, "F4F4F1")
        run = cell.paragraphs[0].add_run(str(counts[s.value]))
        run.bold, run.font.size, run.font.color.rgb = True, Pt(12), rgb(SEV_HEX[s])
        run = cell.paragraphs[0].add_run(f"  {s.value.capitalize()}")
        run.font.size = Pt(8.5)
    if note := opts.scope_note():
        run = doc.add_paragraph().add_run(note)
        run.font.size, run.font.color.rgb = Pt(8), rgb("6B6B66")

    if "summary" in on:
        doc.add_heading("Executive summary", level=1)
        for para in executive_summary(r):
            doc.add_paragraph(_clean(para))

    # Findings grouped by severity: one coloured header per level, then a compact row per finding.
    if r.findings and "details" in on:
        doc.add_heading("Findings", level=1)
        for sev, group in by_severity(r.findings):
            t = doc.add_table(rows=1, cols=2)
            borders(t, inside=False)
            header = t.cell(0, 0).merge(t.cell(0, 1))
            shade(header, SEV_HEX[sev])
            run = header.paragraphs[0].add_run(
                f"{sev.value.upper()}  ·  {_plural(len(group), 'finding')}  ·  fix {TIMELINE[sev].lower()}")
            run.bold, run.font.size, run.font.color.rgb = True, Pt(9), rgb("FFFFFF")
            hdr = OxmlElement("w:tblHeader")  # repeat the level's header if the group spills onto a new page
            hdr.set(qn("w:val"), "true")
            t.rows[0]._tr.get_or_add_trPr().append(hdr)
            for f in group:
                a, b = t.add_row().cells
                a.width, b.width = Inches(1.9), Inches(5.4)
                run = a.paragraphs[0].add_run(_clean(f.title))
                run.bold, run.font.size = True, Pt(9.5)
                run = a.add_paragraph().add_run(f.check)
                run.font.size, run.font.color.rgb = Pt(8), rgb("6B6B66")
                add_rich(b.paragraphs[0], f.description, 9.5)
                if f.recommendation:
                    p = b.add_paragraph()
                    p.add_run("Fix: ").bold = True
                    add_rich(p, f.recommendation, 9.5)
                if f.evidence:
                    run = b.add_paragraph().add_run(_evidence_brief(f.evidence))
                    run.font.name, run.font.size, run.font.color.rgb = "Consolas", Pt(8), rgb("6B6B66")
                cant = OxmlElement("w:cantSplit")  # keep each finding on one page
                cant.set(qn("w:val"), "true")
                t.rows[-1]._tr.get_or_add_trPr().append(cant)
            doc.add_paragraph().paragraph_format.space_after = Pt(0)

    if r.passed and "passed" in on:
        doc.add_heading("Checks passed", level=1)
        p = doc.add_paragraph()
        run = p.add_run("✓  ")
        run.bold, run.font.color.rgb = True, rgb("2F7D4F")
        p.add_run("  ·  ".join(r.passed))
    if r.errors:
        doc.add_heading("Scan notes", level=1)
        for e in r.errors:
            doc.add_paragraph(_clean(e))

    if "methodology" in on:
        doc.add_heading("Methodology and scope", level=1)
        p = doc.add_paragraph()
        for i, (name, desc) in enumerate(METHODOLOGY):
            run = p.add_run(("  ·  " if i else "") + f"{name}: ")
            run.bold, run.font.size = True, Pt(8)
            run = p.add_run(desc)
            run.font.size, run.font.color.rgb = Pt(8), rgb("6B6B66")
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(4)
        run = p.add_run(f"{DISCLAIMER} {WEIGHTS}")
        run.font.size, run.font.color.rgb = Pt(8), rgb("6B6B66")

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
