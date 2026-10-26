"""PDF version of the report, for clients who want a document to file or print.

Same content as the HTML report. Built with ReportLab, an optional dependency:
    pip install "domain-security-check[pdf]"
"""

from __future__ import annotations

import os
from io import BytesIO
from xml.sax.saxutils import escape

from .branding import Branding
from .i18n import date
from .models import Category, Result, Status
from .nis2 import DIRECTIVE_URL as NIS2_URL
from .nis2 import HEADING as NIS2_HEADING
from .nis2 import INTRO as NIS2_INTRO
from .report import (
    CATEGORY_LABELS,
    CATEGORY_METHOD,
    GRADE_SUMMARY,
    GRADES_TEXT,
    LABELS,
    LIMITS_TEXT,
    METHOD_TEXT,
    _points,
    _sorted,
    _translator,
    change_lines,
    changes_heading,
    executive_lines,
    letter,
    nis2_rows,
    reference_groups,
)
from .sources import references
from .summary import EFFORT_LABELS, IMPACT_LABELS, actions


class PDFUnavailable(RuntimeError):
    """ReportLab is not installed."""


INSTALL_HINT = 'PDF output needs ReportLab: pip install "domain-security-check[pdf]"'

STATUS_COLORS = {  # (text, background)
    Status.CRITICAL: ("#b3261e", "#fbe4e2"),
    Status.WARNING: ("#9a5b00", "#fdf0d9"),
    Status.OK: ("#1f7a4d", "#e3f4ea"),
    Status.INFO: ("#2f5d9e", "#e5edf8"),
}
GRADE_COLORS = {"A": STATUS_COLORS[Status.OK], "B": STATUS_COLORS[Status.OK], "C": STATUS_COLORS[Status.WARNING],
                "D": STATUS_COLORS[Status.CRITICAL], "F": STATUS_COLORS[Status.CRITICAL], "N": ("#5d6677", "#eef0f3")}
TEXT, MUTED, BORDER = "#1d2330", "#5d6677", "#e3e6eb"


def render_pdf(r: Result, author: str = "", lang: str = "en", branding: Branding | None = None,
               nis2: bool = False) -> bytes:
    """The report as PDF bytes. Raise PDFUnavailable if ReportLab is missing.

    With a branding (company, contact, client, logo or colour), the report starts with a cover page.
    """
    brand = branding or Branding(author=author)
    author = brand.author or author
    accent = brand.color
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as e:
        raise PDFUnavailable(INSTALL_HINT) from e

    font, bold = _register_fonts(pdfmetrics, TTFont)
    covered = set(pdfmetrics.getFont(font).face.charToGlyph)

    L = _translator(lang)  # noqa: N806 - short name for "translate"

    def t(text: str) -> str:
        """Escape for ReportLab's markup and drop characters the font cannot draw."""
        return escape("".join(c for c in text if ord(c) in covered or c in "\n\t"))

    def style(name, size=9.5, color=TEXT, leading=None, font_name=font, **kw):
        return ParagraphStyle(name, fontName=font_name, fontSize=size, leading=leading or size * 1.35,
                              textColor=colors.HexColor(color), **kw)

    title = style("title", 20, font_name=bold, leading=24)
    sub = style("sub", 9, MUTED)
    body = style("body")
    small = style("small", 8, MUTED)
    h2 = style("h2", 13, accent, font_name=bold, spaceBefore=10, spaceAfter=6, keepWithNext=1)
    centered = style("centered", 8, MUTED, alignment=TA_CENTER)

    def grade_cell(grade: str, size: int):
        fg, _ = GRADE_COLORS[letter(grade)]
        return Paragraph(f'<font color="{fg}">{t(grade)}</font>',
                         style(f"g{size}", size, font_name=bold, alignment=TA_CENTER, leading=size * 1.1))

    def badge(status: Status):
        fg, _ = STATUS_COLORS[status]
        return Paragraph(f'<font color="{fg}"><b>{t(L(LABELS[status]))}</b></font>', style("badge", 8, font_name=bold))

    story: list = []
    if brand.custom:
        story += _cover(r, brand, L, t, style, grade_cell, lang, bold, (Image, PageBreak, Paragraph, Spacer, Table), mm)
    by = L(" by {author}", author=author) if author else ""
    story += [
        Paragraph(t(r.domain), title),
        Paragraph(t(f"{L('Passive security audit')}{by} · {date(r.date, lang)} · {L('overall grade = weakest area')}"),
                  sub),
        Spacer(1, 3 * mm),
        Paragraph(t(L(GRADE_SUMMARY[letter(r.grade)])), body),
    ]
    if r.cap_reason:
        capped = L("{reason}: website grade capped at F.", reason=_capital(L(r.cap_reason)))
        story.append(Paragraph(f'<font color="{STATUS_COLORS[Status.CRITICAL][0]}">{t(capped)}</font>', body))
    story.append(Spacer(1, 4 * mm))

    # Grades: overall, then one column per area
    keys = list(r.grades)
    header_row = [Paragraph(t(L("Overall")), centered)] + [Paragraph(t(L(CATEGORY_LABELS[k])), centered) for k in keys]
    grade_row = [grade_cell(r.grade, 26)] + [grade_cell(r.grades[k].grade, 18) for k in keys]
    detail_row = [Paragraph(t(L("weakest area")), centered)] + [
        Paragraph(t(_grade_detail(L, k, g)), centered) for k, g in r.grades.items()]
    width = 180 * mm
    grades_table = Table([header_row, grade_row, detail_row], colWidths=[width / (len(keys) + 1)] * (len(keys) + 1))
    cell_styles = [("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor(BORDER)),
                   ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.HexColor(BORDER)),
                   ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                   ("TOPPADDING", (0, 1), (-1, 1), 6), ("BOTTOMPADDING", (0, 1), (-1, 1), 6)]
    for col, grade in enumerate([r.grade] + [r.grades[k].grade for k in keys]):
        cell_styles.append(("BACKGROUND", (col, 1), (col, 1), colors.HexColor(GRADE_COLORS[letter(grade)][1])))
    grades_table.setStyle(TableStyle(cell_styles))
    story.append(grades_table)

    counts = {s: sum(1 for f in r.findings if f.status == s) for s in Status}
    summary = " · ".join(f"{counts[s]} {L(LABELS[s]).lower()}"
                         for s in (Status.CRITICAL, Status.WARNING, Status.OK, Status.INFO))
    story += [Spacer(1, 3 * mm), Paragraph(t(summary), sub)]

    if r.changes is not None:
        story.append(Paragraph(t(changes_heading(r.changes, L, lang)), h2))
        for heading, lines in change_lines(r.changes, L):
            story.append(Paragraph(f"<b>{t(heading)}</b>", body))
            for line in lines:
                story.append(Paragraph(f"• {t(line)}", style("change", 9.5, leftIndent=10)))

    # Summary for decision makers
    risks, effort, grade_line = executive_lines(r, L)
    story.append(Paragraph(t(L("Summary for decision makers")), h2))
    if not risks and not effort:
        story.append(Paragraph(t(L("No priority action: keep these settings and audit the domain again regularly.")),
                               body))
    else:
        if risks:
            story.append(Paragraph(f"<b>{t(L('Main risks'))}</b>", body))
            for sentence, impact in risks:
                story.append(Paragraph(f'• {t(sentence)} <font color="{MUTED}" size="8">({t(impact)})</font>',
                                       style("risk", 9.5, leftIndent=10)))
        if effort:
            story.append(Paragraph(f"<b>{t(L('Effort'))}</b> {t(effort)}", body))
        if grade_line:
            story.append(Paragraph(t(grade_line), body))

    todo = actions(r)
    if todo:
        story.append(Paragraph(t(L("Priority actions")), h2))
        for i, a in enumerate(todo, 1):
            f = a.finding
            fg, _ = STATUS_COLORS[f.status]
            tags = f"{L(LABELS[f.status])} · {L(IMPACT_LABELS[a.impact])} · {L(EFFORT_LABELS[a.effort])}"
            item = (f'{i}. <b>{t(L(f.title))}</b> <font color="{fg}" size="8">({t(tags)})</font>'
                    f"<br/>{t(L(f.recommendation))}")
            story.append(Paragraph(item, style(f"p{i}", 9.5, spaceAfter=4, leftIndent=10, firstLineIndent=-10)))

    if nis2:
        story.append(Paragraph(t(L(NIS2_HEADING)), h2))
        story.append(Paragraph(f'{t(L(NIS2_INTRO))} <a href="{escape(NIS2_URL)}">{t(L("Read the directive"))}</a>',
                               body))
        cells = [[Paragraph(f"<b>{t(L(h))}</b>", small) for h in ("Measure", "In this audit", "Result")]]
        cells += [[Paragraph(t(a), small), Paragraph(t(b), small), Paragraph(t(c), small)]
                  for a, b, c in nis2_rows(r, L)]
        nis2_table = Table(cells, colWidths=[70 * mm, 25 * mm, 85 * mm], repeatRows=1)
        nis2_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(BORDER))]))
        story += [Spacer(1, 2 * mm), nis2_table]

    for cat in Category:
        group = [f for f in r.findings if f.category == cat]
        if not group:
            continue
        rows = []
        row_styles = [("VALIGN", (0, 0), (-1, -1), "TOP"),
                      ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(BORDER)),
                      ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
        for i, f in enumerate(_sorted(group)):
            text = f"<b>{t(L(f.title))}</b><br/>{t(_capital(L(f.detail)))}"
            if f.recommendation and f.status != Status.OK:
                text += f'<br/><font color="{accent}">&gt; {t(L(f.recommendation))}</font>'
                if f.fix:
                    how = (f'<br/><font name="Courier" size="8">{t(f.fix.text).replace(chr(10), "<br/>")}</font>'
                           if f.fix.code else t(L(f.fix.text)))
                    doc = f' <a href="{escape(f.fix.link)}">{t(L("Documentation"))}</a>' if f.fix.link else ""
                    text += f'<br/><font size="8.5"><b>{t(L(f.fix.label))}</b> {how}{doc}</font>'
            refs = references(f.source)
            if refs:
                parts = []
                for heading, links_group in reference_groups(L, refs):
                    links = " · ".join(f'<a href="{escape(url)}">{t(label)}</a>' for label, url in links_group)
                    parts.append(f"{t(heading)} {links}")
                text += f'<br/><font size="7.5" color="{MUTED}">{" — ".join(parts)}</font>'
            rows.append([badge(f.status), Paragraph(text, body), Paragraph(t(_points(f.points, lang)), small)])
            row_styles.append(("LINEBEFORE", (0, i), (0, i), 2.5, colors.HexColor(STATUS_COLORS[f.status][0])))
        table = Table(rows, colWidths=[24 * mm, 136 * mm, 20 * mm], repeatRows=0)
        table.setStyle(TableStyle(row_styles))
        story += [Paragraph(t(L(cat.value)), h2), table]

    method = " ".join([L("Method."), L(METHOD_TEXT, by=by), L("Grades."),
                       L(GRADES_TEXT, link=L("Mozilla HTTP Observatory scoring")), L("Limits."), L(LIMITS_TEXT)])
    story += [Spacer(1, 6 * mm), Paragraph(t(method), small)]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(font, 7.5)
        canvas.setFillColor(colors.HexColor(MUTED))
        prefix = f"{brand.company} · " if brand.company else ""
        canvas.drawString(15 * mm, 10 * mm, f"{prefix}{L('Security audit')} · {r.domain} · {date(r.date, lang)}")
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, L("Page {number}", number=doc.page))
        canvas.restoreState()

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                            bottomMargin=18 * mm, title=f"{L('Security audit')} — {r.domain}", author=author or "",
                            subject=L("Passive security audit"))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def _cover(r, brand: Branding, L, t, style, grade_cell, lang, bold, flowables, mm):  # noqa: N803 - L: translator
    """Cover page: logo, title, domain, client, date, overall grade, auditor and contact, confidentiality note."""
    Image, PageBreak, Paragraph, Spacer, Table = flowables  # noqa: N806 - ReportLab class names
    accent = brand.color
    page: list = [Spacer(1, 25 * mm)]
    if brand.logo is not None:
        logo = Image(str(brand.logo))
        ratio = min(60 * mm / logo.imageWidth, 30 * mm / logo.imageHeight)
        logo.drawWidth, logo.drawHeight = logo.imageWidth * ratio, logo.imageHeight * ratio
        logo.hAlign = "LEFT"
        page += [logo, Spacer(1, 18 * mm)]
    else:
        page.append(Spacer(1, 30 * mm))
    page += [Paragraph(t(L("Security audit")), style("cover_title", 30, accent, leading=36, font_name=bold)),
             Spacer(1, 4 * mm),
             Paragraph(t(r.domain), style("cover_domain", 18, leading=22))]
    if brand.client:
        page.append(Paragraph(t(L("Prepared for {client}", client=brand.client)), style("cover_client", 12)))
    page += [Paragraph(t(f"{L('Passive security audit')} · {date(r.date, lang)}"), style("cover_date", 10, MUTED)),
             Spacer(1, 16 * mm)]
    grade = Table([[grade_cell(r.grade, 40), Paragraph(t(L(GRADE_SUMMARY[letter(r.grade)])), style("cover_sum", 12))]],
                  colWidths=[35 * mm, 140 * mm])
    grade.setStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BACKGROUND", (0, 0), (0, 0), colors_hex(GRADE_COLORS[letter(r.grade)][1])),
                    ("TOPPADDING", (0, 0), (0, 0), 10), ("BOTTOMPADDING", (0, 0), (0, 0), 10),
                    ("LEFTPADDING", (1, 0), (1, 0), 12)])
    page += [Paragraph(t(L("Overall grade")), style("cover_label", 9, MUTED)), Spacer(1, 2 * mm), grade,
             Spacer(1, 40 * mm)]
    who = " · ".join(x for x in (brand.author, brand.company) if x)
    if who:
        page.append(Paragraph(t(L("Prepared by {who}", who=who)), style("cover_by", 11)))
    if brand.contact:
        page.append(Paragraph(t(brand.contact), style("cover_contact", 10, MUTED)))
    page += [Spacer(1, 10 * mm),
             Paragraph(t(L("Confidential: this report describes security weaknesses. Share it only with the people "
                           "in charge of fixing them.")), style("cover_conf", 8, MUTED)),
             PageBreak()]
    return page


def colors_hex(value: str):
    from reportlab.lib import colors

    return colors.HexColor(value)


def _grade_detail(L, key: str, grade) -> str:  # noqa: N803 - L is the translator
    if grade.note:
        return L(grade.note)
    return f"{grade.score}/100 · {L(CATEGORY_METHOD[key])}" if grade.score is not None else ""


def _capital(text: str) -> str:
    return text[:1].upper() + text[1:]


def _register_fonts(pdfmetrics, ttfont) -> tuple[str, str]:
    """Bitstream Vera, shipped with ReportLab: unlike the built-in fonts, it covers accents and typographic quotes."""
    import reportlab

    if "DSC-Vera" not in pdfmetrics.getRegisteredFontNames():
        folder = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
        pdfmetrics.registerFont(ttfont("DSC-Vera", os.path.join(folder, "Vera.ttf")))
        pdfmetrics.registerFont(ttfont("DSC-Vera-Bold", os.path.join(folder, "VeraBd.ttf")))
        pdfmetrics.registerFontFamily("DSC-Vera", normal="DSC-Vera", bold="DSC-Vera-Bold",
                                      italic="DSC-Vera", boldItalic="DSC-Vera-Bold")
    return "DSC-Vera", "DSC-Vera-Bold"
