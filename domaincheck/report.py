"""Outputs: standalone HTML report, console summary, JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from html import escape

from .i18n import M, date, tr
from .models import Category, Result, Status
from .scoring import GRADE_ORDER
from .sources import SOURCES, references

LABELS = {
    Status.CRITICAL: "Critical",
    Status.WARNING: "To improve",
    Status.OK: "Compliant",
    Status.INFO: "Info",
}
ORDER = {Status.CRITICAL: 0, Status.WARNING: 1, Status.INFO: 2, Status.OK: 3}
GRADE_COLOR = {"A": "ok", "B": "ok", "C": "warning", "D": "critical", "F": "critical", "N": "na"}
CATEGORY_LABELS = {"WEB": "Website", "TLS": "Certificate & TLS", "EMAIL": "Email", "DNS": "Domain & DNS"}
CATEGORY_METHOD = {
    "WEB": "Mozilla HTTP Observatory scoring",
    "TLS": "this project's scale (RFC 8996, certificate validity)",
    "EMAIL": "this project's scale (RFC 7208, 7489, 6376, 8461)",
    "DNS": "this project's scale (RFC 4033, 8659)",
}
def letter(grade: str) -> str:
    """"A+" -> "A", "N/A" -> "N"."""
    return grade[:1]


GRADE_SUMMARY = {
    "A": "Very good configuration. A few minor adjustments at most.",
    "B": "Solid foundation, with a few points to strengthen.",
    "C": "Partial protection: several important settings are missing.",
    "D": "Significant exposure: fixes are recommended soon.",
    "F": "High exposure: priority fixes are needed.",
    "N": "No grade could be computed.",
}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6677;--border:#e3e6eb;
--ok:#1f7a4d;--ok-bg:#e3f4ea;--warn:#9a5b00;--warn-bg:#fdf0d9;--crit:#b3261e;--crit-bg:#fbe4e2;
--info:#2f5d9e;--info-bg:#e5edf8;--accent:#1f4e78}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1c2027;--text:#e7e9ee;--muted:#a0a8b6;
--border:#2c323c;--ok:#6fd19b;--ok-bg:#16301f;--warn:#f2b552;--warn-bg:#33270f;--crit:#ff8a80;--crit-bg:#3a1a18;
--info:#8ab4f8;--info-bg:#18243a;--accent:#8ab4f8}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 48px}
header{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin-bottom:24px}
.grade{width:96px;height:96px;border-radius:20px;display:grid;place-items:center;font-size:52px;font-weight:700;flex:none}
.grade.ok{background:var(--ok-bg);color:var(--ok)}.grade.warning{background:var(--warn-bg);color:var(--warn)}
.grade.critical{background:var(--crit-bg);color:var(--crit)}
.grade.na{background:var(--card);color:var(--muted);border:1px solid var(--border)}
.cats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:0 0 12px}
.cat{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px;
display:flex;gap:12px;align-items:center}
.cat .grade{width:52px;height:52px;border-radius:12px;font-size:24px}
.cat b{display:block}.cat span{color:var(--muted);font-size:12px;line-height:1.35;display:block}
.pts{font-size:12px;font-weight:600;color:var(--muted);margin-left:6px;white-space:nowrap}
.src{margin:6px 0 0;font-size:12px;color:var(--muted)}.src a{color:var(--muted)}
h1{margin:0;font-size:26px;word-break:break-all}
.sub{color:var(--muted);margin:2px 0 0}
.summary{margin:8px 0 0;font-weight:500}
.cap{margin:6px 0 0;color:var(--crit);font-weight:600}
.counters{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:0 0 28px}
.counter{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px;text-align:center}
.counter b{display:block;font-size:24px}.counter span{color:var(--muted);font-size:13px}
.c-critical b{color:var(--crit)}.c-warning b{color:var(--warn)}.c-ok b{color:var(--ok)}.c-info b{color:var(--info)}
h2{font-size:18px;margin:32px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--border)}
.item{background:var(--card);border:1px solid var(--border);border-left-width:4px;border-radius:10px;
padding:14px 16px;margin-bottom:10px}
.item.critical{border-left-color:var(--crit)}.item.warning{border-left-color:var(--warn)}
.item.ok{border-left-color:var(--ok)}.item.info{border-left-color:var(--info)}
.row{display:flex;justify-content:space-between;gap:12px;align-items:baseline;flex-wrap:wrap}
.title{font-weight:600}
.badge{font-size:12px;font-weight:600;padding:2px 10px;border-radius:99px;white-space:nowrap}
.badge.critical{background:var(--crit-bg);color:var(--crit)}.badge.warning{background:var(--warn-bg);color:var(--warn)}
.badge.ok{background:var(--ok-bg);color:var(--ok)}.badge.info{background:var(--info-bg);color:var(--info)}
.detail{margin:6px 0 0;color:var(--muted)}
.fix{margin:8px 0 0;padding:8px 12px;background:var(--bg);border-radius:8px;font-size:14px}
.fix::before{content:"→ ";font-weight:700;color:var(--accent)}
ol.priority{padding-left:22px}ol.priority li{margin-bottom:8px}
footer{margin-top:40px;color:var(--muted);font-size:13px;border-top:1px solid var(--border);padding-top:16px}
table.list{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--border);border-radius:12px;
overflow:hidden;font-size:14px}
table.list th,table.list td{padding:10px 12px;border-bottom:1px solid var(--border);text-align:left}
table.list th{color:var(--muted);font-weight:600;font-size:13px}
table.list td.g{font-weight:700;text-align:center}
.g.ok{color:var(--ok)}.g.warning{color:var(--warn)}.g.critical{color:var(--crit)}.g.na{color:var(--muted)}
.changes{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:6px 16px 10px;
margin:0 0 8px}
.changes h3{font-size:14px;margin:10px 0 4px}.changes ul{margin:0;padding-left:20px}
.changes li{margin:2px 0}.up{color:var(--ok);font-weight:600}.down{color:var(--crit);font-weight:600}
.scroll{overflow-x:auto}table.list a{color:var(--accent);font-weight:600}
@media (max-width:860px){.cats{grid-template-columns:repeat(2,1fr)}}
@media (max-width:520px){.cats{grid-template-columns:1fr}}
@media (max-width:560px){.counters{grid-template-columns:repeat(2,1fr)}.grade{width:76px;height:76px;font-size:40px}}
@media print{body{background:#fff}.item,.counter,.cat{break-inside:avoid}}
"""


def _sorted(findings):
    """Most serious first: by status, then by points lost (unscored items last within a status)."""
    return sorted(findings, key=lambda f: (ORDER[f.status], f.points if f.points is not None else 0))


def reference_groups(t, refs: list[tuple[str, str, str]]) -> list[tuple[str, list[tuple[str, str]]]]:
    """[(heading, [(link text, url)])]: "Source:" for the standard, "See also:" for the ANSSI guides.

    The guides come under "See also" so that a "Compliant" item does not read as "complies with ANSSI":
    the check relates to the recommendation, it cannot prove the recommendation is met.
    """
    standard = [(t(label), url) for label, url, rec in refs if not rec]
    guides = [(f"{t(label)}, {rec}", url) for label, url, rec in refs if rec]
    groups = []
    if standard:
        groups.append((t("Source:"), standard))
    if guides:
        groups.append((t("See also:"), guides))
    return groups


def capital(text: str) -> str:
    """First letter in upper case (a translated sentence can start with an empty placeholder)."""
    return text[:1].upper() + text[1:]


def _translator(lang: str):
    def t(text, **params) -> str:
        return tr(M(text, **params) if params else text, lang)
    return t


def _linked(t, template: str, link: str, **params) -> str:
    """Escaped translated sentence with an HTML link in place of {link}."""
    marker = "\x00"
    return escape(t(template, link=marker, **params)).replace(marker, link)


def render_html(r: Result, author: str = "", lang: str = "en") -> str:
    e = escape
    t = _translator(lang)
    counts = {s: sum(1 for f in r.findings if f.status == s) for s in Status}

    counters = "".join(
        f'<div class="counter c-{s.value}"><b>{counts[s]}</b><span>{e(t(LABELS[s]))}</span></div>'
        for s in (Status.CRITICAL, Status.WARNING, Status.OK, Status.INFO)
    )

    priorities = [f for f in _sorted(r.findings) if f.status in (Status.CRITICAL, Status.WARNING) and f.recommendation]
    priority_block = ""
    if priorities:
        items = "".join(
            f'<li><b>{e(t(f.title))}</b> <span class="badge {f.status.value}">{e(t(LABELS[f.status]))}</span>'
            f'<br>{e(t(f.recommendation))}</li>'
            for f in priorities
        )
        priority_block = f'<h2>{e(t("Priority actions"))}</h2><ol class="priority">{items}</ol>'

    sections = ""
    for cat in Category:
        group = [f for f in r.findings if f.category == cat]
        if not group:
            continue
        items = ""
        for f in _sorted(group):
            fix = (f'<p class="fix">{e(t(f.recommendation))}</p>'
                   if f.recommendation and f.status != Status.OK else "")
            pts = f'<span class="pts">{e(_points(f.points, lang))}</span>'
            src = ""
            refs = references(f.source)
            if refs:
                parts = []
                for heading, links_group in reference_groups(t, refs):
                    links = " · ".join(f'<a href="{e(url)}">{e(text)}</a>' for text, url in links_group)
                    parts.append(f"{e(heading)} {links}")
                src = f'<p class="src">{" — ".join(parts)}</p>'
            items += (
                f'<div class="item {f.status.value}"><div class="row"><span class="title">{e(t(f.title))}</span>'
                f'<span><span class="badge {f.status.value}">{e(t(LABELS[f.status]))}</span>{pts}</span></div>'
                f'<p class="detail">{e(capital(t(f.detail)))}</p>{fix}{src}</div>'
            )
        sections += f"<h2>{e(t(cat.value))}</h2>{items}"

    cats = ""
    for key, g in r.grades.items():
        detail = t(g.note) if g.note else (f"{g.score}/100 · {t(CATEGORY_METHOD[key])}" if g.score is not None else "")
        cats += (f'<div class="cat"><div class="grade {GRADE_COLOR[letter(g.grade)]}">{e(g.grade)}</div>'
                 f'<div><b>{e(t(CATEGORY_LABELS[key]))}</b><span>{e(detail)}</span></div></div>')

    by = t(" by {author}", author=author) if author else ""
    cap = ""
    if r.cap_reason:
        reason = t(r.cap_reason)
        cap = (f'<p class="cap">{e(t("{reason}: website grade capped at F.", reason=reason[:1].upper() + reason[1:]))}'
               "</p>")
    obs_label, obs_url = SOURCES["observatory"]
    obs_link = f'<a href="{e(obs_url)}">{e(t(obs_label))}</a>'
    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(t("Security audit"))} — {e(r.domain)}</title><style>{CSS}</style></head>
<body><main>
<header><div class="grade {GRADE_COLOR[letter(r.grade)]}">{e(r.grade)}</div>
<div><h1>{e(r.domain)}</h1><p class="sub">{e(t("Passive security audit"))} · {date(r.date, lang)} · \
{e(t("overall grade = weakest area"))}</p>
<p class="summary">{e(t(GRADE_SUMMARY[letter(r.grade)]))}</p>{cap}</div></header>
<section class="cats">{cats}</section>
<section class="counters">{counters}</section>
{_changes_html(r.changes, t, lang)}
{priority_block}
{sections}
<footer>
<p><b>{e(t("Method."))}</b> {e(t(METHOD_TEXT, by=by))}</p>
<p><b>{e(t("Grades."))}</b> {_linked(t, GRADES_TEXT, obs_link)}</p>
<p><b>{e(t("Limits."))}</b> {e(t(LIMITS_TEXT))}</p>
</footer>
</main></body></html>
"""


def _area(t, key: str) -> str:
    return t("Overall") if key == "OVERALL" else t(CATEGORY_LABELS[key])


def change_lines(changes, t) -> list[tuple[str, list[str]]]:
    """[(heading, [lines])] describing the changes, translated; shared by the HTML, console and PDF outputs."""
    groups: list[tuple[str, list[str]]] = []
    if changes.grades:
        groups.append((t("Grades"), [t("{area}: {old} → {new}", area=_area(t, g.key), old=g.old, new=g.new)
                                     for g in changes.grades]))
    for heading, items, with_status in ((t("Fixed ({count})", count=len(changes.fixed)), changes.fixed, False),
                                        (t("New problems ({count})", count=len(changes.new)), changes.new, True),
                                        (t("Worse ({count})", count=len(changes.worse)), changes.worse, True),
                                        (t("Better ({count})", count=len(changes.better)), changes.better, True)):
        if items:
            lines = []
            for c in items:
                line = t(c.title)
                if with_status:
                    old = t(LABELS[Status(c.old)]) if c.old else t("new check")
                    line += f" ({old} → {t(LABELS[Status(c.new)])})"
                lines.append(line)
            groups.append((heading, lines))
    return groups


def changes_heading(changes, t, lang: str) -> str:
    when = date(changes.previous_date, lang)
    if changes.nothing:
        return t("No change since the audit of {date}.", date=when)
    return t("Changes since the audit of {date}", date=when)


def _changes_html(changes, t, lang: str) -> str:
    if changes is None:
        return ""
    body = ""
    for heading, lines in change_lines(changes, t):
        body += f"<h3>{escape(heading)}</h3><ul>" + "".join(f"<li>{escape(line)}</li>" for line in lines) + "</ul>"
    return f'<section class="changes"><h3>{escape(changes_heading(changes, t, lang))}</h3>{body}</section>'


METHOD_TEXT = ("Passive audit carried out{by} using public information only: DNS records, the certificate presented "
               "by the server and the home page. No intrusion testing was performed.")
GRADES_TEXT = ("The website grade follows the {link} (penalties and bonuses per header). The certificate, email and "
               "DNS grades use this project's own scale, based on the standards cited under each item. The overall "
               "grade is the lowest of the four.")
LIMITS_TEXT = ("This audit does not cover the site's applications, workstations or user accounts. It gives an "
               "overview of the exposure visible from the Internet on the date shown. The ANSSI recommendations cited "
               "show what each check relates to; meeting them fully also depends on settings that cannot be seen "
               "from outside, so this report is not a certificate of compliance.")


def render_index(results: list[Result], errors: dict[str, str], author: str = "", lang: str = "en") -> str:
    """Summary page for an audit of several domains, linking to each report (<domain>.html)."""
    e = escape
    t = _translator(lang)
    keys = list(CATEGORY_LABELS)
    head = "".join(f"<th>{e(t(CATEGORY_LABELS[k]))}</th>" for k in keys)
    rows = ""
    for r in sorted(results, key=lambda r: (GRADE_ORDER.index(r.grade) if r.grade in GRADE_ORDER else -1),
                    reverse=True):
        grades = "".join(
            f'<td class="g {GRADE_COLOR[letter(r.grades[k].grade)]}">{e(r.grades[k].grade)}</td>' if k in r.grades
            else "<td></td>" for k in keys)
        critical = sum(1 for f in r.findings if f.status == Status.CRITICAL)
        warning = sum(1 for f in r.findings if f.status == Status.WARNING)
        rows += (f'<tr><td><a href="{e(r.domain)}.html">{e(r.domain)}</a></td>'
                 f'<td class="g {GRADE_COLOR[letter(r.grade)]}">{e(r.grade)}</td>{grades}'
                 f'<td>{critical}</td><td>{warning}</td><td>{_since_last(r.changes, t)}</td></tr>')
    for domain, message in errors.items():
        rows += (f'<tr><td>{e(domain)}</td><td class="g na">–</td>'
                 f'<td colspan="{len(keys) + 3}">{e(t("Not audited: {reason}", reason=message))}</td></tr>')
    by = t(" by {author}", author=author) if author else ""
    when = f" · {date(results[0].date, lang)}" if results else ""
    count = len(results) + len(errors)
    title = t("Security audit of 1 domain") if count == 1 else t("Security audit of {count} domains", count=count)
    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{CSS}</style></head>
<body><main>
<header><div><h1>{e(title)}</h1>
<p class="sub">{e(t("Passive security audit"))}{when} · \
{e(t("weakest domains first · click a domain for its full report"))}</p>
</div></header>
<div class="scroll"><table class="list"><thead><tr><th>{e(t("Domain"))}</th><th>{e(t("Overall"))}</th>{head}
<th>{e(t(LABELS[Status.CRITICAL]))}</th><th>{e(t(LABELS[Status.WARNING]))}</th><th>{e(t("Since last audit"))}</th>
</tr></thead><tbody>{rows}</tbody></table></div>
<footer><p><b>{e(t("Method."))}</b> {e(t(INDEX_METHOD_TEXT, by=by))}</p></footer>
</main></body></html>
"""


def _since_last(changes, t) -> str:
    """Short summary for the index page."""
    if changes is None:
        return escape(t("first audit"))
    if changes.nothing:
        return escape(t("no change"))
    parts = []
    overall = next((g for g in changes.grades if g.key == "OVERALL"), None)
    if overall:
        css = "up" if overall.better else "down"
        parts.append(f'<span class="{css}">{escape(overall.old)} → {escape(overall.new)}</span>')
    if changes.fixed:
        parts.append(escape(t("{count} fixed", count=len(changes.fixed))))
    if changes.new or changes.worse:
        parts.append(escape(t("{count} new or worse", count=len(changes.new) + len(changes.worse))))
    if changes.better:
        parts.append(escape(t("{count} better", count=len(changes.better))))
    return " · ".join(parts) or escape(t("grades changed"))


INDEX_METHOD_TEXT = ("Passive audit carried out{by} using public information only. Each report explains its grades, "
                     "the points behind them and the standard each check relies on.")


def _points(points: int | None, lang: str = "en") -> str:
    if points is None:
        return tr("not scored", lang)
    sign = "+" if points > 0 else ""
    return tr(M("{points} pts", points=f"{sign}{points}"), lang)


def console_summary(r: Result, lang: str = "en") -> str:
    t = _translator(lang)
    symbols = {Status.CRITICAL: "✗", Status.WARNING: "!", Status.OK: "✓", Status.INFO: "i"}
    lines = [f"\n  {r.domain} — {t('overall grade {grade}', grade=r.grade)}", f"  {t(GRADE_SUMMARY[letter(r.grade)])}"]
    for key, g in r.grades.items():
        score = f" ({g.score}/100)" if g.score is not None else ""
        note = f" — {t(g.note)}" if g.note else ""
        lines.append(f"    {t(CATEGORY_LABELS[key]):<20} {g.grade}{score}{note}")
    lines.append("")
    if r.changes is not None:
        lines.append(f"  {changes_heading(r.changes, t, lang)}")
        for heading, items in change_lines(r.changes, t):
            lines.append(f"    {heading}")
            lines += [f"      - {item}" for item in items]
        lines.append("")
    for cat in Category:
        group = [f for f in r.findings if f.category == cat]
        if group:
            lines.append(f"  {t(cat.value)}")
            lines += [f"    [{symbols[f.status]}] {t(f.title)} ({_points(f.points, lang)}) — {capital(t(f.detail))}"
                      for f in _sorted(group)]
            lines.append("")
    return "\n".join(lines)


def _jsonable(o):
    if isinstance(o, Enum):
        return o.value
    if hasattr(o, "isoformat"):
        return o.isoformat()
    raise TypeError(type(o))


def render_json(r: Result) -> str:
    return json.dumps(asdict(r), default=_jsonable, ensure_ascii=False, indent=2)
