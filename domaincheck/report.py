"""Outputs: standalone HTML report, console summary, JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from html import escape

from .models import Category, Result, Status

LABELS = {
    Status.CRITICAL: "Critical",
    Status.WARNING: "To improve",
    Status.OK: "Compliant",
    Status.INFO: "Info",
}
ORDER = {Status.CRITICAL: 0, Status.WARNING: 1, Status.INFO: 2, Status.OK: 3}
GRADE_COLOR = {"A": "ok", "B": "ok", "C": "warning", "D": "critical", "F": "critical"}
GRADE_SUMMARY = {
    "A": "Very good configuration. A few minor adjustments at most.",
    "B": "Solid foundation, with a few points to strengthen.",
    "C": "Partial protection: several important settings are missing.",
    "D": "Significant exposure: fixes are recommended soon.",
    "F": "High exposure: priority fixes are needed.",
}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d2330;--muted:#5d6677;--border:#e3e6eb;
--ok:#1f7a4d;--ok-bg:#e3f4ea;--warn:#9a5b00;--warn-bg:#fdf0d9;--crit:#b3261e;--crit-bg:#fbe4e2;
--info:#2f5d9e;--info-bg:#e5edf8;--accent:#1f4e78}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1c2027;--text:#e7e9ee;--muted:#a0a8b6;
--border:#2c323c;--ok:#6fd19b;--ok-bg:#16301f;--warn:#f2b552;--warn-bg:#33270f;--crit:#ff8a80;--crit-bg:#3a1a18;
--info:#8ab4f8;--info-bg:#18243a;--accent:#8ab4f8}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 48px}
header{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin-bottom:24px}
.grade{width:96px;height:96px;border-radius:20px;display:grid;place-items:center;font-size:52px;font-weight:700;flex:none}
.grade.ok{background:var(--ok-bg);color:var(--ok)}.grade.warning{background:var(--warn-bg);color:var(--warn)}
.grade.critical{background:var(--crit-bg);color:var(--crit)}
h1{margin:0;font-size:26px;word-break:break-all}
.sub{color:var(--muted);margin:2px 0 0}
.summary{margin:8px 0 0;font-weight:500}
.counters{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:0 0 28px}
.counter{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:12px;text-align:center}
.counter b{display:block;font-size:24px}.counter span{color:var(--muted);font-size:13px}
.c-critical b{color:var(--crit)}.c-warning b{color:var(--warn)}.c-ok b{color:var(--ok)}.c-info b{color:var(--info)}
h2{font-size:18px;margin:32px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--border)}
.item{background:var(--card);border:1px solid var(--border);border-left-width:4px;border-radius:10px;padding:14px 16px;margin-bottom:10px}
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
@media (max-width:560px){.counters{grid-template-columns:repeat(2,1fr)}.grade{width:76px;height:76px;font-size:40px}}
@media print{body{background:#fff}.item,.counter{break-inside:avoid}}
"""


def _sorted(findings):
    return sorted(findings, key=lambda f: ORDER[f.status])


def render_html(r: Result, author: str = "") -> str:
    e = escape
    counts = {s: sum(1 for f in r.findings if f.status == s) for s in Status}

    counters = "".join(
        f'<div class="counter c-{s.value}"><b>{counts[s]}</b><span>{LABELS[s]}</span></div>'
        for s in (Status.CRITICAL, Status.WARNING, Status.OK, Status.INFO)
    )

    priorities = [f for f in _sorted(r.findings) if f.status in (Status.CRITICAL, Status.WARNING) and f.recommendation]
    priority_block = ""
    if priorities:
        items = "".join(
            f'<li><b>{e(f.title)}</b> <span class="badge {f.status.value}">{LABELS[f.status]}</span><br>{e(f.recommendation)}</li>'
            for f in priorities
        )
        priority_block = f'<h2>Priority actions</h2><ol class="priority">{items}</ol>'

    sections = ""
    for cat in Category:
        group = [f for f in r.findings if f.category == cat]
        if not group:
            continue
        items = ""
        for f in _sorted(group):
            fix = f'<p class="fix">{e(f.recommendation)}</p>' if f.recommendation and f.status != Status.OK else ""
            items += (
                f'<div class="item {f.status.value}"><div class="row"><span class="title">{e(f.title)}</span>'
                f'<span class="badge {f.status.value}">{LABELS[f.status]}</span></div>'
                f'<p class="detail">{e(f.detail)}</p>{fix}</div>'
            )
        sections += f"<h2>{e(cat.value)}</h2>{items}"

    by = f" by {e(author)}" if author else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security audit — {e(r.domain)}</title><style>{CSS}</style></head>
<body><main>
<header><div class="grade {GRADE_COLOR[r.grade]}">{r.grade}</div>
<div><h1>{e(r.domain)}</h1><p class="sub">Passive security audit · {r.date:%Y-%m-%d} · score {r.score}/100</p>
<p class="summary">{GRADE_SUMMARY[r.grade]}</p></div></header>
<section class="counters">{counters}</section>
{priority_block}
{sections}
<footer>
<p><b>Method.</b> Passive audit carried out{by} using public information only: DNS records, the certificate
presented by the server and the home page headers. No intrusion testing was performed.</p>
<p><b>Limits.</b> This audit does not cover the site's applications, workstations or user accounts.
It gives an overview of the exposure visible from the Internet on the date shown.</p>
</footer>
</main></body></html>
"""


def console_summary(r: Result) -> str:
    symbols = {Status.CRITICAL: "✗", Status.WARNING: "!", Status.OK: "✓", Status.INFO: "i"}
    lines = [f"\n  {r.domain} — grade {r.grade} ({r.score}/100)", f"  {GRADE_SUMMARY[r.grade]}\n"]
    for cat in Category:
        group = [f for f in r.findings if f.category == cat]
        if group:
            lines.append(f"  {cat.value}")
            lines += [f"    [{symbols[f.status]}] {f.title} — {f.detail}" for f in _sorted(group)]
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
