"""Summary for decision makers: main risks in business terms, effort and impact of each fix.

The effort is an order of magnitude for a person who has access to the
settings (web host, DNS zone, email administration): a setting or a DNS record
is quick; what needs testing takes a few hours; what touches the site's code
or depends on a provider is a project. The impact follows the weight of the
problem in the grades.

No network access here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .i18n import M
from .models import Finding, Result, Status
from .scoring import category_grades, overall_grade

QUICK, HOURS, PROJECT = "quick", "hours", "project"
EFFORT_LABELS = {
    QUICK: "Quick fix (under 30 min)",
    HOURS: "A few hours",
    PROJECT: "Project (developer or provider)",
}
HIGH, MEDIUM, LOW = "high", "medium", "low"
IMPACT_LABELS = {HIGH: "High impact", MEDIUM: "Medium impact", LOW: "Low impact"}

# Effort to apply the recommendation, by finding source
EFFORT = {
    "redirection": QUICK, "hsts": QUICK, "hsts-preload": QUICK, "xcto": QUICK, "xfo": QUICK, "referrer": QUICK,
    "permissions": QUICK, "owasp-headers": QUICK, "security-txt": QUICK, "caa": QUICK, "transfer-lock": QUICK,
    "rdap": QUICK, "ct": QUICK, "tls-guide": QUICK, "rfc8996": QUICK, "tls13": QUICK, "tls-rpt": QUICK,
    "null-mx": QUICK, "spf": HOURS, "dmarc": HOURS, "dkim": HOURS, "mta-sts": HOURS, "dnssec": HOURS,
    "rfc9325": HOURS, "starttls": HOURS, "dane": HOURS, "csp": PROJECT, "cookies": PROJECT, "sri": PROJECT,
    "eol": HOURS, "trackers": HOURS, "corp": HOURS, "coop": HOURS, "coep": PROJECT,
}

# What the problem means for the business, by finding source
RISKS = {
    "redirection": "Visitors' data (forms, logins) can be intercepted, for instance on public Wi-Fi.",
    "hsts": "Visitors' data (forms, logins) can be intercepted, for instance on public Wi-Fi.",
    "tls-guide": "Visitors get a security warning, or their data can be intercepted.",
    "rfc8996": "Old encryption weakens the protection of visitors' data.",
    "tls13": "Old encryption weakens the protection of visitors' data.",
    "rfc9325": "Old encryption weakens the protection of visitors' data.",
    "csp": "A flaw in the site or in a third-party script can be used to steal visitors' data (XSS).",
    "sri": "A flaw in the site or in a third-party script can be used to steal visitors' data (XSS).",
    "xfo": "The site can be shown inside a fake site to trick visitors into clicking (clickjacking).",
    "cookies": "Session cookies can be stolen, giving access to users' accounts.",
    "owasp-headers": "Visible software versions make known flaws easier to target.",
    "spf": "Anyone can send emails in the company's name: phishing of clients, fake invoices.",
    "dmarc": "Anyone can send emails in the company's name: phishing of clients, fake invoices.",
    "dkim": "Anyone can send emails in the company's name: phishing of clients, fake invoices.",
    "mta-sts": "Emails sent to the company can be read or altered on the way.",
    "starttls": "Emails sent to the company can be read or altered on the way.",
    "dnssec": "Visitors and emails can be sent to a fake server through forged DNS answers.",
    "caa": "Any certificate authority can issue a certificate for the domain.",
    "rdap": "The domain can expire: website and email down, and the name can be taken by someone else.",
    "transfer-lock": "With a stolen registrar password, the domain can be moved elsewhere.",
    "ct": "A forgotten subdomain can be taken over to publish content in the company's name.",
    "trackers": "Trackers placed without consent expose the company to sanctions from the CNIL.",
    "eol": "Outdated software on the site has known flaws that attackers exploit automatically.",
}


@dataclass
class Action:
    finding: Finding
    effort: str
    impact: str


def effort_of(f: Finding) -> str:
    return EFFORT.get(f.source, HOURS)


def impact_of(f: Finding) -> str:
    points = f.points or 0
    if f.status == Status.CRITICAL or points <= -20:
        return HIGH
    if points <= -10:
        return MEDIUM
    return LOW


def actions(r: Result) -> list[Action]:
    """Priority actions (critical and warning items with a recommendation), most important first."""
    from .report import _sorted  # same order as the report

    found = [f for f in _sorted(r.findings) if f.status in (Status.CRITICAL, Status.WARNING) and f.recommendation]
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    effort_order = {QUICK: 0, HOURS: 1, PROJECT: 2}
    listed = [Action(f, effort_of(f), impact_of(f)) for f in found]
    return sorted(listed, key=lambda a: (order[a.impact], effort_order[a.effort]))


def main_risks(r: Result, limit: int = 3) -> list[tuple[str, str]]:
    """[(risk sentence, impact)]: distinct business risks behind the priority actions, most serious first.

    Problems that lead to the same risk add up (no SPF and no DMARC: one risk, twice as heavy).
    """
    weight: dict[str, list] = {}  # sentence -> [critical?, total points, best impact]
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    for a in actions(r):
        sentence = RISKS.get(a.finding.source)
        if not sentence:
            continue
        w = weight.setdefault(sentence, [False, 0, LOW])
        w[0] = w[0] or a.finding.status == Status.CRITICAL
        w[1] += a.finding.points or 0
        w[2] = min(w[2], a.impact, key=order.__getitem__)
    ranked = sorted(weight.items(), key=lambda item: (not item[1][0], item[1][1]))
    return [(sentence, w[2]) for sentence, w in ranked[:limit]]


def grade_after_quick_fixes(r: Result) -> str:
    """Overall grade once every quick fix is applied (the other problems unchanged)."""
    quick = {id(a.finding) for a in actions(r) if a.effort == QUICK}
    if not quick:
        return r.grade
    fixed = [replace(f, points=0, status=Status.OK) if id(f) in quick and (f.points or 0) < 0 else f
             for f in r.findings]
    website = r.grades.get("WEB")
    grades = category_grades(fixed, website is not None and website.grade != "N/A", r.cap_reason)
    return overall_grade(grades)


def effort_line(r: Result) -> str:
    """"3 quick fixes, 2 of a few hours, 1 project", or "" when there is nothing to fix."""
    counts = {QUICK: 0, HOURS: 0, PROJECT: 0}
    for a in actions(r):
        counts[a.effort] += 1
    if not any(counts.values()):
        return ""
    return M("{quick} quick fix(es) (under 30 min each), {hours} of a few hours, {projects} project(s) needing a "
             "developer or a provider.", quick=counts[QUICK], hours=counts[HOURS], projects=counts[PROJECT])
