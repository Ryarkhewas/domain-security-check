"""Email protection checks: MX, SPF, DMARC, DKIM.

What is valid comes from the standards (RFC 7208 SPF, RFC 7489 DMARC,
RFC 6376 DKIM, RFC 7505 null MX). The points are this project's own:
there is no public scoring standard for email security.

These functions make no network calls: they receive DNS records that were
already fetched, which makes them easy to test.
"""

from __future__ import annotations

import re

from .models import Category, Finding, Status

C = Category.EMAIL

# SPF mechanisms that cost one DNS lookup (RFC 7208 limit: 10)
_DNS_MECHANISMS = re.compile(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)", re.I)


def _f(title, status, detail, recommendation="", points=0, source="") -> Finding:
    return Finding(C, title, status, detail, recommendation, points, source)


def check_mx(mx: list[str]) -> list[Finding]:
    title = "Mail servers (MX)"
    if not mx:
        return [_f(title, Status.INFO, "No MX server: this domain does not receive email.",
                   "If the domain does not send email either, publish \"v=spf1 -all\", a DMARC policy \"p=reject\" "
                   "and a null MX record, so nobody can use it to impersonate you.", 0, "null-mx")]
    return [_f(title, Status.OK, f"{len(mx)} server(s): {', '.join(mx[:3])}", source="null-mx")]


def check_spf(root_txt: list[str], dmarc_enforced: bool = False) -> list[Finding]:
    """Analyse SPF.

    `dmarc_enforced` is True when a DMARC policy of quarantine or reject
    applies: spoofed mail is then already stopped, so a missing SPF record
    is a weakness to fix rather than a critical exposure.
    """
    title = "SPF (authorized senders)"
    spf = [t for t in root_txt if t.lower().startswith("v=spf1")]

    if not spf:
        if dmarc_enforced:
            return [_f(title, Status.WARNING,
                       "No SPF record. Spoofed emails are still stopped by the domain's strict DMARC policy, "
                       "but legitimate mail is more likely to be treated as spam.",
                       "Publish an SPF record listing your sending services, or \"v=spf1 -all\" if this domain sends no email.",
                       -10, "spf")]
        return [_f(title, Status.CRITICAL,
                   "No SPF record: anyone can send email pretending to be this domain.",
                   "Publish an SPF TXT record listing your sending services (e.g. \"v=spf1 include:_spf.google.com -all\").",
                   -30, "spf")]
    if len(spf) > 1:
        return [_f(title, Status.CRITICAL,
                   f"{len(spf)} SPF records found: this is invalid, receiving servers ignore all of them.",
                   "Merge them into a single SPF record.", -30, "spf")]

    record = spf[0]
    terms = record.split()[1:]
    findings: list[Finding] = []

    all_term = next((t for t in terms if t.lower().lstrip("+-~?") == "all"), None)
    if all_term is None and not any(t.lower().startswith("redirect=") for t in terms):
        findings.append(_f(title, Status.WARNING, f"The SPF record does not end with an \"all\" rule: \"{record}\".",
                           "End the record with \"-all\" (or \"~all\" during a test phase).", -15, "spf"))
    elif all_term in ("all", "+all"):
        findings.append(_f(title, Status.CRITICAL,
                           "The SPF record ends with \"+all\": it allows the whole world to send on your behalf.",
                           "Replace \"+all\" with \"-all\".", -40, "spf"))
    elif all_term == "?all":
        findings.append(_f(title, Status.WARNING,
                           "The SPF record ends with \"?all\" (neutral): it provides almost no protection.",
                           "Move to \"~all\", then \"-all\" once your senders are listed.", -20, "spf"))
    elif all_term == "~all":
        findings.append(_f(title, Status.OK, "SPF present with \"~all\" (soft fail). Fine, especially combined with DMARC.",
                           "Once you are sure of your list of senders, switch to \"-all\".", 0, "spf"))
    else:
        findings.append(_f(title, Status.OK, "SPF present and strict (\"-all\").", source="spf"))

    lookups = sum(1 for t in terms if _DNS_MECHANISMS.match(t))
    if lookups > 10:
        findings.append(_f("SPF: number of DNS lookups", Status.WARNING,
                           f"{lookups} mechanisms require a DNS lookup (limit: 10). The SPF record may be rejected.",
                           "Reduce the number of \"include\" entries or use an SPF flattening service.", -15, "spf"))
    return findings


def dmarc_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()
    return tags


def is_dmarc(record: str) -> bool:
    return record.lower().replace(" ", "").startswith("v=dmarc1")


def effective_dmarc_policy(dmarc_txt: list[str], inherited_from: str = "") -> str:
    """The policy that applies ("none", "quarantine", "reject"), or "" if none/invalid."""
    records = [t for t in dmarc_txt if is_dmarc(t)]
    if len(records) != 1:
        return ""
    t = dmarc_tags(records[0])
    policy = t.get("sp" if inherited_from and "sp" in t else "p", "").lower()
    return policy if policy in ("none", "quarantine", "reject") else ""


def check_dmarc(dmarc_txt: list[str], inherited_from: str = "") -> list[Finding]:
    """Analyse a DMARC record.

    `inherited_from` is set when the record belongs to a parent domain: per the
    DMARC standard, a subdomain without its own record is covered by its parent's
    policy, using the subdomain policy tag (sp=) when present, otherwise p=.
    """
    title = "DMARC (anti-spoofing policy)"
    dmarc = [t for t in dmarc_txt if is_dmarc(t)]

    if not dmarc:
        return [_f(title, Status.CRITICAL,
                   "No DMARC policy: fraudulent messages using your domain are neither blocked nor reported.",
                   "Publish a TXT record on _dmarc.<domain>, starting with "
                   "\"v=DMARC1; p=none; rua=mailto:dmarc@<domain>\" to monitor, then tighten it.", -40, "dmarc")]
    if len(dmarc) > 1:
        return [_f(title, Status.CRITICAL, "Several DMARC records: this is invalid, they are ignored.",
                   "Keep a single DMARC record.", -40, "dmarc")]

    t = dmarc_tags(dmarc[0])
    tag = "sp" if inherited_from and "sp" in t else "p"
    policy = t.get(tag, "").lower()
    origin = f"Inherited from {inherited_from}: " if inherited_from else ""
    findings: list[Finding] = []

    if policy == "reject":
        findings.append(_f(title, Status.OK, f"{origin}\"reject\" policy: spoofed emails are rejected.", source="dmarc"))
    elif policy == "quarantine":
        findings.append(_f(title, Status.OK, f"{origin}\"quarantine\" policy: spoofed emails go to spam.",
                           "Move to \"reject\" once the reports confirm your legitimate email passes.", 0, "dmarc"))
    elif policy == "none":
        findings.append(_f(title, Status.WARNING, f"{origin}\"none\" policy: DMARC monitors but blocks nothing.",
                           "After a few weeks of report analysis, move to \"quarantine\", then \"reject\".", -20, "dmarc"))
    else:
        findings.append(_f(title, Status.CRITICAL, f"{origin}Missing or invalid DMARC policy ({tag}={policy or '?'}).",
                           f"Fix the record: the {tag}= tag must be none, quarantine or reject.", -40, "dmarc"))

    pct = t.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        findings.append(_f("DMARC: coverage", Status.WARNING, f"The policy only applies to {pct}% of messages.",
                           "Gradually raise it to pct=100.", -10, "dmarc"))
    if "rua" not in t:
        findings.append(_f("DMARC: reports", Status.INFO,
                           "No report address (rua): you cannot see who sends email on your behalf.",
                           "Add \"rua=mailto:...\" to receive aggregate reports.", 0, "dmarc"))
    return findings


def check_dkim(found_selectors: list[str], tested_selectors: list[str]) -> list[Finding]:
    title = "DKIM (email signing)"
    if found_selectors:
        return [_f(title, Status.OK, f"DKIM key(s) found: {', '.join(found_selectors)}.", source="dkim")]
    return [_f(title, Status.INFO,
               f"No DKIM key found among the common selectors tested ({len(tested_selectors)}). "
               "This is not necessarily a problem: the selector may have another name.",
               "Check in your email service (Google Workspace, Microsoft 365...) that DKIM signing is enabled.",
               None, "dkim")]
