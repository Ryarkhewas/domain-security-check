"""Email protection analysis: MX, SPF, DMARC, DKIM.

These functions make no network calls: they receive DNS records that were
already fetched, which makes them easy to test.
"""

from __future__ import annotations

import re

from .models import Category, Finding, Status

C = Category.EMAIL

# SPF mechanisms that cost one DNS lookup (RFC 7208 limit: 10)
_DNS_MECHANISMS = re.compile(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)", re.I)


def check_mx(mx: list[str]) -> list[Finding]:
    if not mx:
        return [Finding(
            C, "Mail servers (MX)", Status.INFO,
            "No MX server: this domain does not receive email.",
            "If the domain does not send email either, publish \"v=spf1 -all\" and a DMARC policy "
            "\"p=reject\" so nobody can use it to impersonate you.",
        )]
    return [Finding(C, "Mail servers (MX)", Status.OK, f"{len(mx)} server(s): {', '.join(mx[:3])}")]


def check_spf(root_txt: list[str]) -> list[Finding]:
    title = "SPF (authorized senders)"
    spf = [t for t in root_txt if t.lower().startswith("v=spf1")]

    if not spf:
        return [Finding(
            C, title, Status.CRITICAL,
            "No SPF record: anyone can send email pretending to be this domain.",
            "Publish an SPF TXT record listing your sending services (e.g. \"v=spf1 include:_spf.google.com -all\").",
        )]
    if len(spf) > 1:
        return [Finding(
            C, title, Status.CRITICAL,
            f"{len(spf)} SPF records found: this is invalid, receiving servers ignore all of them.",
            "Merge them into a single SPF record.",
        )]

    record = spf[0]
    terms = record.split()[1:]
    findings: list[Finding] = []

    all_term = next((t for t in terms if t.lower().lstrip("+-~?") == "all"), None)
    if all_term is None and not any(t.lower().startswith("redirect=") for t in terms):
        findings.append(Finding(
            C, title, Status.WARNING,
            f"The SPF record does not end with an \"all\" rule: \"{record}\".",
            "End the record with \"-all\" (or \"~all\" during a test phase).",
        ))
    elif all_term in ("all", "+all"):
        findings.append(Finding(
            C, title, Status.CRITICAL,
            "The SPF record ends with \"+all\": it allows the whole world to send on your behalf.",
            "Replace \"+all\" with \"-all\".",
        ))
    elif all_term == "?all":
        findings.append(Finding(
            C, title, Status.WARNING,
            "The SPF record ends with \"?all\" (neutral): it provides almost no protection.",
            "Move to \"~all\", then \"-all\" once your senders are listed.",
        ))
    elif all_term == "~all":
        findings.append(Finding(
            C, title, Status.OK,
            "SPF present with \"~all\" (soft fail). Fine, especially combined with DMARC.",
            "Once you are sure of your list of senders, switch to \"-all\".",
        ))
    else:
        findings.append(Finding(C, title, Status.OK, "SPF present and strict (\"-all\")."))

    lookups = sum(1 for t in terms if _DNS_MECHANISMS.match(t))
    if lookups > 10:
        findings.append(Finding(
            C, "SPF: number of DNS lookups", Status.WARNING,
            f"{lookups} mechanisms require a DNS lookup (limit: 10). The SPF record may be rejected.",
            "Reduce the number of \"include\" entries or use an SPF flattening service.",
        ))
    return findings


def _dmarc_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()
    return tags


def check_dmarc(dmarc_txt: list[str]) -> list[Finding]:
    title = "DMARC (anti-spoofing policy)"
    dmarc = [t for t in dmarc_txt if t.lower().replace(" ", "").startswith("v=dmarc1")]

    if not dmarc:
        return [Finding(
            C, title, Status.CRITICAL,
            "No DMARC policy: fraudulent messages using your domain are neither blocked nor reported.",
            "Publish a TXT record on _dmarc.<domain>, starting with "
            "\"v=DMARC1; p=none; rua=mailto:dmarc@<domain>\" to monitor, then tighten it.",
        )]
    if len(dmarc) > 1:
        return [Finding(
            C, title, Status.CRITICAL,
            "Several DMARC records: this is invalid, they are ignored.",
            "Keep a single DMARC record.",
        )]

    t = _dmarc_tags(dmarc[0])
    policy = t.get("p", "").lower()
    findings: list[Finding] = []

    if policy == "reject":
        findings.append(Finding(C, title, Status.OK, "\"reject\" policy: spoofed emails are rejected."))
    elif policy == "quarantine":
        findings.append(Finding(
            C, title, Status.OK,
            "\"quarantine\" policy: spoofed emails go to spam.",
            "Move to \"p=reject\" once the reports confirm your legitimate email passes.",
        ))
    elif policy == "none":
        findings.append(Finding(
            C, title, Status.WARNING,
            "\"none\" policy: DMARC monitors but blocks nothing.",
            "After a few weeks of report analysis, move to \"p=quarantine\", then \"p=reject\".",
        ))
    else:
        findings.append(Finding(
            C, title, Status.CRITICAL,
            f"Missing or invalid DMARC policy (p={policy or '?'}).",
            "Fix the record: the p= tag must be none, quarantine or reject.",
        ))

    pct = t.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        findings.append(Finding(
            C, "DMARC: coverage", Status.WARNING,
            f"The policy only applies to {pct}% of messages.",
            "Gradually raise it to pct=100.",
        ))
    if "rua" not in t:
        findings.append(Finding(
            C, "DMARC: reports", Status.INFO,
            "No report address (rua): you cannot see who sends email on your behalf.",
            "Add \"rua=mailto:...\" to receive aggregate reports.",
        ))
    return findings


def check_dkim(found_selectors: list[str], tested_selectors: list[str]) -> list[Finding]:
    title = "DKIM (email signing)"
    if found_selectors:
        return [Finding(C, title, Status.OK, f"DKIM key(s) found: {', '.join(found_selectors)}.")]
    return [Finding(
        C, title, Status.INFO,
        f"No DKIM key found among the common selectors tested ({len(tested_selectors)}). "
        "This is not necessarily a problem: the selector may have another name.",
        "Check in your email service (Google Workspace, Microsoft 365...) that DKIM signing is enabled.",
    )]
