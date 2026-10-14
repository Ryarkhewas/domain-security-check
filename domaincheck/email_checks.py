"""Email protection checks: MX, SPF, DMARC, DKIM, MTA-STS, TLS reporting.

What is valid comes from the standards (RFC 7208 SPF, RFC 7489 DMARC,
RFC 6376 DKIM, RFC 7505 null MX, RFC 8461 MTA-STS, RFC 8460 TLS-RPT). The points are this project's own:
there is no public scoring standard for email security.

These functions make no network calls: they receive DNS records that were
already fetched, which makes them easy to test.
"""

from __future__ import annotations

import re

from .models import Category, Finding, MTASTSInfo, Status

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
                       "Publish an SPF record listing your sending services, "
                       "or \"v=spf1 -all\" if this domain sends no email.",
                       -10, "spf")]
        return [_f(title, Status.CRITICAL,
                   "No SPF record: anyone can send email pretending to be this domain.",
                   "Publish an SPF TXT record listing your sending services "
                   "(e.g. \"v=spf1 include:_spf.google.com -all\").",
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
        findings.append(_f(title, Status.OK,
                           "SPF present with \"~all\" (soft fail). Fine, especially combined with DMARC.",
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
        findings.append(_f(title, Status.OK, f"{origin}\"reject\" policy: spoofed emails are rejected.",
                           source="dmarc"))
    elif policy == "quarantine":
        findings.append(_f(title, Status.OK, f"{origin}\"quarantine\" policy: spoofed emails go to spam.",
                           "Move to \"reject\" once the reports confirm your legitimate email passes.", 0, "dmarc"))
    elif policy == "none":
        findings.append(_f(title, Status.WARNING, f"{origin}\"none\" policy: DMARC monitors but blocks nothing.",
                           "After a few weeks of report analysis, move to \"quarantine\", then \"reject\".",
                           -20, "dmarc"))
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


# --- MTA-STS (RFC 8461) and SMTP TLS reporting (RFC 8460) ----------------------
MAX_MTA_STS_AGE = 31_557_600  # one year, RFC 8461 section 3.2


def parse_mta_sts_policy(text: str) -> dict[str, list[str]]:
    """"key: value" lines; "mx" may appear several times."""
    policy: dict[str, list[str]] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            policy.setdefault(key.strip().lower(), []).append(value.strip())
    return policy


def mx_matches(host: str, pattern: str) -> bool:
    """RFC 8461 section 4.1: "*.example.net" matches exactly one extra label on the left."""
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") > 0 and host.split(".", 1)[1] == pattern[2:]
    return host == pattern


def check_mta_sts(info: MTASTSInfo | None, mx: list[str]) -> list[Finding]:
    title, src = "MTA-STS (encrypted email delivery)", "mta-sts"
    receivers = [m for m in mx if m]  # a null MX ("." -> "") receives nothing
    if not receivers or info is None:
        return []  # the domain receives no email: nothing to protect

    findings = [_check_mta_sts_policy(info, receivers, title, src)]
    if any(t.lower().replace(" ", "").startswith("v=tlsrptv1") for t in info.tls_rpt):
        findings.append(_f("TLS reporting (TLS-RPT)", Status.OK,
                           "Present: sending servers report the delivery problems they meet.", points=None,
                           source="tls-rpt"))
    else:
        findings.append(_f("TLS reporting (TLS-RPT)", Status.INFO,
                           "Not set: you are not told when other servers fail to deliver your mail securely.",
                           "Publish a _smtp._tls TXT record, e.g. \"v=TLSRPTv1; rua=mailto:tls-reports@your-domain\".",
                           None, "tls-rpt"))
    return findings


def _check_mta_sts_policy(info: MTASTSInfo, receivers: list[str], title: str, src: str) -> Finding:
    records = [t for t in info.txt if t.lower().replace(" ", "").startswith("v=stsv1")]
    if not records:
        return _f(title, Status.WARNING,
                  "Not set: other mail servers may deliver your incoming email without encryption if an attacker "
                  "tampers with the connection.",
                  "Publish an MTA-STS policy (in \"testing\" mode first), or enable it in your email service.",
                  -5, src)
    if len(records) > 1 or "id=" not in records[0].replace(" ", "").lower():
        return _f(title, Status.WARNING, f"The _mta-sts TXT record is invalid: {'; '.join(records)}.",
                  "Publish a single record of the form \"v=STSv1; id=20260101\".", -10, src)
    if info.policy is None:
        return _f(title, Status.WARNING,
                  f"Announced, but the policy file cannot be read ({info.error or 'unknown error'}): "
                  "sending servers ignore it.",
                  "Serve the policy at https://mta-sts.<your-domain>/.well-known/mta-sts.txt (valid HTTPS, "
                  "no redirect).", -15, src)

    policy = parse_mta_sts_policy(info.policy)
    mode = (policy.get("mode") or [""])[0].lower()
    max_age = (policy.get("max_age") or [""])[0]
    patterns = policy.get("mx", [])
    problems = []
    if (policy.get("version") or [""])[0] != "STSv1":
        problems.append("version is not STSv1")
    if mode not in ("enforce", "testing", "none"):
        problems.append(f"unknown mode \"{mode}\"")
    if not max_age.isdigit() or int(max_age) > MAX_MTA_STS_AGE:
        problems.append("max_age missing or invalid")
    if not patterns and mode != "none":
        problems.append("no mx line")
    if problems:
        return _f(title, Status.WARNING, f"The policy file is invalid: {', '.join(problems)}.",
                  "Fix the policy file (fields: version, mode, mx, max_age).", -15, src)

    uncovered = [m for m in receivers if not any(mx_matches(m, p) for p in patterns)]
    if mode == "none":
        return _f(title, Status.WARNING, "Policy in \"none\" mode: MTA-STS is switched off.",
                  "Move to \"testing\", then \"enforce\".", -5, src)
    if uncovered and mode == "enforce":
        return _f(title, Status.CRITICAL,
                  f"Policy in \"enforce\" mode, but some mail servers are not listed ({', '.join(uncovered)}): "
                  "servers applying MTA-STS will refuse to deliver email to them.",
                  "Add these servers to the mx lines of the policy, then change its id.", -30, src)
    if mode == "testing":
        extra = f" Not listed: {', '.join(uncovered)}." if uncovered else ""
        return _f(title, Status.INFO,
                  f"Policy in \"testing\" mode: problems are reported but delivery is not yet protected.{extra}",
                  "Once the TLS reports are clean, switch to \"enforce\".", 0, src)
    return _f(title, Status.OK, "Policy in \"enforce\" mode, covering all mail servers: incoming email is always "
              "delivered encrypted.", source=src)
