"""Email protection checks: MX, SPF, DMARC, DKIM, MTA-STS, TLS reporting.

What is valid comes from the standards (RFC 7208 SPF, RFC 7489 DMARC,
RFC 6376 DKIM, RFC 7505 null MX, RFC 8461 MTA-STS, RFC 8460 TLS-RPT, RFC 3207 STARTTLS,
RFC 7672 DANE for SMTP). The points are this project's own:
there is no public scoring standard for email security.

These functions make no network calls: they receive DNS records that were
already fetched, which makes them easy to test.
"""

from __future__ import annotations

import re
from datetime import datetime

from .i18n import Date, Joined, M
from .models import Category, Finding, MailServerInfo, MTASTSInfo, Status

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
    servers = M("{count} server(s): {names}", count=len(mx), names=", ".join(mx[:3]))
    return [_f(title, Status.OK, servers, source="null-mx")]


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
                   M("{count} SPF records found: this is invalid, receiving servers ignore all of them.",
                     count=len(spf)),
                   "Merge them into a single SPF record.", -30, "spf")]

    record = spf[0]
    terms = record.split()[1:]
    findings: list[Finding] = []

    all_term = next((t for t in terms if t.lower().lstrip("+-~?") == "all"), None)
    if all_term is None and not any(t.lower().startswith("redirect=") for t in terms):
        findings.append(_f(title, Status.WARNING,
                           M("The SPF record does not end with an \"all\" rule: \"{record}\".", record=record),
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
                           M("{count} mechanisms require a DNS lookup (limit: 10). The SPF record may be rejected.",
                             count=lookups),
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
    origin = M("Inherited from {parent}: ", parent=inherited_from) if inherited_from else ""
    findings: list[Finding] = []

    if policy == "reject":
        findings.append(_f(title, Status.OK,
                           M("{origin}\"reject\" policy: spoofed emails are rejected.", origin=origin),
                           source="dmarc"))
    elif policy == "quarantine":
        findings.append(_f(title, Status.OK,
                           M("{origin}\"quarantine\" policy: spoofed emails go to spam.", origin=origin),
                           "Move to \"reject\" once the reports confirm your legitimate email passes.", 0, "dmarc"))
    elif policy == "none":
        findings.append(_f(title, Status.WARNING,
                           M("{origin}\"none\" policy: DMARC monitors but blocks nothing.", origin=origin),
                           "After a few weeks of report analysis, move to \"quarantine\", then \"reject\".",
                           -20, "dmarc"))
    else:
        findings.append(_f(title, Status.CRITICAL,
                           M("{origin}Missing or invalid DMARC policy ({tag}={policy}).", origin=origin, tag=tag,
                             policy=policy or "?"),
                           M("Fix the record: the {tag}= tag must be none, quarantine or reject.", tag=tag),
                           -40, "dmarc"))

    pct = t.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        findings.append(_f("DMARC: coverage", Status.WARNING,
                           M("The policy only applies to {pct}% of messages.", pct=pct),
                           "Gradually raise it to pct=100.", -10, "dmarc"))
    if "rua" not in t:
        findings.append(_f("DMARC: reports", Status.INFO,
                           "No report address (rua): you cannot see who sends email on your behalf.",
                           "Add \"rua=mailto:...\" to receive aggregate reports.", 0, "dmarc"))
    return findings


# Services that send email for a domain, recognised by the SPF include they ask for, with the DKIM
# selectors they publish (from their documentation). Empty: selectors chosen per account, cannot be guessed.
SENDERS = [
    ("_spf.google.com", "Google Workspace", ["google"]),
    ("spf.protection.outlook.com", "Microsoft 365", ["selector1", "selector2"]),
    ("sendgrid.net", "SendGrid", ["s1", "s2"]),
    ("mailgun.org", "Mailgun", ["mx", "smtp", "k1", "krs", "pic"]),
    ("servers.mcsv.net", "Mailchimp", ["k1", "k2", "k3"]),
    ("spf.mandrillapp.com", "Mailchimp Transactional", ["mandrill", "mte1", "mte2"]),
    ("spf.mailjet.com", "Mailjet", ["mailjet"]),
    ("zoho.com", "Zoho Mail", ["zoho", "zmail"]),
    ("zoho.eu", "Zoho Mail", ["zoho", "zmail"]),
    ("_spf.protonmail.ch", "Proton Mail", ["protonmail", "protonmail2", "protonmail3"]),
    ("spf.messagingengine.com", "Fastmail", ["fm1", "fm2", "fm3"]),
    ("mail.zendesk.com", "Zendesk", ["zendesk1", "zendesk2"]),
    ("spf.sendinblue.com", "Brevo", []),
    ("spf.brevo.com", "Brevo", []),
    ("amazonses.com", "Amazon SES", []),
    ("spf.mtasv.net", "Postmark", []),
    ("mx.ovh.com", "OVHcloud", []),
]


def spf_senders(root_txt: list[str]) -> list[tuple[str, list[str]]]:
    """[(service, its usual DKIM selectors)] for the services named in the SPF record's includes."""
    found: dict[str, list[str]] = {}
    for record in root_txt:
        if not record.lower().startswith("v=spf1"):
            continue
        for term in record.split():
            domain = term.lower().lstrip("+-~?")
            if not domain.startswith("include:"):
                continue
            domain = domain[len("include:"):].rstrip(".")
            for suffix, name, selectors in SENDERS:
                if domain == suffix or domain.endswith("." + suffix):
                    found.setdefault(name, selectors)
    return list(found.items())


def dkim_key_bits(record: str) -> int | None:
    """Size of the RSA key of a DKIM record, 0 for a revoked key (empty p=), None when it cannot be read."""
    tags = dict(part.strip().split("=", 1) for part in record.split(";") if "=" in part)
    if tags.get("k", "rsa").strip().lower() != "rsa":
        return None  # ed25519: fixed size, always strong
    key = "".join(tags.get("p", "").split())
    if not key:
        return 0
    try:
        import base64

        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        public = load_der_public_key(base64.b64decode(key + "=" * (-len(key) % 4)))
    except (ImportError, ValueError, TypeError):
        return None
    return public.key_size if isinstance(public, rsa.RSAPublicKey) else None


def check_dkim(found_selectors: list[str], tested_selectors: list[str], records: dict[str, str] | None = None,
               senders: list[tuple[str, list[str]]] | None = None) -> list[Finding]:
    """DKIM keys found among the tested selectors, their strength, and the senders of the SPF record without one."""
    title = "DKIM (email signing)"
    records = records or {}
    senders = senders or []
    findings = []
    if found_selectors:
        sizes = {sel: dkim_key_bits(records[sel]) for sel in found_selectors if sel in records}
        described = [f"{sel} (RSA {sizes[sel]})" if sizes.get(sel) else sel for sel in found_selectors]
        weak = [sel for sel, bits in sizes.items() if bits and bits < 1024]
        short = [sel for sel, bits in sizes.items() if bits and 1024 <= bits < 2048]
        found = M("DKIM key(s) found: {selectors}.", selectors=", ".join(described))
        if weak:
            findings.append(_f(title, Status.CRITICAL,
                               M("{found} Keys under 1024 bits can be broken: someone could then sign emails in your "
                                 "name: {weak}.", found=found, weak=", ".join(weak)),
                               "Generate a new 2048-bit DKIM key in your email service and delete the old record.",
                               -20, "dkim"))
        elif short:
            findings.append(_f(title, Status.WARNING,
                               M("{found} 1024-bit keys are still accepted but now considered too short; 2048 bits "
                                 "is the current recommendation: {short}.", found=found, short=", ".join(short)),
                               "Switch to a 2048-bit DKIM key when your email service allows it (key rotation).",
                               -5, "dkim"))
        else:
            findings.append(_f(title, Status.OK, found, source="dkim"))
    else:
        with_selectors = [name for name, sels in senders if sels]
        detail = M("No DKIM key found among the common selectors tested ({count}). "
                   "This is not necessarily a problem: the selector may have another name.",
                   count=len(tested_selectors))
        if with_selectors:
            detail = M("No DKIM key found among the common selectors tested ({count}), including the usual ones of "
                       "the services named in SPF ({senders}): DKIM signing is probably not enabled for them.",
                       count=len(tested_selectors), senders=", ".join(with_selectors))
        findings.append(_f(title, Status.INFO, detail,
                           "Check in your email service (Google Workspace, Microsoft 365...) that DKIM signing is "
                           "enabled.", None, "dkim"))
    missing = [name for name, sels in senders if sels and not set(sels) & set(found_selectors)]
    if found_selectors and missing:
        findings.append(_f("DKIM for each sending service", Status.INFO,
                           M("SPF allows these services to send for the domain, but their usual DKIM keys were not "
                             "found: {senders}. Their emails may be signed with their own domain, which DMARC does not "
                             "count as yours.", senders=", ".join(missing)),
                           "Enable DKIM with your own domain in each of these services.", None, "dkim"))
    return findings


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
        return _f(title, Status.WARNING,
                  M("The _mta-sts TXT record is invalid: {records}.", records="; ".join(records)),
                  "Publish a single record of the form \"v=STSv1; id=20260101\".", -10, src)
    if info.policy is None:
        return _f(title, Status.WARNING,
                  M("Announced, but the policy file cannot be read ({error}): sending servers ignore it.",
                    error=info.error or M("unknown error")),
                  "Serve the policy at https://mta-sts.<your-domain>/.well-known/mta-sts.txt (valid HTTPS, "
                  "no redirect).", -15, src)

    policy = parse_mta_sts_policy(info.policy)
    mode = (policy.get("mode") or [""])[0].lower()
    max_age = (policy.get("max_age") or [""])[0]
    patterns = policy.get("mx", [])
    problems = []
    if (policy.get("version") or [""])[0] != "STSv1":
        problems.append(M("version is not STSv1"))
    if mode not in ("enforce", "testing", "none"):
        problems.append(M("unknown mode \"{mode}\"", mode=mode))
    if not max_age.isdigit() or int(max_age) > MAX_MTA_STS_AGE:
        problems.append(M("max_age missing or invalid"))
    if not patterns and mode != "none":
        problems.append(M("no mx line"))
    if problems:
        return _f(title, Status.WARNING, M("The policy file is invalid: {problems}.", problems=Joined(problems)),
                  "Fix the policy file (fields: version, mode, mx, max_age).", -15, src)

    uncovered = [m for m in receivers if not any(mx_matches(m, p) for p in patterns)]
    if mode == "none":
        return _f(title, Status.WARNING, "Policy in \"none\" mode: MTA-STS is switched off.",
                  "Move to \"testing\", then \"enforce\".", -5, src)
    if uncovered and mode == "enforce":
        return _f(title, Status.CRITICAL,
                  M("Policy in \"enforce\" mode, but some mail servers are not listed ({servers}): "
                    "servers applying MTA-STS will refuse to deliver email to them.", servers=", ".join(uncovered)),
                  "Add these servers to the mx lines of the policy, then change its id.", -30, src)
    if mode == "testing":
        extra = M(" Not listed: {servers}.", servers=", ".join(uncovered)) if uncovered else ""
        return _f(title, Status.INFO,
                  M("Policy in \"testing\" mode: problems are reported but delivery is not yet protected.{extra}",
                    extra=extra),
                  "Once the TLS reports are clean, switch to \"enforce\".", 0, src)
    return _f(title, Status.OK, "Policy in \"enforce\" mode, covering all mail servers: incoming email is always "
              "delivered encrypted.", source=src)


# --- The mail servers themselves -------------------------------------------------------
def _enforced(info: MTASTSInfo | None) -> bool:
    if info is None or not info.policy:
        return False
    return [m.lower() for m in parse_mta_sts_policy(info.policy).get("mode", [])] == ["enforce"]


def check_mail_servers(servers: list[MailServerInfo], mta_sts: MTASTSInfo | None, now: datetime) -> list[Finding]:
    """STARTTLS, TLS version, certificates and DANE of the mail servers, as a sending server sees them."""
    if not servers:
        return []
    reached = [s for s in servers if s.reachable]
    if not reached:
        return [_f("Mail servers: encryption", Status.INFO,
                   M("Could not connect to the mail servers on port 25 ({error}). This port is often blocked by the "
                     "network the audit runs from (home connections, cloud providers): nothing can be concluded.",
                     error=servers[0].error or M("no answer")),
                   "Run the audit from a network that allows outgoing connections on port 25.", None, "starttls")]
    findings = []
    missed = [s.host for s in servers if not s.reachable]
    unreached = M(" Not reached: {hosts}.", hosts=", ".join(missed)) if missed else ""

    title = "Encryption of incoming email (STARTTLS)"
    plain = [s.host for s in reached if not s.starttls]
    if plain:
        findings.append(_f(title, Status.WARNING,
                           M("These mail servers do not offer encryption: emails sent to you travel in clear text "
                             "and can be read on the way: {hosts}.{unreached}", hosts=", ".join(plain),
                             unreached=unreached),
                           "Enable STARTTLS with a valid certificate on these servers (or ask your email provider).",
                           -20, "starttls"))
    else:
        versions = ", ".join(sorted({s.tls_version for s in reached if s.tls_version}))
        findings.append(_f(title, Status.OK,
                           M("Every mail server reached offers encryption ({versions}).{unreached}",
                             versions=versions or "TLS", unreached=unreached), source="starttls"))

    old = [f"{s.host} ({s.tls_version})" for s in reached if s.tls_version in ("SSLv3", "TLSv1", "TLSv1.1")]
    if old:
        findings.append(_f("Mail server TLS version", Status.WARNING,
                           M("These mail servers negotiate an obsolete TLS version with a current sender: {hosts}.",
                             hosts=", ".join(old)),
                           "Allow TLS 1.2 and 1.3 on these servers.", -10, "rfc8996"))

    title = "Mail server certificates"
    enforced = _enforced(mta_sts)
    bad: list[str] = []
    for s in reached:
        if s.cert_valid is False:
            bad.append(f"{s.host} ({s.cert_error})")
        elif s.cert_expires and s.cert_expires < now:
            bad.append(M("{host} (expired on {date})", host=s.host, date=Date(s.cert_expires)))
    if bad and enforced:
        findings.append(_f(title, Status.CRITICAL,
                           M("Your MTA-STS policy is in enforce mode, but these certificates are not valid: senders "
                             "that apply MTA-STS (Gmail, Outlook...) will refuse to deliver emails to you: {hosts}.",
                             hosts=Joined(bad)),
                           "Install a valid certificate for the server's name now, or switch MTA-STS to testing mode "
                           "until it is fixed.", -30, "mta-sts"))
    elif bad:
        findings.append(_f(title, Status.WARNING,
                           M("Not valid: {hosts}. Senders still encrypt, but cannot check they reach the real server, "
                             "and MTA-STS or DANE cannot be enforced.", hosts=Joined(bad)),
                           "Install a certificate valid for the mail server's name (Let's Encrypt is free).", -5,
                           "starttls"))
    elif any(s.cert_valid for s in reached):
        findings.append(_f(title, Status.OK, "The certificates of the mail servers are valid.", source="starttls"))

    if any(s.starttls for s in reached):
        with_dane = [s.host for s in servers if s.tlsa]
        if with_dane and len(with_dane) == len(servers):
            findings.append(_f("DANE (mail server keys in DNS)", Status.OK,
                               "Every mail server publishes TLSA records: senders that support DANE check the "
                               "server's key through DNSSEC.", source="dane"))
        else:
            findings.append(_f("DANE (mail server keys in DNS)", Status.INFO,
                               M("Not used{partial}. Optional: DANE lets senders check the mail server's key through "
                                 "DNSSEC, and is required by some administrations.",
                                 partial=M(" by {hosts}", hosts=", ".join(s.host for s in servers if not s.tlsa))
                                 if with_dane else ""),
                               "If the domain uses DNSSEC, publish a TLSA record for each mail server "
                               "(_25._tcp.<server>), or ask your email provider.", None, "dane"))
    return findings
