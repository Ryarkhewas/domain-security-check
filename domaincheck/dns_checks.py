"""Domain & DNS checks: DNSSEC, CAA, registration data and forgotten subdomains.

What is valid comes from the standards (RFC 4033-4035 DNSSEC, RFC 8659 CAA).
The points are this project's own, kept moderate: both are defence in depth,
and many large sites still do without them.

No network access here: the functions analyse data that was already collected.
"""

from __future__ import annotations

from datetime import datetime

from .ct import takeover_provider
from .i18n import Date, Joined, M
from .models import (
    CAAInfo,
    Category,
    CertificateInfo,
    DNSSECInfo,
    Finding,
    RDAPInfo,
    Status,
    SubdomainAudit,
    SubdomainInfo,
)
from .rdap import TRANSFER_LOCKS
from .software import check_software

D = Category.DNS
KNOWN_CAA_TAGS = {"issue", "issuewild", "iodef", "issuemail", "issuevmc", "contactemail", "contactphone"}


def _f(title, status, detail, recommendation="", points=0, source="") -> Finding:
    return Finding(D, title, status, detail, recommendation, points, source)


def check_dnssec(info: DNSSECInfo) -> Finding:
    title, src = "DNSSEC", "dnssec"
    if info.error:
        return _f(title, Status.INFO, M("Could not be checked ({error}).", error=info.error), points=None, source=src)
    zone = info.zone or M("the zone")
    if info.ds_count == 0:
        return _f(title, Status.WARNING,
                  M("Not enabled for {zone}: DNS answers are not signed, so a resolver cannot detect forged answers "
                    "(redirecting visitors or emails to another server).", zone=zone),
                  "Enable DNSSEC at your DNS host, then publish the DS record at your registrar "
                  "(often a single option in their interface).", -15, src)
    if info.dnskey_count == 0 or info.ds_matches is False:
        problem = M("publishes no DNSSEC key") if info.dnskey_count == 0 else M("has no key matching the DS record")
        return _f(title, Status.CRITICAL,
                  M("Broken: the parent zone announces DNSSEC for {zone}, but the zone {problem}. Validating "
                    "resolvers (used by many ISPs and public DNS services) may refuse to resolve the domain.",
                    zone=zone, problem=problem),
                  "Fix it now: publish the right DS record at your registrar, or remove it if DNSSEC was turned off "
                  "at your DNS host.", -50, src)
    unchecked = M(" (the DS record could not be compared with the keys)") if info.ds_matches is None else ""
    return _f(title, Status.OK, M("Enabled for {zone}: DNS answers are signed{unchecked}.", zone=zone,
                                  unchecked=unchecked), source=src)


def check_caa(info: CAAInfo, has_website: bool) -> Finding:
    title, src = "CAA (allowed certificate authorities)", "caa"
    if info.error:
        return _f(title, Status.INFO, M("Could not be checked ({error}).", error=info.error), points=None, source=src)
    if not info.records:
        return _f(title, Status.WARNING,
                  "No CAA record: any certificate authority may issue a certificate for this domain.",
                  "Publish a CAA record naming the authority you use, e.g. 0 issue \"letsencrypt.org\".", -5, src)

    where = "" if not info.owner else M(" (published on {owner})", owner=info.owner)
    unknown_critical = [tag for flags, tag, _ in info.records if flags & 128 and tag.lower() not in KNOWN_CAA_TAGS]
    if unknown_critical:
        return _f(title, Status.WARNING,
                  M("A CAA record uses an unknown tag marked critical ({tags}){where}: "
                    "certificate authorities must then refuse to issue any certificate.",
                    tags=", ".join(unknown_critical), where=where),
                  "Remove the critical flag (128) or fix the tag name.", -10, src)

    issuers = [value.split(";")[0].strip() for _, tag, value in info.records if tag.lower() in ("issue", "issuewild")]
    if not issuers:
        return _f(title, Status.WARNING,
                  M("CAA records exist{where} but none restricts issuance (no \"issue\" tag).", where=where),
                  "Add an \"issue\" record naming the authority you use.", -5, src)
    named = sorted({i for i in issuers if i})
    if not named:
        if has_website:
            return _f(title, Status.WARNING,
                      M("CAA forbids every certificate authority{where}: the site's certificate cannot be renewed.",
                        where=where),
                      "Name the authority you use in an \"issue\" record.", -10, src)
        return _f(title, Status.OK, M("CAA forbids every certificate authority{where} (fine for a domain without "
                                      "a website).", where=where), source=src)
    return _f(title, Status.OK, M("Only these authorities may issue certificates{where}: {names}.", where=where,
                                  names=", ".join(named)), source=src)


# --- CAA and the certificate actually in use -----------------------------------------
# Issuer organisation (as written in certificates) -> identifiers the authority accepts in CAA records,
# as published by each authority (CCADB "CAA identifiers" and the authorities' documentation)
CAA_IDENTIFIERS = [
    ("let's encrypt", ["letsencrypt.org"]),
    ("google trust services", ["pki.goog"]),
    ("digicert", ["digicert.com", "symantec.com", "thawte.com", "geotrust.com", "rapidssl.com",
                  "digitalcertvalidation.com"]),
    ("zerossl", ["sectigo.com"]),
    ("sectigo", ["sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"]),
    ("comodo", ["sectigo.com", "comodoca.com", "comodo.com", "usertrust.com", "trust-provider.com"]),
    ("amazon", ["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"]),
    ("globalsign", ["globalsign.com"]),
    ("godaddy", ["godaddy.com", "starfieldtech.com"]),
    ("starfield", ["godaddy.com", "starfieldtech.com"]),
    ("entrust", ["entrust.net"]),
    ("ssl corporation", ["ssl.com"]),
    ("ssl.com", ["ssl.com"]),
    ("buypass", ["buypass.com"]),
    ("actalis", ["actalis.it"]),
    ("certigna", ["certigna.fr", "certigna.com"]),
    ("harica", ["harica.gr"]),
]


def caa_identifiers(issuer: str) -> list[str]:
    """CAA identifiers of a certificate issuer, [] if the authority is not in the table."""
    name = issuer.lower()
    return next((ids for word, ids in CAA_IDENTIFIERS if word in name), [])


def check_caa_certificate(info: CAAInfo, cert: CertificateInfo | None) -> Finding | None:
    """Does CAA allow the authority that issued the certificate in use? If not, its renewal will be refused."""
    if info.error or not info.records or cert is None or not cert.valid or not cert.issuer:
        return None
    title, src = "CAA and the current certificate", "caa"
    wildcard = any(n.startswith("*.") for n in cert.names)
    tags = {tag.lower() for _, tag, _ in info.records}
    tag = "issuewild" if wildcard and "issuewild" in tags else "issue"
    if tag not in tags:
        return None  # no restriction for this kind of certificate (reported by the CAA check)
    allowed = {value.split(";")[0].strip().lower() for _, t, value in info.records if t.lower() == tag}
    allowed.discard("")
    ids = caa_identifiers(cert.issuer)
    if not ids:
        return _f(title, Status.INFO,
                  M("The authority of the current certificate ({issuer}) is not in this tool's list, so whether CAA "
                    "allows it was not checked. Allowed: {allowed}.", issuer=cert.issuer,
                    allowed=", ".join(sorted(allowed)) or M("none")), points=None, source=src)
    if allowed & set(ids):
        return _f(title, Status.OK,
                  M("The current certificate comes from {issuer}, which CAA allows: renewals will be accepted.",
                    issuer=cert.issuer), source=src)
    return _f(title, Status.WARNING,
              M("The current certificate comes from {issuer}, but CAA only allows {allowed}: the certificate stays "
                "valid, but its renewal by the same authority will be refused, and the site will show an error when "
                "it expires.", issuer=cert.issuer, allowed=", ".join(sorted(allowed)) or M("no authority")),
              M("Add \"{id}\" to the CAA records ({tag}), or switch to an allowed authority before the certificate "
                "expires.", id=ids[0], tag=tag), -10, src)


# --- Registration (RDAP) -----------------------------------------------------------
def check_registration(info: RDAPInfo, now: datetime) -> list[Finding]:
    """Expiry date of the domain and its transfer lock, as published by the registry."""
    expiry_title, lock_title, src, lock_src = "Domain expiry date", "Transfer lock", "rdap", "transfer-lock"
    if info.error:
        return [_f(expiry_title, Status.INFO, M("Could not be checked ({error}).", error=info.error), points=None,
                   source=src)]
    findings = []
    registrar = M(" Registrar: {name}.", name=info.registrar) if info.registrar else ""
    if info.expires is None:
        findings.append(_f(expiry_title, Status.INFO,
                           M("The registry does not publish the expiry date of {domain}.{registrar}",
                             domain=info.domain, registrar=registrar), points=None, source=src))
    else:
        days = (info.expires - now).days
        date = Date(info.expires)
        if info.expires < now:
            findings.append(_f(expiry_title, Status.CRITICAL,
                               M("The domain {domain} expired on {date}: the website and the email will stop working, "
                                 "and someone else could register the name.{registrar}", domain=info.domain, date=date,
                                 registrar=registrar),
                               M("Renew the domain immediately at your registrar."), -50, src))
        elif days < 15:
            findings.append(_f(expiry_title, Status.CRITICAL,
                               M("The domain {domain} expires in {days} day(s), on {date}.{registrar}",
                                 domain=info.domain, days=days, date=date, registrar=registrar),
                               M("Renew it now and turn on automatic renewal at your registrar."), -30, src))
        elif days < 30:
            findings.append(_f(expiry_title, Status.WARNING,
                               M("The domain {domain} expires in {days} days, on {date}.{registrar}",
                                 domain=info.domain, days=days, date=date, registrar=registrar),
                               M("Check that automatic renewal is on and that the payment card is valid."), -10, src))
        else:
            findings.append(_f(expiry_title, Status.OK,
                               M("The domain {domain} is registered until {date} ({days} days).{registrar}",
                                 domain=info.domain, date=date, days=days, registrar=registrar), source=src))
    if info.statuses:
        if TRANSFER_LOCKS & set(info.statuses):
            findings.append(_f(lock_title, Status.OK,
                               M("The domain is locked against transfers to another registrar."), source=lock_src))
        else:
            findings.append(_f(lock_title, Status.WARNING,
                               M("The domain is not locked against transfers: with a stolen access to your registrar "
                                 "account, it is easier to move it elsewhere."),
                               M("Turn on the transfer lock (often called \"registrar lock\") at your registrar."),
                               -5, lock_src))
    return findings


# --- Subdomains in Certificate Transparency logs -----------------------------------
SHOWN = 12  # names listed in a detail; the others are counted


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:SHOWN])
    return shown if len(names) <= SHOWN else M("{names} and {count} more", names=shown, count=len(names) - SHOWN)


def check_subdomains(info: SubdomainInfo) -> list[Finding]:
    """Dangling CNAME records among the subdomains published in CT logs (subdomain takeover)."""
    title, src = "Forgotten subdomains (CT logs)", "ct"
    if info.error:
        return [_f(title, Status.INFO, M("Could not be checked ({error}).", error=info.error), points=None,
                   source=src)]
    findings = _subdomain_findings(info, title, src)
    if info.source == "Cert Spotter":
        # Seen in the Live check: for wikipedia.org, 1 name from Cert Spotter against 3 from crt.sh
        note = M("crt.sh did not answer, so the names come from Cert Spotter, which may list fewer old "
                 "certificates: forgotten subdomains can be missing. Run the audit again later for a complete "
                 "check.")
        for f in findings:
            f.detail = M("{detail} {note}", detail=f.detail, note=note)
    return findings


def _subdomain_findings(info: SubdomainInfo, title: str, src: str) -> list[Finding]:
    if not info.names:
        return [_f(title, Status.OK, M("No subdomain found in Certificate Transparency logs ({source}).",
                                       source=info.source), source=src)]
    unknown = M(" ({count} could not be looked up)", count=info.unknown) if info.unknown else ""
    seen = M("{count} subdomain(s) found in Certificate Transparency logs ({source}), {active} still in use{unknown}.",
             count=len(info.names), source=info.source, active=len(info.resolving), unknown=unknown)
    findings = []
    open_to_takeover = [(n, t, takeover_provider(t)) for n, t in info.dangling if takeover_provider(t)]
    other = [(n, t) for n, t in info.dangling if not takeover_provider(t)]
    if open_to_takeover:
        listed = ", ".join(f"{n} → {t} ({p})" for n, t, p in open_to_takeover)
        findings.append(_f(title, Status.CRITICAL,
                           M("{seen} These subdomains point to a resource that no longer exists at a provider where "
                             "anyone can create it again, and then publish content on your domain (subdomain "
                             "takeover): {listed}.", seen=seen, listed=listed),
                           "Delete these DNS records now, or recreate the resource at the provider before someone "
                           "else does.", -30, src))
    if other:
        listed = ", ".join(f"{n} → {t}" for n, t in other)
        findings.append(_f(title, Status.WARNING,
                           M("{seen} These subdomains point to a name that no longer exists: {listed}.",
                             seen=seen, listed=listed),
                           "Delete the DNS records of subdomains that are no longer used.", -10, src))
    if not findings:
        active = M(" In use: {names}.", names=_names(info.resolving)) if info.resolving else ""
        findings.append(_f(title, Status.OK,
                           M("{seen} None points to a resource that no longer exists.{active}",
                             seen=seen, active=active), source=src))
    return findings


# --- Subdomains in use (with --subdomains) -------------------------------------------
def check_subdomain_audits(audits: list[SubdomainAudit], lifecycles: dict, now: datetime) -> list[Finding]:
    """HTTPS, certificates, redirects, old TLS and outdated software of the subdomains in use.

    Not scored: the grades describe the domain itself. Problems still appear among the priority actions.
    """
    if not audits:
        return []
    tls = Category.TLS
    websites = [a for a in audits if a.https or a.http]
    findings = []
    title = "Subdomains: HTTPS certificates"
    seen = M("{count} subdomain(s) in use checked, {web} with a website.", count=len(audits), web=len(websites))
    bad = []
    for a in audits:
        if a.cert_valid is False:
            bad.append(f"{a.host} ({a.cert_error})")
        elif a.cert_expires and a.cert_expires < now:
            bad.append(M("{host} (expired on {date})", host=a.host, date=Date(a.cert_expires)))
    if bad:
        findings.append(Finding(tls, title, Status.WARNING,
                                M("{seen} Certificate not valid: {hosts}. Visitors get a security warning.",
                                  seen=seen, hosts=Joined(bad)),
                                "Renew or replace these certificates, or delete the subdomains no longer used.", None,
                                "tls-guide"))
    else:
        findings.append(Finding(tls, title, Status.OK if websites else Status.INFO,
                                M("{seen} Every certificate is valid.", seen=seen) if websites else seen,
                                points=None, source="tls-guide"))
    plain = [a.host for a in audits if a.http and not a.https]
    no_redirect = [a.host for a in audits if a.https and a.redirects is False]
    if plain:
        findings.append(Finding(tls, "Subdomains: no HTTPS", Status.WARNING,
                                M("These subdomains only answer over unencrypted HTTP: {hosts}.",
                                  hosts=", ".join(plain)),
                                "Enable HTTPS on these subdomains (a free Let's Encrypt certificate is enough).", None,
                                "redirection"))
    if no_redirect:
        findings.append(Finding(tls, "Subdomains: HTTP to HTTPS redirect", Status.WARNING,
                                M("These subdomains are still reachable over HTTP without a redirect to HTTPS: "
                                  "{hosts}.", hosts=", ".join(no_redirect)),
                                "Redirect HTTP to HTTPS (301) on these subdomains too.", None, "redirection"))
    labels = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1"}
    old = [f"{a.host} ({', '.join(labels[v] for v in a.old_tls)})" for a in audits if a.old_tls]
    if old:
        findings.append(Finding(tls, "Subdomains: obsolete TLS versions", Status.WARNING,
                                M("These subdomains still accept TLS 1.0 or 1.1: {hosts}.", hosts=", ".join(old)),
                                "Only allow TLS 1.2 and 1.3 on these subdomains too.", None, "rfc8996"))
    for a in audits:
        findings += [f for f in check_software(a.software, lifecycles, now, host=a.host)
                     if f.status in (Status.CRITICAL, Status.WARNING)]
    return findings
