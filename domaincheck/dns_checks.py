"""Domain & DNS checks: DNSSEC and CAA.

What is valid comes from the standards (RFC 4033-4035 DNSSEC, RFC 8659 CAA).
The points are this project's own, kept moderate: both are defence in depth,
and many large sites still do without them.

No network access here: the functions analyse data that was already collected.
"""

from __future__ import annotations

from datetime import datetime

from .i18n import Date, M
from .models import CAAInfo, Category, DNSSECInfo, Finding, RDAPInfo, Status
from .rdap import TRANSFER_LOCKS

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


# --- Registration (RDAP) -----------------------------------------------------------
def check_registration(info: RDAPInfo, now: datetime) -> list[Finding]:
    """Expiry date of the domain and its transfer lock, as published by the registry."""
    expiry_title, lock_title, src = "Domain expiry date", "Transfer lock", "rdap"
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
                               M("The domain is locked against transfers to another registrar."), source=src))
        else:
            findings.append(_f(lock_title, Status.WARNING,
                               M("The domain is not locked against transfers: with a stolen access to your registrar "
                                 "account, it is easier to move it elsewhere."),
                               M("Turn on the transfer lock (often called \"registrar lock\") at your registrar."),
                               -5, src))
    return findings
