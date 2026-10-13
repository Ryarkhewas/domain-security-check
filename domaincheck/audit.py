"""Orchestration: domain normalisation, checks, scoring."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .email_checks import check_dkim, check_dmarc, check_mx, check_spf
from .models import CollectedData, Result, Status
from .web_checks import check_certificate, check_headers, check_redirect

PENALTIES = {Status.CRITICAL: 20, Status.WARNING: 5, Status.INFO: 0, Status.OK: 0}
GRADE_THRESHOLDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]

_VALID_DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


class InvalidDomain(ValueError):
    pass


def normalize_domain(text: str) -> str:
    """"https://WWW.Example.com/contact" -> "www.example.com\""""
    d = text.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1].split(":")[0].rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")  # internationalised domain names
    except UnicodeError as e:
        raise InvalidDomain(f"Invalid domain name: {text!r}") from e
    if not _VALID_DOMAIN.match(d):
        raise InvalidDomain(f"Invalid domain name: {text!r}")
    return d


def email_domain(domain: str) -> str:
    """SPF/DMARC records live on the main domain, not on "www"."""
    return domain[4:] if domain.startswith("www.") else domain


CAPPED_SCORE = 39  # highest score that still gives an F


def compute_score(findings) -> tuple[int, str]:
    score = max(0, 100 - sum(PENALTIES[f.status] for f in findings))
    grade = next(g for threshold, g in GRADE_THRESHOLDS if score >= threshold)
    return score, grade


def broken_https_reason(data: CollectedData, now: datetime) -> str:
    """Return why HTTPS is broken for visitors, or "" if it works (or there is no website).

    When HTTPS fails, header checks cannot run, so without a cap a broken site
    would lose fewer points than a working one with a few missing headers.
    """
    cert = data.certificate
    if cert is None:
        if data.http.http_redirects_to_https is None:
            return ""  # nothing answers on port 80 or 443: no website to grade
        return "the site is reachable over HTTP but not over HTTPS"
    if not cert.valid:
        return f"the HTTPS certificate is not valid ({cert.error or 'unknown error'})"
    if cert.expires_at and cert.expires_at < now:
        return "the HTTPS certificate has expired"
    return ""


def analyze(data: CollectedData, tested_selectors: list[str], now: datetime | None = None) -> Result:
    findings = []
    findings += check_certificate(data.certificate, now)
    findings += check_redirect(data.http)
    if data.http.https_reachable:
        findings += check_headers(data.http.headers)
    findings += check_mx(data.mx)
    findings += check_spf(data.root_txt)
    findings += check_dmarc(data.dmarc_txt, data.dmarc_inherited_from)
    findings += check_dkim(data.dkim_selectors, tested_selectors)

    now = now or datetime.now(timezone.utc)
    score, grade = compute_score(findings)
    cap_reason = broken_https_reason(data, now)
    if cap_reason and score > CAPPED_SCORE:
        score, grade = CAPPED_SCORE, "F"
    return Result(
        domain=data.domain,
        date=now,
        findings=findings,
        score=score,
        grade=grade,
        cap_reason=cap_reason,
    )


def _has_dmarc(records: list[str]) -> bool:
    return any(r.lower().replace(" ", "").startswith("v=dmarc1") for r in records)


def find_dmarc(collector, domain: str) -> tuple[list[str], str]:
    """Return (records, inherited_from).

    Look for _dmarc.<domain> first; if there is none, walk up the parent
    domains (shop.eu.example.com -> eu.example.com -> example.com), as a
    subdomain is covered by its parent's policy. The top-level domain itself
    is never queried.
    """
    records = collector.txt(f"_dmarc.{domain}")
    if _has_dmarc(records):
        return records, ""
    labels = domain.split(".")
    for i in range(1, len(labels) - 1):
        parent = ".".join(labels[i:])
        parent_records = collector.txt(f"_dmarc.{parent}")
        if _has_dmarc(parent_records):
            return parent_records, parent
    return records, ""


def run_audit(text: str, collector=None) -> Result:
    from .collector import DKIM_SELECTORS, Collector

    domain = normalize_domain(text)
    collector = collector or Collector()
    mail_domain = email_domain(domain)

    if hasattr(collector, "check_exists"):
        collector.check_exists(domain)

    dmarc_records, dmarc_parent = find_dmarc(collector, mail_domain)
    data = CollectedData(
        domain=domain,
        root_txt=collector.txt(mail_domain),
        dmarc_txt=dmarc_records,
        dmarc_inherited_from=dmarc_parent,
        mx=collector.mx(mail_domain),
        dkim_selectors=collector.dkim_selectors(mail_domain),
        certificate=collector.certificate(domain),
        http=collector.http(domain),
    )
    return analyze(data, DKIM_SELECTORS)
