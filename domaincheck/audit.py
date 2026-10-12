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


def compute_score(findings) -> tuple[int, str]:
    score = max(0, 100 - sum(PENALTIES[f.status] for f in findings))
    grade = next(g for threshold, g in GRADE_THRESHOLDS if score >= threshold)
    return score, grade


def analyze(data: CollectedData, tested_selectors: list[str], now: datetime | None = None) -> Result:
    findings = []
    findings += check_certificate(data.certificate, now)
    findings += check_redirect(data.http)
    if data.http.https_reachable:
        findings += check_headers(data.http.headers)
    findings += check_mx(data.mx)
    findings += check_spf(data.root_txt)
    findings += check_dmarc(data.dmarc_txt)
    findings += check_dkim(data.dkim_selectors, tested_selectors)

    score, grade = compute_score(findings)
    return Result(
        domain=data.domain,
        date=now or datetime.now(timezone.utc),
        findings=findings,
        score=score,
        grade=grade,
    )


def run_audit(text: str, collector=None) -> Result:
    from .collector import DKIM_SELECTORS, Collector

    domain = normalize_domain(text)
    collector = collector or Collector()
    mail_domain = email_domain(domain)

    if hasattr(collector, "check_exists"):
        collector.check_exists(domain)

    data = CollectedData(
        domain=domain,
        root_txt=collector.txt(mail_domain),
        dmarc_txt=collector.txt(f"_dmarc.{mail_domain}"),
        mx=collector.mx(mail_domain),
        dkim_selectors=collector.dkim_selectors(mail_domain),
        certificate=collector.certificate(domain),
        http=collector.http(domain),
    )
    return analyze(data, DKIM_SELECTORS)
