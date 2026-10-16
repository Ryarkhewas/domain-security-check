"""Orchestration: domain normalisation, checks, scoring."""

from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .dns_checks import check_caa, check_dnssec
from .email_checks import check_dkim, check_dmarc, check_mta_sts, check_mx, check_spf, effective_dmarc_policy
from .i18n import M
from .models import CollectedData, Result
from .scoring import category_grades, overall_grade
from .tls_checks import check_certificate
from .web_checks import check_website

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


def broken_https_reason(data: CollectedData, now: datetime) -> str:
    """Return why HTTPS is broken for visitors, or "" if it works (or there is no website).

    When HTTPS fails, header checks cannot run, so without a cap a broken site
    would score better on the website grade than a working one with a few
    missing headers.
    """
    cert = data.certificate
    if cert is None:
        if data.http.http_redirects_to_https is None:
            return ""  # nothing answers on port 80 or 443: no website to grade
        return M("the site is reachable over HTTP but not over HTTPS")
    if not cert.valid:
        return M("the HTTPS certificate is not valid ({error})", error=cert.error or M("unknown error"))
    if cert.expires_at and cert.expires_at < now:
        return M("the HTTPS certificate has expired")
    return ""


def website_exists(data: CollectedData) -> bool:
    return data.certificate is not None or data.http.http_redirects_to_https is not None


def analyze(data: CollectedData, tested_selectors: list[str], now: datetime | None = None) -> Result:
    now = now or datetime.now(timezone.utc)
    exists = website_exists(data)
    findings = []
    if exists:
        findings += check_certificate(data.certificate, now)
        findings += check_website(data.http, data.domain)
    findings += check_mx(data.mx)
    enforced = effective_dmarc_policy(data.dmarc_txt, data.dmarc_inherited_from) in ("quarantine", "reject")
    findings += check_spf(data.root_txt, dmarc_enforced=enforced)
    findings += check_dmarc(data.dmarc_txt, data.dmarc_inherited_from)
    findings += check_dkim(data.dkim_selectors, tested_selectors)
    findings += check_mta_sts(data.mta_sts, data.mx)
    if data.dnssec is not None:
        findings.append(check_dnssec(data.dnssec))
    if data.caa is not None:
        findings.append(check_caa(data.caa, exists))

    cap_reason = broken_https_reason(data, now)
    grades = category_grades(findings, exists, cap_reason)
    return Result(
        domain=data.domain,
        date=now,
        findings=findings,
        grades=grades,
        grade=overall_grade(grades),
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
        dnssec=collector.dnssec(domain),
        caa=collector.caa(domain),
        mta_sts=collector.mta_sts(mail_domain),
    )
    return analyze(data, DKIM_SELECTORS)


def audit_many(domains: list[str], workers: int = 6,
               on_done: Callable[[str, Result | Exception], None] | None = None) -> dict[str, Result | Exception]:
    """Audit several domains at the same time (most of an audit is spent waiting for the network).

    Returns {domain: Result, or the exception that stopped its audit}, in the order given.
    on_done is called as each audit finishes, for progress messages.
    """
    from .collector import Collector

    Collector().preload_list()  # downloaded once, before the threads share it
    outcomes: dict[str, Result | Exception] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(run_audit, d): d for d in domains}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                outcome: Result | Exception = future.result()
            except Exception as e:  # noqa: BLE001 - reported per domain, the others go on
                outcome = e
            outcomes[domain] = outcome
            if on_done:
                on_done(domain, outcome)
    return {d: outcomes[d] for d in domains}
