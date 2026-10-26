"""Light checks of the subdomains in use (--subdomains)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from domaincheck import cli
from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.dns_checks import check_subdomain_audits
from domaincheck.models import Status, SubdomainAudit
from domaincheck.software import Cycle, Software

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)


def titles(findings):
    return {str(f.title): f for f in findings}


def test_nothing_to_check():
    assert check_subdomain_audits([], {}, NOW) == []


def test_all_good():
    audits = [SubdomainAudit("www.example.com", https=True, cert_valid=True, http=True, redirects=True),
              SubdomainAudit("mail.example.com")]
    (f,) = check_subdomain_audits(audits, {}, NOW)
    assert f.status == Status.OK and "2 subdomain(s) in use checked, 1 with a website" in f.detail


def test_problems_are_warnings_not_scored():
    audits = [
        SubdomainAudit("a.example.com", https=True, cert_valid=False, cert_error="self-signed certificate"),
        SubdomainAudit("b.example.com", https=True, cert_valid=True, cert_expires=NOW - timedelta(days=2)),
        SubdomainAudit("c.example.com", http=True, redirects=False),
        SubdomainAudit("d.example.com", https=True, cert_valid=True, http=True, redirects=False,
                       old_tls=["TLSv1", "TLSv1.1"]),
    ]
    f = titles(check_subdomain_audits(audits, {}, NOW))
    assert "a.example.com (self-signed certificate)" in f["Subdomains: HTTPS certificates"].detail
    assert "b.example.com (expired on 2026-10-24)" in f["Subdomains: HTTPS certificates"].detail
    assert "c.example.com" in f["Subdomains: no HTTPS"].detail
    assert "d.example.com" in f["Subdomains: HTTP to HTTPS redirect"].detail
    assert "d.example.com (TLS 1.0, TLS 1.1)" in f["Subdomains: obsolete TLS versions"].detail
    assert all(x.points is None for x in f.values())
    assert all(x.status == Status.WARNING for x in f.values())


def test_outdated_software_on_a_subdomain():
    audits = [SubdomainAudit("shop.example.com", https=True, cert_valid=True,
                             software=[Software("php", "7.4.3", "X-Powered-By"), Software("joomla", "", "tag")])]
    f = titles(check_subdomain_audits(audits, {"php": [Cycle("7.4", True)]}, NOW))
    assert f["Software on shop.example.com: PHP"].status == Status.CRITICAL
    assert not any("Joomla" in t for t in f)  # unknown version: not worth a line per subdomain


def test_off_by_default_and_grades_unchanged():
    plain = run_audit("bakery-example.com", collector=DemoCollector())
    full = run_audit("bakery-example.com", collector=DemoCollector(), subdomains=True)
    assert not any("Subdomains:" in str(f.title) for f in plain.findings)
    assert any("Subdomains:" in str(f.title) for f in full.findings)
    assert {k: g.score for k, g in plain.grades.items()} == {k: g.score for k, g in full.grades.items()}
    # no hosting fix for the subdomains: those describe the main site's platform
    assert all(f.fix is None for f in full.findings if "Subdomains:" in str(f.title))


def test_cli_option(tmp_path):
    out = tmp_path / "r.html"
    assert cli.main(["--demo", "--subdomains", "-o", str(out)]) == 0
    assert "Subdomains: obsolete TLS versions" in out.read_text(encoding="utf-8")
