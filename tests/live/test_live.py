"""Live tests against real domains (run with: python -m pytest -m live).

They need Internet access, so they are excluded from the regular test run and
executed by the "Live check" GitHub Actions workflow instead.

Two kinds of checks:
- badssl.com hosts, which are deliberately misconfigured for testing TLS
  clients, must be reported as critical by the certificate check;
- for well-known domains, the SPF and DMARC records read by our collector must
  match the ones returned by an independent resolver (Google DNS-over-HTTPS).
"""

from __future__ import annotations

import pytest
import requests

from domaincheck.audit import run_audit
from domaincheck.collector import Collector
from domaincheck.models import Category, Status

pytestmark = pytest.mark.live

REFERENCE_DOMAINS = ["github.com", "google.com", "cloudflare.com", "wikipedia.org"]


def doh_txt(name: str) -> list[str]:
    """TXT records from Google's public DNS-over-HTTPS API (independent source)."""
    r = requests.get("https://dns.google/resolve", params={"name": name, "type": "TXT"}, timeout=10)
    r.raise_for_status()
    answers = r.json().get("Answer", [])
    # DoH returns each record quoted, possibly split in several quoted chunks
    return sorted("".join(part for part in a["data"].split('"') if part.strip()) for a in answers if a["type"] == 16)


def certificate_finding(result):
    return next(f for f in result.findings if f.category == Category.WEB and f.title == "HTTPS certificate")


# --- Certificate problems are detected --------------------------------------
@pytest.mark.parametrize("host, expected_words", [
    ("expired.badssl.com", ["expired"]),
    ("self-signed.badssl.com", ["self", "signed"]),
    ("wrong.host.badssl.com", ["hostname", "mismatch"]),
    ("untrusted-root.badssl.com", ["certificate"]),
])
def test_bad_certificates_are_critical(host, expected_words):
    result = run_audit(host)
    finding = certificate_finding(result)
    assert finding.status == Status.CRITICAL, finding
    detail = finding.detail.lower()
    assert any(word in detail for word in expected_words), detail
    assert result.grade == "F" and result.cap_reason, result  # broken HTTPS caps the grade


def test_valid_certificate_is_ok():
    finding = certificate_finding(run_audit("badssl.com"))
    assert finding.status in (Status.OK, Status.WARNING), finding  # warning only if expiring soon


# --- DNS data matches an independent resolver --------------------------------
@pytest.mark.parametrize("domain", REFERENCE_DOMAINS)
def test_spf_matches_independent_resolver(domain):
    ours = sorted(t for t in Collector().txt(domain) if t.lower().startswith("v=spf1"))
    reference = [t for t in doh_txt(domain) if t.lower().startswith("v=spf1")]
    assert ours == reference


@pytest.mark.parametrize("domain", REFERENCE_DOMAINS)
def test_dmarc_matches_independent_resolver(domain):
    ours = sorted(t for t in Collector().txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1"))
    reference = [t for t in doh_txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    assert ours == reference


# --- End-to-end sanity on large, well-run domains ----------------------------
@pytest.mark.parametrize("domain", ["github.com", "google.com"])
def test_well_known_domains(domain):
    result = run_audit(domain)
    by_title = {f.title: f for f in result.findings}
    assert by_title["HTTPS certificate"].status == Status.OK
    assert by_title["SPF (authorized senders)"].status in (Status.OK, Status.WARNING)
    assert by_title["DMARC (anti-spoofing policy)"].status != Status.CRITICAL
    assert result.grade in "ABCDF"


@pytest.mark.parametrize("domain", ["github.com", "google.com"])
def test_http_redirect_and_hsts_seen_like_a_browser(domain):
    # google.com redirects browsers to HTTPS and sends HSTS (checked against
    # securityheaders.com), but not clients that look like bots: requests must
    # look like a browser to report what visitors actually get.
    by_title = {f.title: f for f in run_audit(domain).findings}
    assert by_title["HTTP to HTTPS redirect"].status == Status.OK, by_title["HTTP to HTTPS redirect"]
    assert by_title["HSTS"].status == Status.OK, by_title["HSTS"]


def test_subdomain_inherits_parent_dmarc():
    # A subdomain without its own DMARC record is covered by its parent's policy.
    sub, parent = "docs.github.com", "github.com"
    own_record = any(t.lower().startswith("v=dmarc1") for t in doh_txt(f"_dmarc.{sub}"))
    dmarc = next(f for f in run_audit(sub).findings if f.title == "DMARC (anti-spoofing policy)")
    assert dmarc.status != Status.CRITICAL, dmarc
    if not own_record:
        assert f"Inherited from {parent}" in dmarc.detail, dmarc
