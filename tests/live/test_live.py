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

from domaincheck.audit import audit_many, run_audit
from domaincheck.collector import Collector
from domaincheck.models import Category, Status

pytestmark = pytest.mark.live

REFERENCE_DOMAINS = ["github.com", "google.com", "cloudflare.com", "wikipedia.org"]
BAD_CERT_HOSTS = ["expired.badssl.com", "self-signed.badssl.com", "wrong.host.badssl.com", "untrusted-root.badssl.com"]
AUDITED = [*REFERENCE_DOMAINS, *BAD_CERT_HOSTS, "badssl.com", "docs.github.com", "gmail.com", "afnic.fr"]


_AUDITS: dict = {}


def audit(domain: str):
    """Each domain is audited once, whatever the number of tests that look at it."""
    if domain not in _AUDITS:
        try:
            _AUDITS[domain] = run_audit(domain, ct_logs=False)
        except Exception as e:  # noqa: BLE001 - kept, then raised again for the test that asked
            _AUDITS[domain] = e
    outcome = _AUDITS[domain]
    if isinstance(outcome, Exception):
        raise outcome
    return outcome


@pytest.fixture(scope="module", autouse=True)
def audit_in_parallel():
    """Audit every domain at the same time before the tests run (the network waits dominate)."""
    _AUDITS.update(audit_many(AUDITED, workers=8, ct_logs=False))  # CT logs: tested on their own below


def doh(name: str, rtype: str) -> list[dict]:
    """Answers from Google's public DNS-over-HTTPS API (independent source)."""
    r = requests.get("https://dns.google/resolve", params={"name": name, "type": rtype}, timeout=10)
    r.raise_for_status()
    return r.json().get("Answer", [])


def doh_txt(name: str) -> list[str]:
    answers = doh(name, "TXT")
    # DoH returns each record quoted, possibly split in several quoted chunks
    return sorted("".join(part for part in a["data"].split('"') if part.strip()) for a in answers if a["type"] == 16)


def certificate_finding(result):
    return next(f for f in result.findings if f.category == Category.TLS and f.title == "HTTPS certificate")


# --- Certificate problems are detected --------------------------------------
@pytest.mark.parametrize("host, expected_words", [
    ("expired.badssl.com", ["expired"]),
    ("self-signed.badssl.com", ["self", "signed"]),
    ("wrong.host.badssl.com", ["hostname", "mismatch"]),
    ("untrusted-root.badssl.com", ["certificate"]),
])
def test_bad_certificates_are_critical(host, expected_words):
    result = audit(host)
    finding = certificate_finding(result)
    assert finding.status == Status.CRITICAL, finding
    detail = finding.detail.lower()
    assert any(word in detail for word in expected_words), detail
    assert result.cap_reason, result
    assert result.grades["WEB"].grade == result.grades["TLS"].grade == result.grade == "F"


def test_valid_certificate_is_ok():
    finding = certificate_finding(audit("badssl.com"))
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
    result = audit(domain)
    by_title = {f.title: f for f in result.findings}
    assert by_title["HTTPS certificate"].status == Status.OK
    assert by_title["SPF (authorized senders)"].status in (Status.OK, Status.WARNING)
    assert by_title["DMARC (anti-spoofing policy)"].status != Status.CRITICAL
    assert result.grade[0] in "ABCDF"


@pytest.mark.parametrize("domain", ["github.com", "google.com"])
def test_http_redirect_and_hsts_seen_like_a_browser(domain):
    # Seen like a browser, both sites end on HTTPS and send HSTS. google.com
    # first redirects to http://www.google.com, which the Observatory scoring
    # penalises (-10): the redirect must end on HTTPS, with at most that penalty.
    by_title = {f.title: f for f in audit(domain).findings}
    assert by_title["HTTP to HTTPS redirect"].points >= -10, by_title["HTTP to HTTPS redirect"]
    assert by_title["HSTS"].status == Status.OK, by_title["HSTS"]


def test_subdomain_inherits_parent_dmarc():
    # A subdomain without its own DMARC record is covered by its parent's policy.
    sub, parent = "docs.github.com", "github.com"
    own_record = any(t.lower().startswith("v=dmarc1") for t in doh_txt(f"_dmarc.{sub}"))
    dmarc = next(f for f in audit(sub).findings if f.title == "DMARC (anti-spoofing policy)")
    assert dmarc.status != Status.CRITICAL, dmarc
    if not own_record:
        assert f"Inherited from {parent}" in dmarc.detail, dmarc


# --- Domain & DNS, MTA-STS ----------------------------------------------------
@pytest.mark.parametrize("domain", ["cloudflare.com", "github.com", "wikipedia.org"])
def test_dnssec_matches_independent_resolver(domain):
    signed = any(a["type"] == 43 for a in doh(domain, "DS"))  # 43 = DS
    dnssec = next(f for f in audit(domain).findings if f.title == "DNSSEC")
    assert dnssec.status == (Status.OK if signed else Status.WARNING), dnssec


def test_caa_found_on_google():
    caa = next(f for f in audit("google.com").findings if f.title.startswith("CAA"))
    assert caa.status == Status.OK and "pki.goog" in caa.detail, caa


def test_mta_sts_enforced_on_gmail():
    findings = {f.title: f for f in audit("gmail.com").findings}
    mta_sts = findings["MTA-STS (encrypted email delivery)"]
    assert mta_sts.status == Status.OK and "enforce" in mta_sts.detail, mta_sts
    assert findings["TLS reporting (TLS-RPT)"].status == Status.OK


# --- Registration (RDAP) and security.txt ------------------------------------
@pytest.mark.parametrize("domain", ["github.com", "google.com", "wikipedia.org", "afnic.fr"])
def test_registration_data_is_read(domain):
    findings = {f.title: f for f in audit(domain).findings}
    expiry = findings["Domain expiry date"]
    assert expiry.status == Status.OK and "is registered until" in expiry.detail, expiry


@pytest.mark.parametrize("domain", ["github.com", "google.com"])
def test_transfer_lock_is_seen_on_large_sites(domain):
    lock = {f.title: f for f in audit(domain).findings}["Transfer lock"]
    assert lock.status == Status.OK, lock


@pytest.mark.parametrize("domain", ["github.com", "google.com"])
def test_security_txt_is_found(domain):
    found = {f.title: f for f in audit(domain).findings}["security.txt (vulnerability reporting)"]
    assert found.status == Status.OK and "contact" in found.detail, found


def test_tls_scan_of_a_modern_site():
    r = audit("github.com")
    titles = {f.title: f for f in r.findings if f.category == Category.TLS}
    assert titles["Accepted TLS versions"].status == Status.OK
    assert titles["Weak cipher suites"].status == Status.OK
    assert titles["Certificate key"].status == Status.OK


def test_tls_1_0_is_seen():
    info = Collector().tls_scan("tls-v1-0.badssl.com", port=1010)
    assert info.versions["TLSv1"] is True


def test_3des_is_seen():
    info = Collector().tls_scan("3des.badssl.com")
    assert any("DES-CBC3" in suite for suite in info.weak_ciphers), info


def test_rsa_key_exchange_is_seen():
    info = Collector().tls_scan("static-rsa.badssl.com")
    assert info.static_rsa is True


def test_subdomains_are_read_from_ct_logs():
    info = Collector().subdomains("afnic.fr")
    if info.error and any(code in info.error for code in ("429", "500", "502", "503", "504", "timed out")):
        pytest.skip(f"CT log services unavailable: {info.error}")  # an outage of crt.sh is not a bug of the tool
    assert not info.error, info.error
    assert info.names and info.resolving
    assert all(name.endswith(".afnic.fr") for name in info.names)


def test_hosting_platforms_are_recognised():
    from domaincheck.hosting import detect

    c = Collector()
    assert detect({}, c.ns("cloudflare.com"), []).dns == "Cloudflare"
    assert detect({}, [], c.mx("gmail.com")).mail == "Google Workspace"


def test_gmail_mail_servers_offer_starttls():
    c = Collector()
    servers = c.mail_servers(c.mx("gmail.com")[:1])
    if not servers[0].reachable:
        pytest.skip(f"port 25 blocked from this network ({servers[0].error})")
    assert servers[0].starttls and servers[0].cert_valid and servers[0].tls_version in ("TLSv1.2", "TLSv1.3")


@pytest.mark.parametrize("product", ["php", "wordpress", "drupal", "joomla", "typo3"])
def test_support_dates_are_read(product):
    from domaincheck.software import load_cycles

    cycles = load_cycles(product)
    assert len(cycles) > 3 and any(c.eol is False or not isinstance(c.eol, bool) for c in cycles)
    assert any(c.latest for c in cycles)
