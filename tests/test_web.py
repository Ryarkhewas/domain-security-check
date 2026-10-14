"""Website checks: each expected value is the Mozilla HTTP Observatory modifier."""

from datetime import datetime, timedelta, timezone

import pytest

from domaincheck.models import CertificateInfo, CookieInfo, HTTPInfo, Status
from domaincheck.tls_checks import check_certificate
from domaincheck.web_checks import (
    check_cookies,
    check_coop,
    check_corp,
    check_csp,
    check_hsts,
    check_redirection,
    check_referrer,
    check_sri,
    check_version_disclosure,
    check_website,
    check_xcto,
    check_xfo,
    meta_referrer,
    parse_csp,
)

NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


# --- Certificate & TLS --------------------------------------------------------
def cert(days, tls="TLSv1.3"):
    return CertificateInfo(valid=True, expires_at=NOW + timedelta(days=days), issuer="CA", tls_version=tls)


@pytest.mark.parametrize("days, status, points", [
    (-1, Status.CRITICAL, -100), (5, Status.CRITICAL, -30), (20, Status.WARNING, -10), (90, Status.OK, 0)])
def test_expiry(days, status, points):
    f = check_certificate(cert(days), NOW)[0]
    assert (f.status, f.points) == (status, points)


def test_certificate_missing_or_invalid():
    assert check_certificate(None)[0].points == -100
    f = check_certificate(CertificateInfo(valid=False, error="hostname mismatch"))
    assert f[0].status == Status.CRITICAL and "hostname mismatch" in f[0].detail


@pytest.mark.parametrize("tls, points", [("TLSv1", -30), ("TLSv1.1", -30), ("TLSv1.2", 0), ("TLSv1.3", 0)])
def test_tls_version(tls, points):
    f = check_certificate(cert(90, tls), NOW)
    assert next(x for x in f if x.title == "TLS protocol version").points == points


# --- Redirection --------------------------------------------------------------
@pytest.mark.parametrize("chain, final_https, points", [
    (["http://example.com/", "https://example.com/"], True, 0),
    (["http://example.com/", "http://www.example.com/", "https://www.example.com/"], True, -10),
    (["http://example.com/", "https://www.example.com/"], True, -5),
    (["http://example.com/"], False, -20),
    (["http://example.com/", "http://www.example.com/"], False, -20),
])
def test_redirection(chain, final_https, points):
    http = HTTPInfo(True, http_redirects_to_https=final_https, redirect_chain=chain)
    assert check_redirection(http, "example.com").points == points


def test_redirection_without_http_or_with_bad_cert():
    assert check_redirection(HTTPInfo(True, http_redirects_to_https=None), "example.com").points == 0
    bad = HTTPInfo(True, http_redirects_to_https=True, redirect_cert_error=True)
    assert check_redirection(bad, "example.com").points == -20


# --- HSTS ---------------------------------------------------------------------
@pytest.mark.parametrize("value, points", [
    (None, -20), ("max-age=31536000; includeSubDomains", 0), ("max-age=15552000", 0),
    ("max-age=300", -10), ("includeSubDomains", -20)])
def test_hsts(value, points):
    headers = {"Strict-Transport-Security": value} if value else {}
    assert check_hsts(headers).points == points


# --- CSP ----------------------------------------------------------------------
@pytest.mark.parametrize("policy, points", [
    ("default-src 'none'; script-src 'self'; style-src 'self'", 10),
    ("default-src 'self'", 5),
    ("default-src 'self'; style-src 'self' 'unsafe-inline'", 0),
    ("default-src 'self'; img-src http://cdn.example.com", -10),
    ("default-src 'self'; script-src 'self' 'unsafe-eval'", -10),
    ("default-src 'self'; script-src 'self' 'unsafe-inline'", -20),
    ("script-src 'self'", -20),  # object-src not restricted
    ("default-src 'self'; script-src https:", -20),
    ("default-src 'self'; script-src http://cdn.example.com", -20),
    ("default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-abc'", 5),  # nonce neutralises unsafe-inline
    ("default-src 'self'; script-src 'strict-dynamic'", -25),  # strict-dynamic without nonce: invalid
    ("default-src 'self'; script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'", 5),
    ("default-src 'self'; default-src 'none'", -25),  # duplicate directive: invalid
])
def test_csp(policy, points):
    assert check_csp({"Content-Security-Policy": policy}).points == points


def test_csp_missing_and_report_only():
    assert check_csp({}).points == -25
    f = check_csp({"Content-Security-Policy-Report-Only": "default-src 'self'"})
    assert f.points == -25 and "Report-Only" in f.detail


def test_parse_csp_empty_source_list_means_none():
    assert parse_csp("img-src; default-src 'self'")["img-src"] == {"'none'"}


# --- Simple headers -----------------------------------------------------------
@pytest.mark.parametrize("headers, points", [
    ({}, -20), ({"X-Frame-Options": "DENY"}, 5), ({"X-Frame-Options": "sameorigin"}, 5),
    ({"X-Frame-Options": "ALLOW-FROM https://a.com"}, 0), ({"X-Frame-Options": "nonsense"}, -20),
    ({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}, 5),
    ({"Content-Security-Policy": "default-src 'self'; frame-ancestors *"}, -20),
])
def test_xfo(headers, points):
    assert check_xfo(headers).points == points


@pytest.mark.parametrize("value, points", [(None, -5), ("nosniff", 0), ("yes", -5)])
def test_xcto(value, points):
    assert check_xcto({"X-Content-Type-Options": value} if value else {}).points == points


@pytest.mark.parametrize("value, points", [
    (None, 0), ("strict-origin-when-cross-origin", 5), ("no-referrer", 5), ("unsafe-url", -5),
    ("nonsense", -5), ("origin-when-cross-origin, strict-origin-when-cross-origin", 5),  # last known value wins
    ("no-referrer, unsafe-url", -5)])
def test_referrer(value, points):
    assert check_referrer({"Referrer-Policy": value} if value else {}).points == points


def test_isolation_headers():
    assert check_corp({}).points == 0
    assert check_corp({"Cross-Origin-Resource-Policy": "same-origin"}).points == 10
    assert check_corp({"Cross-Origin-Resource-Policy": "cross-origin"}).points == 0
    assert check_coop({"Cross-Origin-Opener-Policy": "same-origin-allow-popups; report-to=\"x\""}).points == 10
    assert check_coop({"Cross-Origin-Opener-Policy": "bogus"}).points == -5


def test_version_disclosure_is_not_scored():
    f = check_version_disclosure({"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"})
    assert f.points is None and "Apache/2.4.41" in f.detail
    assert check_version_disclosure({"Server": "nginx"}) is None


# --- Cookies ------------------------------------------------------------------
def c(name, secure=True, httponly=True, samesite="lax"):
    return CookieInfo(name, secure, httponly, samesite)


@pytest.mark.parametrize("cookies, hsts, points", [
    ([], False, 0),
    ([c("pref")], False, 5),
    ([c("pref", samesite=None)], False, 0),
    ([c("pref", secure=False)], True, -5),
    ([c("pref", secure=False)], False, -20),
    ([c("sessionid", secure=False)], True, -10),
    ([c("sessionid", secure=False)], False, -40),
    ([c("sessionid", httponly=False)], True, -30),
    ([c("csrftoken", samesite=None)], True, -20),
    ([c("pref", samesite="none", secure=False)], True, -20),
    ([c("pref"), c("loginhint", httponly=False)], True, -30),  # worst cookie wins
])
def test_cookies(cookies, hsts, points):
    assert check_cookies(cookies, hsts).points == points


# --- Whole website ------------------------------------------------------------
def test_website_without_https_only_checks_redirect():
    findings = check_website(HTTPInfo(False, http_redirects_to_https=False, redirect_chain=["http://x.com/"]), "x.com")
    assert [f.title for f in findings] == ["HTTP to HTTPS redirect"]


def test_website_full_set():
    http = HTTPInfo(True, headers={"Strict-Transport-Security": "max-age=31536000"},
                    http_redirects_to_https=True, redirect_chain=["http://x.com/", "https://x.com/"],
                    cookies=[c("sid", secure=False)])
    titles = [f.title for f in check_website(http, "x.com")]
    assert titles[:4] == ["HTTP to HTTPS redirect", "Content-Security-Policy", "Cookies", "HSTS"]
    cookies = next(f for f in check_website(http, "x.com") if f.title == "Cookies")
    assert cookies.points == -5  # not secure, but HSTS present


# --- HSTS preload list (Observatory: hsts-preloaded, redirection-all-redirects-preloaded)
def test_preloaded_hsts_overrides_the_header():
    f = check_hsts({}, preloaded=True)
    assert (f.points, f.source) == (5, "hsts-preload")
    assert check_hsts({}, preloaded=None).points == -20  # list unavailable: header only


def test_hsts_sent_twice_is_invalid():
    assert check_hsts({"Strict-Transport-Security": "max-age=31536000, max-age=31536000"}).points == -20


def test_preloaded_redirects_are_not_penalised():
    chain = ["http://example.com/", "https://www.example.com/"]  # off-host: -5 without preload
    plain = HTTPInfo(True, http_redirects_to_https=True, redirect_chain=chain)
    assert check_redirection(plain, "example.com").points == -5
    preloaded = HTTPInfo(True, http_redirects_to_https=True, redirect_chain=chain, redirects_preloaded=True)
    assert check_redirection(preloaded, "example.com").points == 0
    bad_cert = HTTPInfo(True, http_redirects_to_https=True, redirect_cert_error=True, redirects_preloaded=True)
    assert check_redirection(bad_cert, "example.com").points == -20  # certificate problems come first


def test_cookies_count_preloaded_hsts_as_protection():
    http = HTTPInfo(True, headers={}, http_redirects_to_https=True, redirect_chain=["http://x.com/", "https://x.com/"],
                    cookies=[c("pref", secure=False)], hsts_preloaded=True)
    cookies = next(f for f in check_website(http, "x.com") if f.title == "Cookies")
    assert cookies.points == -5


# --- Subresource Integrity (Observatory: subresource-integrity) ----------------
SRI = 'integrity="sha384-abc" crossorigin="anonymous"'


@pytest.mark.parametrize("html, points", [
    ("<p>no scripts</p>", 0),
    ("<script>inline()</script>", 0),
    ('<script src="/app.js"></script><script src="https://static.example.com/x.js"></script>', 0),
    (f'<script src="/app.js" {SRI}></script>', 5),
    (f'<script src="https://cdn.other.net/lib.js" {SRI}></script>', 5),
    ('<script src="https://cdn.other.net/lib.js"></script>', -5),
    (f'<script src="http://cdn.other.net/lib.js" {SRI}></script>', -20),
    ('<script src="http://cdn.other.net/lib.js"></script>', -50),
    ('<script src="//cdn.other.net/lib.js"></script>', -50),  # protocol-relative
    ('<script src="//static.example.com/lib.js"></script>', -50),  # even on the same domain
    (f'<script src="/a.js" {SRI}></script><script src="https://cdn.other.net/lib.js"></script>', -5),
    # the Observatory keeps the first problem unless a later one ranks after it in its list
    (f'<script src="http://a.net/x.js"></script><script src="http://b.net/y.js" {SRI}></script>', -50),
    (f'<script src="http://b.net/y.js" {SRI}></script><script src="https://a.net/x.js"></script>', -5),
])
def test_sri(html, points):
    assert check_sri(html, "text/html", "www.example.com").points == points


def test_sri_not_html_and_registrable_domain():
    assert check_sri("<script src='http://a.net/x.js'></script>", "application/json", "example.com").points == 0
    assert check_sri('<script src="https://cdn.bbc.co.uk/x.js"></script>', "", "www.bbc.co.uk").points == 0
    assert check_sri('<script src="https://other.co.uk/x.js"></script>', "", "www.bbc.co.uk").points == -5


# --- <meta name="referrer"> (read by browsers and by the Observatory) ----------
def test_meta_referrer_is_read():
    assert meta_referrer('<meta name="referrer" content="origin"><p>x</p>') == "origin"
    assert meta_referrer('<meta name="referrer" content="origin"><meta name="Referrer" content="no-referrer">') \
        == "no-referrer"
    assert meta_referrer('<meta name="description" content="x">') is None


def test_meta_referrer_applies_after_the_header():
    f = check_referrer({"Referrer-Policy": "strict-origin-when-cross-origin"}, "origin")
    assert f.points == -5 and "meta" in f.detail
    assert check_referrer({}, "no-referrer").points == 5
    assert check_referrer({"Referrer-Policy": "unsafe-url"}, None).points == -5
