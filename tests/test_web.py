from datetime import datetime, timedelta, timezone

import pytest

from domaincheck.models import CertificateInfo, HTTPInfo, Status
from domaincheck.web_checks import check_certificate, check_headers, check_redirect

NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


def cert(days, tls="TLSv1.3"):
    return CertificateInfo(valid=True, expires_at=NOW + timedelta(days=days), issuer="CA", tls_version=tls)


@pytest.mark.parametrize("days, expected", [(-1, Status.CRITICAL), (5, Status.CRITICAL), (20, Status.WARNING), (90, Status.OK)])
def test_expiry(days, expected):
    assert check_certificate(cert(days), NOW)[0].status == expected


def test_certificate_missing_or_invalid():
    assert check_certificate(None)[0].status == Status.CRITICAL
    f = check_certificate(CertificateInfo(valid=False, error="hostname mismatch"))
    assert f[0].status == Status.CRITICAL and "hostname mismatch" in f[0].detail


@pytest.mark.parametrize("tls, expected", [("TLSv1", Status.CRITICAL), ("TLSv1.1", Status.CRITICAL), ("TLSv1.2", Status.OK), ("TLSv1.3", Status.OK)])
def test_tls_version(tls, expected):
    f = check_certificate(cert(90, tls), NOW)
    assert next(x for x in f if x.title == "TLS protocol version").status == expected


def test_redirect():
    assert check_redirect(HTTPInfo(True, http_redirects_to_https=True))[0].status == Status.OK
    assert check_redirect(HTTPInfo(True, http_redirects_to_https=False))[0].status == Status.WARNING
    assert check_redirect(HTTPInfo(True, http_redirects_to_https=None))[0].status == Status.INFO


def by_title(findings):
    return {f.title: f.status for f in findings}


def test_all_headers_present():
    r = by_title(check_headers({
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "Server": "nginx",
    }))
    assert all(s == Status.OK for s in r.values()), r
    assert "Software version disclosure" not in r


def test_headers_missing():
    r = by_title(check_headers({}))
    for title in ("HSTS", "Content-Security-Policy", "Clickjacking protection", "X-Content-Type-Options"):
        assert r[title] == Status.WARNING
    assert r["Referrer-Policy"] == Status.INFO and r["Permissions-Policy"] == Status.INFO


def test_hsts_too_short():
    assert by_title(check_headers({"Strict-Transport-Security": "max-age=300"}))["HSTS"] == Status.WARNING


def test_csp_unsafe_inline():
    r = by_title(check_headers({"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}))
    assert r["Content-Security-Policy"] == Status.INFO


def test_xfo_is_enough_against_clickjacking():
    assert by_title(check_headers({"X-Frame-Options": "sameorigin"}))["Clickjacking protection"] == Status.OK


def test_version_disclosure():
    f = check_headers({"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4"})
    leak = next(x for x in f if x.title == "Software version disclosure")
    assert "Apache/2.4.41" in leak.detail and "PHP/7.4" in leak.detail
