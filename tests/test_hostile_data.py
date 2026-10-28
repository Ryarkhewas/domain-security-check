"""Data controlled by the audited servers must never act on the reports, the terminal or the alerts."""

from __future__ import annotations

import pytest

from domaincheck import alerts
from domaincheck.alerts import AlertError, send_webhook
from domaincheck.audit import run_audit
from domaincheck.ct import clean_names
from domaincheck.demo import DemoCollector
from domaincheck.i18n import printable
from domaincheck.models import CertificateInfo, HTTPInfo
from domaincheck.report import console_summary, render_html, render_index

EVIL = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'


class HostileCollector(DemoCollector):
    def http(self, host):
        return HTTPInfo(https_reachable=True, http_redirects_to_https=False,
                        headers={"Server": EVIL + "\x1b[2J\x1b]0;owned\x07", "X-Powered-By": EVIL},
                        content_type="text/html", body=f"<meta name='generator' content='WordPress {EVIL}'>")

    def certificate(self, host):
        return CertificateInfo(valid=True, issuer=EVIL, names=[host], tls_version="TLSv1.3")


def hostile():
    return run_audit("bakery-example.com", collector=HostileCollector())


def test_html_report_escapes_everything():
    html = render_html(hostile())
    assert "<script>" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "default-src 'none'" in html and 'name="referrer" content="no-referrer"' in html
    index = render_index([hostile()], {"bad.example": EVIL})
    assert "<script>" not in index and "default-src 'none'" in index


def test_pdf_report_escapes_markup():
    pytest.importorskip("reportlab")
    from domaincheck.pdf_report import render_pdf

    assert render_pdf(hostile()).startswith(b"%PDF")  # ReportLab markup in the data does not break or inject


def test_terminal_output_has_no_control_characters():
    out = console_summary(hostile())
    assert "\x1b" not in out and "\x07" not in out
    assert printable("a\x1b[31mb\x00c\nd") == "a[31mbc\nd"


def test_ct_names_must_be_host_names():
    raw = ["good.example.com", "evil/../x.example.com", "a@b.example.com", "with space.example.com",
           "http://x.example.com", "x.example.com:8080", "_dmarc.example.com", "-bad.example.com"]
    assert clean_names(raw, "example.com") == ["_dmarc.example.com", "good.example.com"]


def test_webhook_errors_never_show_the_url(monkeypatch):
    secret = "https://hooks.slack.com/services/T000/B000/SECRET-TOKEN"

    def down(url, **kwargs):
        raise alerts.requests.ConnectionError(f"HTTPSConnectionPool: Max retries exceeded with url: {url}")

    monkeypatch.setattr(alerts.requests, "post", down)
    with pytest.raises(AlertError) as e:
        send_webhook(secret, "body")
    assert "SECRET-TOKEN" not in str(e.value) and e.value.__cause__ is None

    class Refused:
        status_code = 403

        def raise_for_status(self):
            raise alerts.requests.HTTPError(f"403 Client Error for url: {secret}", response=self)

    monkeypatch.setattr(alerts.requests, "post", lambda url, **kw: Refused())
    with pytest.raises(AlertError, match="HTTP 403") as e:
        send_webhook(secret, "body")
    assert "SECRET-TOKEN" not in str(e.value)
