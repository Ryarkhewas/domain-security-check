"""Fixes adapted to the hosting platform."""

from __future__ import annotations

import pytest

from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.hosting import Platforms, add_fixes, detect, fix_for
from domaincheck.i18n import M
from domaincheck.models import Category, Finding, Status
from domaincheck.report import render_html


@pytest.mark.parametrize("headers, web", [
    ({"Server": "Apache/2.4.41 (Ubuntu)"}, "apache"),
    ({"server": "nginx"}, "nginx"),
    ({"Server": "Microsoft-IIS/10.0"}, "iis"),
    ({"Server": "LiteSpeed"}, "litespeed"),
    ({"Server": "cloudflare", "CF-RAY": "1"}, "cloudflare"),
    ({"Server": "nginx", "CF-RAY": "1"}, "cloudflare"),  # Cloudflare in front of nginx: the edge answers
    ({"Server": "Netlify", "X-NF-Request-ID": "1"}, "netlify"),
    ({"Server": "Vercel"}, "vercel"),
    ({"Server": "GitHub.com"}, "github-pages"),
    ({}, ""),
])
def test_web_platform(headers, web):
    assert detect(headers, [], []).web == web


def test_github_itself_is_not_github_pages():
    assert detect({"Server": "GitHub.com"}, [], [], "docs.github.com").web == ""


def test_dns_and_mail_providers():
    p = detect({}, ["dns110.ovh.net", "ns110.ovh.net"], ["aspmx.l.google.com", "alt1.aspmx.l.google.com"])
    assert (p.dns, p.mail) == ("OVHcloud", "Google Workspace")
    assert detect({}, ["ns-123.awsdns-45.com"], ["example-com.mail.protection.outlook.com"]).dns == "Amazon Route 53"
    assert detect({}, ["ns-123.awsdns-45.com"], ["example-com.mail.protection.outlook.com"]).mail == "Microsoft 365"
    assert detect({}, ["lara.ns.cloudflare.com"], []).dns == "Cloudflare"
    assert detect({}, ["ns1.example.net"], ["mx.example.net"]) == Platforms("", "", "")


def finding(source, detail="Missing: something.", status=Status.WARNING):
    return Finding(Category.WEB, "x", status, M(detail) if detail.startswith("Missing") else detail, "Do it.", -5,
                   source)


def test_header_lines_per_server():
    assert fix_for(finding("hsts"), Platforms("apache")).text == \
        'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'
    assert fix_for(finding("xcto"), Platforms("nginx")).text == 'add_header X-Content-Type-Options "nosniff" always;'
    assert fix_for(finding("xfo"), Platforms("iis")).text == '<add name="X-Frame-Options" value="SAMEORIGIN" />'
    assert "/*\n  Referrer-Policy:" in fix_for(finding("referrer"), Platforms("netlify")).text
    assert fix_for(finding("xfo"), Platforms("vercel")).link.startswith("https://vercel.com/")
    assert fix_for(finding("hsts"), Platforms("cloudflare")).link.endswith("http-strict-transport-security/")
    assert fix_for(finding("xfo"), Platforms("")) is None


def test_csp_line_only_when_the_policy_is_missing():
    fix = fix_for(finding("csp"), Platforms("nginx"))
    assert fix.code and "Content-Security-Policy-Report-Only" in fix.text
    assert fix_for(finding("csp", "Present, but unsafe: 'unsafe-inline'."), Platforms("nginx")) is None


def test_redirect_tls_and_versions():
    assert "RewriteRule" in fix_for(finding("redirection"), Platforms("apache")).text
    assert fix_for(finding("redirection"), Platforms("nginx")).text == "return 301 https://$host$request_uri;"
    assert fix_for(finding("rfc8996"), Platforms("nginx")).text == "ssl_protocols TLSv1.2 TLSv1.3;"
    assert fix_for(finding("tls13"), Platforms("apache")).text == "SSLProtocol -all +TLSv1.2 +TLSv1.3"
    assert fix_for(finding("rfc9325"), Platforms("nginx")).link == "https://ssl-config.mozilla.org/"
    assert fix_for(finding("owasp-headers"), Platforms("nginx")).text == "server_tokens off;"


def test_email_and_dns_providers():
    assert "Authenticate email" in fix_for(finding("dkim"), Platforms(mail="Google Workspace")).text
    assert "DKIM" in fix_for(finding("dkim"), Platforms(mail="Microsoft 365")).text
    assert fix_for(finding("dkim"), Platforms()) is None
    assert fix_for(finding("dnssec"), Platforms(dns="Cloudflare")).link == "https://developers.cloudflare.com/dns/dnssec/"
    assert "OVHcloud" in fix_for(finding("spf"), Platforms(dns="OVHcloud")).label
    assert fix_for(finding("spf"), Platforms()) is None


def test_compliant_items_get_no_fix():
    f = finding("hsts", "Present.", Status.OK)
    add_fixes([f], Platforms("nginx"))
    assert f.fix is None


def test_demo_report_shows_the_fixes():
    r = run_audit("bakery-example.com", collector=DemoCollector())
    html = render_html(r)
    assert 'class="howto"' in html
    assert "Header always set Strict-Transport-Security" in html  # demo site runs Apache
    assert "On OVHcloud:" in html  # demo DNS zone at OVHcloud
    fr = render_html(r, lang="fr")
    assert "Chez OVHcloud :" in fr and "Sur Apache (.htaccess) :" in fr
