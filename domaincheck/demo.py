"""Fake collector to demonstrate the tool without network access.

The data represents an imaginary small business ("bakery-example.com") with
a typical setup: HTTPS in place, but poorly protected email.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import (
    CAAInfo,
    CertificateInfo,
    DNSSECInfo,
    HTTPInfo,
    MailServerInfo,
    MTASTSInfo,
    RDAPInfo,
    SecurityTxtInfo,
    SubdomainInfo,
    TLSScanInfo,
)

DEMO_DOMAIN = "bakery-example.com"


class DemoCollector:
    def txt(self, name: str) -> list[str]:
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=none"]
        return ["v=spf1 include:_spf.hosting-example.com ?all", "google-site-verification=abc123"]

    def mx(self, domain: str) -> list[str]:
        return ["mx1.hosting-example.com", "mx2.hosting-example.com"]

    def dkim_selectors(self, domain: str) -> list[str]:
        return []

    def certificate(self, host: str) -> CertificateInfo:
        return CertificateInfo(
            valid=True,
            expires_at=datetime.now(timezone.utc) + timedelta(days=21),
            issuer="Let's Encrypt",
            names=[host, f"www.{host}"],
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="RSA",
            key_bits=2048,
        )

    def mail_servers(self, mx: list[str]) -> list[MailServerInfo]:
        return [MailServerInfo(host, reachable=True, starttls=True, tls_version="TLSv1.3", cert_valid=True,
                               cert_expires=datetime.now(timezone.utc) + timedelta(days=60)) for host in mx]

    def ns(self, domain: str) -> list[str]:
        return ["dns110.ovh.net", "ns110.ovh.net"]

    def subdomains(self, domain: str) -> SubdomainInfo:
        # The shop moved in 2021, the old Azure app was deleted, its DNS record was forgotten
        names = [f"{n}.{domain}" for n in ("mail", "old-shop", "shop", "www")]
        return SubdomainInfo(names=names, source="crt.sh", resolving=[names[0], names[2], names[3]],
                             dangling=[(names[1], "bakery-shop-2019.azurewebsites.net")])

    def tls_scan(self, host: str) -> TLSScanInfo:
        # An old shared hosting configuration: TLS 1.0 and 1.1 still on
        return TLSScanInfo(versions={"SSLv3": False, "TLSv1": True, "TLSv1.1": True, "TLSv1.2": True,
                                     "TLSv1.3": True},
                           weak_ciphers=[], weak_tested=True, static_rsa=False)

    def http(self, host: str) -> HTTPInfo:
        return HTTPInfo(
            https_reachable=True,
            http_redirects_to_https=False,
            headers={
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3",
                "Content-Type": "text/html; charset=UTF-8",
                "X-Content-Type-Options": "nosniff",
            },
        )

    def dnssec(self, domain: str) -> DNSSECInfo:
        return DNSSECInfo(zone=domain)  # not enabled, as for most small businesses

    def caa(self, domain: str) -> CAAInfo:
        return CAAInfo()

    def mta_sts(self, domain: str) -> MTASTSInfo:
        return MTASTSInfo()

    def security_txt(self, host: str) -> SecurityTxtInfo:
        return SecurityTxtInfo()  # not published

    def rdap(self, domain: str) -> RDAPInfo:
        return RDAPInfo(domain=domain, expires=datetime.now(timezone.utc) + timedelta(days=200),
                        statuses=["active"], registrar="Example Registrar")  # no transfer lock
