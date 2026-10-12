"""Fake collector to demonstrate the tool without network access.

The data represents an imaginary small business ("bakery-example.com") with
a typical setup: HTTPS in place, but poorly protected email.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import CertificateInfo, HTTPInfo

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
        )

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
