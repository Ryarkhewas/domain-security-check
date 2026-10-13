"""Passive collection of a domain's public information.

Only requests that any visitor or mail server makes normally: DNS lookups,
a TLS handshake and one GET request on the home page. No port scanning, no
intrusion attempt.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import requests

from .models import CertificateInfo, HTTPInfo

DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "protonmail", "sib",
]
TIMEOUT = 8
# Some sites (Google, for instance) answer differently to bots and to browsers:
# no HTTPS redirect, missing security headers... To report what a real visitor
# gets, requests look like a current desktop browser. The tool's name is kept
# at the end so it remains identifiable in server logs.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 domain-security-check/1.1"
)
BROWSER_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
}


class CollectionError(RuntimeError):
    """A check could not be performed (network or DNS failure...).

    Not to be confused with "the record does not exist": concluding
    "no SPF" when the query actually failed would be a false diagnosis.
    """


class DomainNotFound(RuntimeError):
    pass


class Collector:
    def __init__(self, timeout: float = TIMEOUT):
        self.timeout = timeout
        try:
            self.resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration as e:
            raise CollectionError("No DNS server configured on this machine.") from e
        self.resolver.lifetime = timeout

    # --- DNS ---------------------------------------------------------------
    def _resolve(self, name: str, rtype: str):
        """Return the answer, or None if the record does not exist.

        Raise CollectionError when it cannot be known (outage, timeout).
        """
        try:
            return self.resolver.resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise CollectionError(f"DNS resolution failed for {name} ({rtype}): check your connection.") from e

    def check_exists(self, domain: str) -> None:
        try:
            self.resolver.resolve(domain, "SOA", search=False)
        except dns.resolver.NXDOMAIN as e:
            raise DomainNotFound(
                f"The domain {domain} does not exist (or your network filters DNS queries)."
            ) from e
        except dns.resolver.NoAnswer:
            return  # subdomain (e.g. www): it exists but has no SOA of its own
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise CollectionError(f"DNS resolution failed for {domain}: check your connection.") from e

    def txt(self, name: str) -> list[str]:
        answer = self._resolve(name, "TXT")
        if answer is None:
            return []
        return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]

    def mx(self, domain: str) -> list[str]:
        answer = self._resolve(domain, "MX")
        if answer is None:
            return []
        return [str(r.exchange).rstrip(".") for r in sorted(answer, key=lambda r: r.preference)]

    def dkim_selectors(self, domain: str) -> list[str]:
        found = []
        for sel in DKIM_SELECTORS:
            if any("p=" in t for t in self.txt(f"{sel}._domainkey.{domain}")):
                found.append(sel)
        return found

    # --- TLS ---------------------------------------------------------------
    def certificate(self, host: str) -> CertificateInfo | None:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version() or ""
        except ssl.SSLCertVerificationError as e:
            return CertificateInfo(valid=False, error=e.verify_message or str(e))
        except (OSError, ssl.SSLError):
            return None

        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        names = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        return CertificateInfo(
            valid=True,
            expires_at=expires,
            issuer=issuer.get("organizationName") or issuer.get("commonName", ""),
            names=names,
            tls_version=version,
        )

    # --- HTTP --------------------------------------------------------------
    def http(self, host: str) -> HTTPInfo:
        headers = dict(BROWSER_HEADERS)
        try:
            r = requests.get(f"https://{host}", headers=headers, timeout=self.timeout, allow_redirects=True)
            info = HTTPInfo(https_reachable=True, headers=dict(r.headers))
        except requests.RequestException as e:
            info = HTTPInfo(https_reachable=False, error=str(e))

        try:
            r = requests.get(f"http://{host}", headers=headers, timeout=self.timeout, allow_redirects=True)
            info.http_redirects_to_https = r.url.startswith("https://")
        except requests.exceptions.SSLError:
            # Redirected to HTTPS, but the certificate is a problem: the redirect does exist.
            info.http_redirects_to_https = True
        except requests.RequestException:
            info.http_redirects_to_https = None
        return info
