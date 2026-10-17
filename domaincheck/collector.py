"""Passive collection of a domain's public information.

Only requests that any visitor or mail server makes normally: DNS lookups,
TLS handshakes (including the first message of an old client's handshake, to
see which protocol versions and cipher suites are accepted), the home page (over HTTPS and HTTP) and robots.txt, like
Mozilla HTTP Observatory. No port scanning, no intrusion attempt.
"""

from __future__ import annotations

import contextlib
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import cast

import dns.dnssec
import dns.exception
import dns.name
import dns.resolver
import requests

from . import tls_scan as scan
from ._version import __version__
from .hsts_preload import PreloadList
from .i18n import M, Message
from .models import (
    CAAInfo,
    CertificateInfo,
    CookieInfo,
    DNSSECInfo,
    HTTPInfo,
    MTASTSInfo,
    RDAPInfo,
    SecurityTxtInfo,
    TLSScanInfo,
)
from .rdap import load_bootstrap, read_answer, server_for
from .web_checks import registrable_domain

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
    f"(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 domain-security-check/{__version__}"
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
            raise CollectionError(M("No DNS server configured on this machine.")) from e
        self.resolver.lifetime = timeout

    # --- DNS ---------------------------------------------------------------
    def _resolve(self, name: str, rtype: str, resolver: dns.resolver.Resolver | None = None):
        """Return the answer, or None if the record does not exist.

        Raise CollectionError when it cannot be known (outage, timeout).
        """
        try:
            return (resolver or self.resolver).resolve(name, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise CollectionError(M("DNS resolution failed for {name} ({rtype}): check your connection.",
                                    name=str(name), rtype=rtype)) from e

    def check_exists(self, domain: str) -> None:
        try:
            self.resolver.resolve(domain, "SOA", search=False)
        except dns.resolver.NXDOMAIN as e:
            raise DomainNotFound(
                M("The domain {domain} does not exist (or your network filters DNS queries).", domain=domain)
            ) from e
        except dns.resolver.NoAnswer:
            return  # subdomain (e.g. www): it exists but has no SOA of its own
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise CollectionError(M("DNS resolution failed for {domain}: check your connection.", domain=domain)) from e

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

    def dnssec(self, domain: str) -> DNSSECInfo:
        """DS (in the parent zone) and DNSKEY records of the zone containing the domain.

        Some local resolvers (systemd-resolved, some routers) refuse DS and
        DNSKEY queries. In that case the query is retried through public
        resolvers before reporting that DNSSEC could not be checked.
        """
        try:
            return self._dnssec(domain, self.resolver)
        except (CollectionError, dns.exception.DNSException) as first:
            try:
                return self._dnssec(domain, _public_resolver(self.timeout))
            except (CollectionError, dns.exception.DNSException):
                return DNSSECInfo(error=_short(first))

    def _dnssec(self, domain: str, resolver: dns.resolver.Resolver) -> DNSSECInfo:
        zone = dns.resolver.zone_for_name(domain, resolver=resolver)
        ds = self._resolve(zone.to_text(), "DS", resolver)
        keys = self._resolve(zone.to_text(), "DNSKEY", resolver)
        info = DNSSECInfo(zone=zone.to_text().rstrip("."), ds_count=len(ds) if ds else 0,
                          dnskey_count=len(keys) if keys else 0)
        if ds and keys:
            info.ds_matches = _ds_matches(zone, ds, keys)
        return info

    def caa(self, domain: str) -> CAAInfo:
        """CAA records of the domain, or of its closest parent that has some (RFC 8659 section 3)."""
        labels = domain.split(".")
        try:
            for i in range(len(labels) - 1):  # never the top-level domain itself
                name = ".".join(labels[i:])
                answer = self._resolve(name, "CAA")
                if answer:
                    records = [(r.flags, r.tag.decode("ascii", "replace"), r.value.decode("utf-8", "replace"))
                               for r in answer]
                    return CAAInfo(records, name)
        except CollectionError as e:
            return CAAInfo(error=_short(e))
        return CAAInfo()

    def mta_sts(self, domain: str) -> MTASTSInfo:
        """MTA-STS record and policy file, and the TLS reporting record."""
        info = MTASTSInfo(txt=self.txt(f"_mta-sts.{domain}"), tls_rpt=self.txt(f"_smtp._tls.{domain}"))
        if not any(t.lower().replace(" ", "").startswith("v=stsv1") for t in info.txt):
            return info
        try:
            # RFC 8461: the policy must be served over valid HTTPS, without redirects
            r = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", headers=dict(BROWSER_HEADERS),
                             timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as e:
            info.error = _short(e)
            return info
        if r.status_code != 200:
            info.error = f"HTTP {r.status_code}"
        else:
            info.policy = r.text[:65_536]
        return info

    def security_txt(self, host: str) -> SecurityTxtInfo:
        """security.txt at its standard place (/.well-known/), or at the old one (/security.txt)."""
        last_error = ""
        for path in ("/.well-known/security.txt", "/security.txt"):
            url = f"https://{host}{path}"
            try:
                r = requests.get(url, headers={**BROWSER_HEADERS, "Accept": "text/plain"}, timeout=self.timeout,
                                 allow_redirects=True)
            except requests.RequestException as e:
                last_error = _short(e)
                continue
            content_type = (r.headers.get("Content-Type") or "").lower()
            # Many sites answer 200 with an HTML page for any address: only a text file counts
            if r.status_code == 200 and content_type.startswith("text/plain"):
                return SecurityTxtInfo(url=url, content=r.text[:32_768])
        return SecurityTxtInfo(error=last_error)

    def rdap(self, domain: str) -> RDAPInfo:
        """Expiry date, status and registrar of the registrable domain, from its registry (RDAP)."""
        registered = registrable_domain(domain) or domain
        info = RDAPInfo(domain=registered)
        try:
            servers = load_bootstrap(self.timeout * 2)
        except (requests.RequestException, OSError, ValueError) as e:
            info.error = _short(e)
            return info
        base = server_for(registered, servers)
        if not base:
            info.error = M("no RDAP server for this extension")
            return info
        try:
            r = requests.get(f"{base.rstrip('/')}/domain/{registered}", timeout=self.timeout * 2,
                             headers={"Accept": "application/rdap+json, application/json",
                                      "User-Agent": BROWSER_HEADERS["User-Agent"]})
        except requests.RequestException as e:
            info.error = _short(e)
            return info
        if r.status_code != 200:
            info.error = f"HTTP {r.status_code}"
            return info
        try:
            info.expires, info.statuses, info.registrar = read_answer(r.json())
        except ValueError:
            info.error = M("unreadable answer")
        return info

    # --- TLS ---------------------------------------------------------------
    def certificate(self, host: str) -> CertificateInfo | None:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443), timeout=self.timeout) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version() or ""
                cipher = (tls.cipher() or ("", "", 0))[0]
                der = tls.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError as e:
            return CertificateInfo(valid=False, error=_ssl_error(e.verify_message or str(e)))
        except (OSError, ssl.SSLError):
            return None
        if not cert:
            return None

        not_after = cert.get("notAfter")
        expires = (datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
                   if isinstance(not_after, str) else None)
        # getpeercert() fields, as documented in the ssl module
        rdns = cast("tuple[tuple[tuple[str, str], ...], ...]", cert.get("issuer", ()))
        issuer = {key: value for rdn in rdns for key, value in rdn}
        alt_names = cast("tuple[tuple[str, str], ...]", cert.get("subjectAltName", ()))
        names = [value for key, value in alt_names if key == "DNS"]
        return CertificateInfo(
            valid=True,
            expires_at=expires,
            issuer=issuer.get("organizationName") or issuer.get("commonName", ""),
            names=names,
            tls_version=version,
            cipher=cipher,
            **_public_key(der),
        )

    def tls_scan(self, host: str, port: int = 443) -> TLSScanInfo:
        """Accepted protocol versions and cipher suites (one short connection each)."""
        info = TLSScanInfo()

        def version(v: int) -> bool | None:
            try:
                hello = scan.probe(host, v, scan.VERSION_PROBE_SUITES, timeout=self.timeout, port=port)
            except OSError:
                return None
            return hello.accepted and hello.version == v

        with ThreadPoolExecutor(max_workers=6) as pool:
            legacy = {name: pool.submit(version, v) for v, name in scan.VERSION_NAMES.items()}
            tls13 = pool.submit(scan.accepts_tls13, host, self.timeout, port)
            weak = pool.submit(self._accepted_suites, host, scan.WEAK_SUITES, port)
            static_rsa = pool.submit(self._accepted_suites, host, scan.STATIC_RSA_SUITES, port)
            info.versions = {name: f.result() for name, f in legacy.items()}
            info.versions["TLSv1.3"] = tls13.result()
            weak_suites, static_suites = weak.result(), static_rsa.result()
        if all(v is None for v in info.versions.values()):
            info.error = M("the server did not answer the test connections")
        if weak_suites is not None:
            info.weak_ciphers, info.weak_tested = weak_suites, True
        if static_suites is not None:
            info.static_rsa = bool(static_suites)
        return info

    def _accepted_suites(self, host: str, suites: dict[int, str], port: int = 443) -> list[str] | None:
        """Names of the given suites the server accepts with TLS 1.2 or older, None if it could not be tested."""
        offered, accepted = list(suites), list[str]()
        while offered:
            try:
                hello = scan.probe(host, scan.TLS12, offered, timeout=self.timeout, port=port)
            except OSError:
                return accepted or None
            if not hello.accepted or hello.cipher not in offered:
                break
            accepted.append(suites[hello.cipher])
            offered.remove(hello.cipher)
        return accepted

    # --- HTTP --------------------------------------------------------------
    def http(self, host: str) -> HTTPInfo:
        # Like a browser (and the Observatory), cookies are collected across the
        # redirects and robots.txt, not only from the final page.
        https = requests.Session()
        try:
            r = https.get(f"https://{host}", headers=dict(BROWSER_HEADERS), timeout=self.timeout,
                          allow_redirects=True)
            content_type = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            info = HTTPInfo(https_reachable=True, headers=dict(r.headers), content_type=content_type,
                            body=_page_text(r, content_type))
            with contextlib.suppress(requests.RequestException):  # robots.txt is optional
                https.get(f"https://{host}/robots.txt", headers={**BROWSER_HEADERS, "Accept": "text/plain,*/*;q=0.8"},
                          timeout=self.timeout, allow_redirects=True)
            info.cookies = _cookies(https.cookies)
        except requests.RequestException as e:
            info = HTTPInfo(https_reachable=False, error=str(e))

        try:
            r = requests.Session().get(f"http://{host}", headers=dict(BROWSER_HEADERS), timeout=self.timeout,
                                       allow_redirects=True)
            info.redirect_chain = [h.url for h in getattr(r, "history", [])] + [r.url]
            info.http_redirects_to_https = r.url.startswith("https://")
        except requests.exceptions.SSLError:
            # Redirected to HTTPS, but the certificate is a problem: the redirect does exist.
            info.http_redirects_to_https = True
            info.redirect_cert_error = True
        except requests.RequestException:
            info.http_redirects_to_https = None

        preload = self.preload_list()
        if preload is not None:
            info.hsts_preloaded = preload.covers(host)
            hosts = [_url_host(u) for u in info.redirect_chain] or [host]
            info.redirects_preloaded = all(preload.covers(h) for h in hosts)
        return info

    def preload_list(self) -> PreloadList | None:
        """HSTS preload list, loaded once per run; None if it cannot be obtained."""
        if Collector._preload is None:
            try:
                Collector._preload = PreloadList.load()
            except (requests.RequestException, OSError, ValueError):
                Collector._preload = False
        return Collector._preload if isinstance(Collector._preload, PreloadList) else None

    _preload: PreloadList | bool | None = None  # None: not loaded yet; False: unavailable


PUBLIC_RESOLVERS = ["1.1.1.1", "9.9.9.9", "8.8.8.8"]  # Cloudflare, Quad9, Google


def _public_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(PUBLIC_RESOLVERS)
    resolver.lifetime = timeout
    return resolver


def _ds_matches(zone: dns.name.Name, ds_set, key_set) -> bool | None:
    """True if a DS record is the digest of one of the zone's keys; None if no comparison was possible."""
    compared = False
    for ds in ds_set:
        for key in key_set:
            if key.algorithm != ds.algorithm or dns.dnssec.key_id(key) != ds.key_tag:
                continue
            try:
                if dns.dnssec.make_ds(zone, key, ds.digest_type) == ds:
                    return True
                compared = True
            except (dns.dnssec.UnsupportedAlgorithm, dns.dnssec.DeniedByPolicy, ValueError):
                continue
    return False if compared else None


# Usual certificate errors (OpenSSL wording), so that the report can translate them
_SSL_ERRORS = {
    "certificate has expired": M("certificate has expired"),
    "certificate is not yet valid": M("certificate is not yet valid"),
    "self-signed certificate": M("self-signed certificate"),
    "self signed certificate": M("self-signed certificate"),
    "self-signed certificate in certificate chain": M("self-signed certificate in certificate chain"),
    "self signed certificate in certificate chain": M("self-signed certificate in certificate chain"),
    "unable to get local issuer certificate": M("unable to get local issuer certificate"),
}


def _public_key(der: bytes | None) -> dict:
    """{"key_type": ..., "key_bits": ...} of a DER certificate, empty when it cannot be read."""
    if not der:
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

        key = x509.load_der_x509_certificate(der).public_key()
    except (ImportError, ValueError):
        return {}
    if isinstance(key, rsa.RSAPublicKey):
        return {"key_type": "RSA", "key_bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"key_type": "EC", "key_bits": key.curve.key_size}
    if isinstance(key, dsa.DSAPublicKey):
        return {"key_type": "DSA", "key_bits": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"key_type": "Ed25519", "key_bits": 256}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"key_type": "Ed448", "key_bits": 456}
    return {}


def _ssl_error(text: str) -> str:
    mismatch = re.match(r"Hostname mismatch, certificate is not valid for '(.+?)'\.?$", text)
    if mismatch:
        return M("hostname mismatch: the certificate is not valid for '{host}'", host=mismatch.group(1))
    return _SSL_ERRORS.get(text.strip().lower(), text)


def _short(error: Exception) -> str:
    """First line of an error message, for the report."""
    if error.args and isinstance(error.args[0], Message):
        return error.args[0]  # keeps its translation
    text = str(error).strip().split("\n")[0]
    return text[:200] or type(error).__name__


MAX_PAGE_SIZE = 2_000_000
HTML_TYPES = {"text/html", "application/xhtml+xml"}


def _page_text(response, content_type: str) -> str:
    """Home page HTML (to look at its scripts); empty for other content types."""
    if content_type and content_type not in HTML_TYPES:
        return ""
    content = getattr(response, "content", b"") or b""
    try:
        return content[:MAX_PAGE_SIZE].decode(getattr(response, "encoding", None) or "utf-8", "replace")
    except LookupError:  # unknown charset announced by the server
        return content[:MAX_PAGE_SIZE].decode("utf-8", "replace")


def _url_host(url: str) -> str:
    return url.split("://", 1)[-1].split("/")[0].split(":")[0].lower()


def _cookies(jar) -> list[CookieInfo]:
    """Cookies set while loading the home page, with their security attributes."""
    if jar is None:
        return []
    cookies = []
    for c in jar:
        rest = {k.lower(): v for k, v in getattr(c, "_rest", {}).items()}
        samesite = rest.get("samesite")
        cookies.append(CookieInfo(
            name=c.name,
            secure=bool(c.secure),
            httponly="httponly" in rest,
            samesite=samesite.lower() if isinstance(samesite, str) else None,
        ))
    return cookies
