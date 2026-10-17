"""Certificate and TLS checks.

There is no public scoring standard for these (SSL Labs' rating needs a full
handshake scan), so the points below are this project's own, based on RFC 8996
(TLS 1.0 and 1.1 are deprecated) and on certificate validity.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .i18n import Date, M
from .models import Category, CertificateInfo, Finding, Status, TLSScanInfo
from .tls_scan import has_forward_secrecy

T = Category.TLS


def check_certificate(cert: CertificateInfo | None, now: datetime | None = None) -> list[Finding]:
    title = "HTTPS certificate"
    if cert is None:
        return [Finding(T, title, Status.CRITICAL, "Could not establish an HTTPS connection on port 443.",
                        "Install a certificate (Let's Encrypt is free) and enable HTTPS.", -100, "tls-guide")]
    if not cert.valid:
        return [Finding(T, title, Status.CRITICAL,
                        M("The certificate is not recognised as valid: {error}. Browsers show a warning to visitors.",
                          error=cert.error or M("unknown error")),
                        "Replace it with a valid certificate covering this domain name.", -100, "tls-guide")]

    findings: list[Finding] = []
    now = now or datetime.now(timezone.utc)
    if cert.expires_at:
        days = (cert.expires_at - now).days
        date_txt = Date(cert.expires_at)
        if days < 0:
            findings.append(Finding(T, title, Status.CRITICAL, M("Certificate expired on {date}.", date=date_txt),
                                    "Renew the certificate immediately.", -100, "tls-guide"))
        elif days < 15:
            findings.append(Finding(T, title, Status.CRITICAL,
                                    M("The certificate expires in {days} day(s) ({date}).", days=days, date=date_txt),
                                    "Renew it now and set up automatic renewal.", -30, "tls-guide"))
        elif days < 30:
            findings.append(Finding(T, title, Status.WARNING,
                                    M("The certificate expires in {days} days ({date}).", days=days, date=date_txt),
                                    "Check that automatic renewal is in place.", -10, "tls-guide"))
        else:
            issuer = M(", issued by {issuer}", issuer=cert.issuer) if cert.issuer else ""
            findings.append(Finding(T, title, Status.OK,
                                    M("Certificate valid until {date} ({days} days){issuer}.", date=date_txt, days=days,
                                      issuer=issuer),
                                    points=0, source="tls-guide"))

    if cert.tls_version:
        if cert.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(Finding(
                T, "TLS protocol version", Status.CRITICAL,
                M("Connection negotiated with {version}, an obsolete and vulnerable version.",
                  version=cert.tls_version),
                "Disable TLS 1.0/1.1 on the server and only allow TLS 1.2 and 1.3.", -30, "rfc8996"))
        else:
            findings.append(Finding(T, "TLS protocol version", Status.OK,
                                    M("Connection negotiated with {version}.", version=cert.tls_version),
                                    points=0, source="rfc8996"))
    return findings


# --- Accepted versions and cipher suites -------------------------------------------
OBSOLETE = ["SSLv3", "TLSv1", "TLSv1.1"]
VERSION_LABELS = {"SSLv3": "SSL 3.0", "TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1", "TLSv1.2": "TLS 1.2",
                  "TLSv1.3": "TLS 1.3"}


def check_tls_scan(scan: TLSScanInfo, cert: CertificateInfo | None) -> list[Finding]:
    """Protocol versions and cipher suites accepted by the server, and the certificate's key."""
    findings: list[Finding] = []
    if scan.error:
        return [Finding(T, "Accepted TLS versions", Status.INFO, M("Could not be checked ({error}).", error=scan.error),
                        points=None, source="rfc8996")]
    findings += _versions(scan)
    findings += _ciphers(scan, cert)
    if cert is not None and cert.valid and cert.key_type:
        findings.append(_key(cert))
    return findings


def _versions(scan: TLSScanInfo) -> list[Finding]:
    findings = []
    title = "Accepted TLS versions"
    old = [VERSION_LABELS[v] for v in OBSOLETE if scan.versions.get(v)]
    accepted = ", ".join(VERSION_LABELS[v] for v in VERSION_LABELS if scan.versions.get(v))
    if scan.versions.get("SSLv3"):
        findings.append(Finding(T, title, Status.CRITICAL,
                                M("The server still accepts SSL 3.0, broken since 2014 (POODLE attack). Accepted: "
                                  "{versions}.", versions=accepted),
                                "Disable SSL 3.0, TLS 1.0 and TLS 1.1 and only allow TLS 1.2 and 1.3.", -30, "rfc8996"))
    elif old:
        findings.append(Finding(T, title, Status.WARNING,
                                M("The server still accepts old versions ({old}), deprecated since 2021: an attacker "
                                  "who can force an old version weakens the encryption. Accepted: {versions}.",
                                  old=", ".join(old), versions=accepted),
                                "Disable TLS 1.0 and 1.1 and only allow TLS 1.2 and 1.3 (current browsers no longer "
                                "use the old versions).", -20, "rfc8996"))
    elif accepted:
        findings.append(Finding(T, title, Status.OK, M("Only current versions are accepted: {versions}.",
                                                       versions=accepted), points=0, source="rfc8996"))
    if scan.versions.get("TLSv1.3") is False and scan.versions.get("TLSv1.2"):
        findings.append(Finding(T, "TLS 1.3", Status.WARNING,
                                "Not supported: TLS 1.3 is faster and removes the weak options of older versions.",
                                "Enable TLS 1.3 in the server or hosting configuration, next to TLS 1.2.", -5,
                                "tls13"))
    return findings


def _ciphers(scan: TLSScanInfo, cert: CertificateInfo | None) -> list[Finding]:
    findings = []
    if scan.weak_tested:
        title = "Weak cipher suites"
        if scan.weak_ciphers:
            findings.append(Finding(T, title, Status.WARNING,
                                    M("The server accepts broken cipher suites (RC4, 3DES, export, no encryption or "
                                      "no authentication): {suites}.", suites=", ".join(scan.weak_ciphers)),
                                    "Remove these suites from the server configuration and keep only AES-GCM and "
                                    "ChaCha20 suites with ECDHE.", -20, "rfc9325"))
        else:
            findings.append(Finding(T, title, Status.OK,
                                    "No broken cipher suite accepted (RC4, 3DES, export, no encryption or no "
                                    "authentication).", points=0, source="rfc9325"))
    title = "Forward secrecy"
    negotiated = cert.cipher if cert is not None and cert.valid else ""
    if negotiated and not has_forward_secrecy(negotiated, cert.tls_version if cert else ""):
        findings.append(Finding(T, title, Status.WARNING,
                                M("The suite chosen for a current browser ({suite}) has no forward secrecy: if the "
                                  "server's private key is stolen one day, recorded traffic can be decrypted.",
                                  suite=negotiated),
                                "Prefer ECDHE suites (and TLS 1.3) in the server configuration.", -10, "rfc9325"))
    elif scan.static_rsa:
        findings.append(Finding(T, title, Status.WARNING,
                                "Current browsers get forward secrecy, but the server still accepts the RSA key "
                                "exchange for old clients: their recorded traffic could be decrypted if the private "
                                "key is stolen.",
                                "Remove the suites without ECDHE or DHE (AES128-SHA, AES256-GCM-SHA384...).", -5,
                                "rfc9325"))
    elif negotiated or scan.static_rsa is False:
        findings.append(Finding(T, title, Status.OK,
                                "Every accepted key exchange has forward secrecy: a stolen private key would not "
                                "decrypt recorded traffic.", points=0, source="rfc9325"))
    return findings


def _key(cert: CertificateInfo) -> Finding:
    title = "Certificate key"
    kind, bits = cert.key_type, cert.key_bits
    label = M("{kind} {bits} bits", kind=kind, bits=bits)
    weak = (kind in ("RSA", "DSA") and bits < 2048) or (kind == "EC" and bits < 256)
    if weak:
        return Finding(T, title, Status.CRITICAL, M("Key too short ({key}): it could be broken.", key=label),
                       "Issue a new certificate with an RSA key of at least 2048 bits or an ECDSA P-256 key.", -30,
                       "rfc9325")
    return Finding(T, title, Status.OK, M("Key strong enough ({key}).", key=label), points=0, source="rfc9325")
