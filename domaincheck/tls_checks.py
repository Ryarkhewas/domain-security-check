"""Certificate and TLS checks.

There is no public scoring standard for these (SSL Labs' rating needs a full
handshake scan), so the points below are this project's own, based on RFC 8996
(TLS 1.0 and 1.1 are deprecated) and on certificate validity.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .models import Category, CertificateInfo, Finding, Status

T = Category.TLS


def check_certificate(cert: CertificateInfo | None, now: datetime | None = None) -> list[Finding]:
    title = "HTTPS certificate"
    if cert is None:
        return [Finding(T, title, Status.CRITICAL, "Could not establish an HTTPS connection on port 443.",
                        "Install a certificate (Let's Encrypt is free) and enable HTTPS.", -100, "tls-guide")]
    if not cert.valid:
        return [Finding(T, title, Status.CRITICAL,
                        f"The certificate is not recognised as valid: {cert.error or 'unknown error'}. "
                        "Browsers show a warning to visitors.",
                        "Replace it with a valid certificate covering this domain name.", -100, "tls-guide")]

    findings: list[Finding] = []
    now = now or datetime.now(timezone.utc)
    if cert.expires_at:
        days = (cert.expires_at - now).days
        date_txt = f"{cert.expires_at:%Y-%m-%d}"
        if days < 0:
            findings.append(Finding(T, title, Status.CRITICAL, f"Certificate expired on {date_txt}.",
                                    "Renew the certificate immediately.", -100, "tls-guide"))
        elif days < 15:
            findings.append(Finding(T, title, Status.CRITICAL, f"The certificate expires in {days} day(s) ({date_txt}).",
                                    "Renew it now and set up automatic renewal.", -30, "tls-guide"))
        elif days < 30:
            findings.append(Finding(T, title, Status.WARNING, f"The certificate expires in {days} days ({date_txt}).",
                                    "Check that automatic renewal is in place.", -10, "tls-guide"))
        else:
            issuer = f", issued by {cert.issuer}" if cert.issuer else ""
            findings.append(Finding(T, title, Status.OK, f"Certificate valid until {date_txt} ({days} days){issuer}.",
                                    points=0, source="tls-guide"))

    if cert.tls_version:
        if cert.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(Finding(
                T, "TLS protocol version", Status.CRITICAL,
                f"Connection negotiated with {cert.tls_version}, an obsolete and vulnerable version.",
                "Disable TLS 1.0/1.1 on the server and only allow TLS 1.2 and 1.3.", -30, "rfc8996"))
        else:
            findings.append(Finding(T, "TLS protocol version", Status.OK,
                                    f"Connection negotiated with {cert.tls_version}.", points=0, source="rfc8996"))
    return findings
