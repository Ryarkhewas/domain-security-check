"""Website analysis: TLS certificate, HTTPS redirect, security headers.

No network calls here: the functions analyse data that was already collected.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Mapping

from .models import Category, CertificateInfo, Finding, HTTPInfo, Status

W = Category.WEB
H = Category.HEADERS

SIX_MONTHS = 15_552_000  # seconds


def check_certificate(cert: CertificateInfo | None, now: datetime | None = None) -> list[Finding]:
    title = "HTTPS certificate"
    if cert is None:
        return [Finding(
            W, title, Status.CRITICAL,
            "Could not establish an HTTPS connection on port 443.",
            "Install a certificate (Let's Encrypt is free) and enable HTTPS.",
        )]
    if not cert.valid:
        return [Finding(
            W, title, Status.CRITICAL,
            f"The certificate is not recognised as valid: {cert.error or 'unknown error'}. "
            "Browsers show a warning to visitors.",
            "Replace it with a valid certificate covering this domain name.",
        )]

    findings: list[Finding] = []
    now = now or datetime.now(timezone.utc)
    if cert.expires_at:
        days = (cert.expires_at - now).days
        date_txt = f"{cert.expires_at:%Y-%m-%d}"
        if days < 0:
            findings.append(Finding(W, title, Status.CRITICAL, f"Certificate expired on {date_txt}.",
                                    "Renew the certificate immediately."))
        elif days < 15:
            findings.append(Finding(W, title, Status.CRITICAL, f"The certificate expires in {days} day(s) ({date_txt}).",
                                    "Renew it now and set up automatic renewal."))
        elif days < 30:
            findings.append(Finding(W, title, Status.WARNING, f"The certificate expires in {days} days ({date_txt}).",
                                    "Check that automatic renewal is in place."))
        else:
            issuer = f", issued by {cert.issuer}" if cert.issuer else ""
            findings.append(Finding(W, title, Status.OK, f"Certificate valid until {date_txt} ({days} days){issuer}."))

    if cert.tls_version:
        if cert.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append(Finding(
                W, "TLS protocol version", Status.CRITICAL,
                f"Connection negotiated with {cert.tls_version}, an obsolete and vulnerable version.",
                "Disable TLS 1.0/1.1 on the server and only allow TLS 1.2 and 1.3.",
            ))
        else:
            findings.append(Finding(W, "TLS protocol version", Status.OK, f"Connection negotiated with {cert.tls_version}."))
    return findings


def check_redirect(http: HTTPInfo) -> list[Finding]:
    title = "HTTP to HTTPS redirect"
    if http.http_redirects_to_https is None:
        return [Finding(W, title, Status.INFO, "The site does not answer on plain HTTP (port 80). Nothing to redirect.")]
    if http.http_redirects_to_https:
        return [Finding(W, title, Status.OK, "Visitors arriving over HTTP are redirected to HTTPS.")]
    return [Finding(
        W, title, Status.WARNING,
        "The site is still reachable over unencrypted HTTP, without a redirect.",
        "Set up a permanent (301) redirect from HTTP to HTTPS.",
    )]


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return None


def check_headers(headers: Mapping[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    # HSTS
    hsts = _header(headers, "Strict-Transport-Security")
    if not hsts:
        findings.append(Finding(
            H, "HSTS", Status.WARNING,
            "Missing: the browser is not required to use HTTPS on later visits.",
            "Add \"Strict-Transport-Security: max-age=31536000; includeSubDomains\".",
        ))
    else:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < SIX_MONTHS:
            findings.append(Finding(
                H, "HSTS", Status.WARNING, f"Present but short duration (max-age={age}).",
                "Use at least 6 months (max-age=15552000), ideally 1 year.",
            ))
        else:
            findings.append(Finding(H, "HSTS", Status.OK, f"Present (max-age={age})."))

    # CSP
    csp = _header(headers, "Content-Security-Policy")
    if not csp:
        findings.append(Finding(
            H, "Content-Security-Policy", Status.WARNING,
            "Missing: no limit on which scripts the page can load (protection against XSS injection).",
            "Define a CSP suited to the site, starting in \"Report-Only\" mode.",
        ))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        findings.append(Finding(
            H, "Content-Security-Policy", Status.INFO,
            "Present, but allows \"unsafe-inline\" or \"unsafe-eval\", which greatly reduces its effectiveness.",
            "Move inline scripts to external files or use nonces.",
        ))
    else:
        findings.append(Finding(H, "Content-Security-Policy", Status.OK, "Present."))

    # Clickjacking
    xfo = _header(headers, "X-Frame-Options")
    if (xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN")) or (csp and "frame-ancestors" in csp):
        findings.append(Finding(H, "Clickjacking protection", Status.OK, "The site cannot be embedded by a third-party site."))
    else:
        findings.append(Finding(
            H, "Clickjacking protection", Status.WARNING,
            "The site can be displayed inside a frame on another site (clickjacking risk).",
            "Add \"X-Frame-Options: SAMEORIGIN\" or \"frame-ancestors 'self'\" in the CSP.",
        ))

    # nosniff
    xcto = _header(headers, "X-Content-Type-Options")
    if xcto and xcto.strip().lower() == "nosniff":
        findings.append(Finding(H, "X-Content-Type-Options", Status.OK, "Present (nosniff)."))
    else:
        findings.append(Finding(
            H, "X-Content-Type-Options", Status.WARNING,
            "Missing: the browser may misinterpret the type of some files.",
            "Add \"X-Content-Type-Options: nosniff\".",
        ))

    # Referrer / Permissions
    if _header(headers, "Referrer-Policy"):
        findings.append(Finding(H, "Referrer-Policy", Status.OK, "Present."))
    else:
        findings.append(Finding(
            H, "Referrer-Policy", Status.INFO,
            "Missing: full page addresses may be sent to external sites.",
            "Add \"Referrer-Policy: strict-origin-when-cross-origin\".",
        ))
    if not _header(headers, "Permissions-Policy"):
        findings.append(Finding(
            H, "Permissions-Policy", Status.INFO,
            "Missing: no restriction on access to browser features (camera, microphone, geolocation).",
            "Add for example \"Permissions-Policy: camera=(), microphone=(), geolocation=()\".",
        ))

    # Version disclosure
    leaks = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = _header(headers, name)
        if val and re.search(r"\d", val):
            leaks.append(f"{name}: {val}")
    if leaks:
        findings.append(Finding(
            H, "Software version disclosure", Status.WARNING,
            "The server announces its versions (" + "; ".join(leaks) + "), which helps an attacker target known vulnerabilities.",
            "Hide version numbers in the server configuration.",
        ))
    return findings
