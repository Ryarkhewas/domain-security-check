"""Standards and guides each check is based on.

Every finding points to one of these keys, and the report shows the
reference so that readers can check the rule themselves.
"""

from __future__ import annotations

MDN = "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides"

SOURCES: dict[str, tuple[str, str]] = {
    # Website (Mozilla HTTP Observatory tests)
    "csp": ("W3C Content Security Policy Level 3", "https://www.w3.org/TR/CSP3/"),
    "cookies": ("RFC 6265 (HTTP cookies) and MDN cookie guide", f"{MDN}/Cookies"),
    "redirection": ("MDN TLS guide: HTTP redirection", f"{MDN}/TLS#http_redirection"),
    "hsts": ("RFC 6797 (HTTP Strict Transport Security)", "https://www.rfc-editor.org/rfc/rfc6797"),
    "hsts-preload": ("HSTS preload list (Chromium, used by all major browsers)", "https://hstspreload.org/"),
    "sri": ("W3C Subresource Integrity", "https://www.w3.org/TR/SRI/"),
    "referrer": ("W3C Referrer Policy", "https://www.w3.org/TR/referrer-policy/"),
    "xcto": ("WHATWG Fetch: X-Content-Type-Options", "https://fetch.spec.whatwg.org/#x-content-type-options-header"),
    "xfo": ("RFC 7034 (X-Frame-Options)", "https://www.rfc-editor.org/rfc/rfc7034"),
    "corp": ("MDN: Cross-Origin-Resource-Policy", f"{MDN}/CORP"),
    "coop": ("MDN: Cross-Origin-Opener-Policy",
             "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy"),
    "coep": ("MDN: Cross-Origin-Embedder-Policy",
             "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy"),
    "permissions": ("W3C Permissions Policy", "https://www.w3.org/TR/permissions-policy/"),
    "security-txt": ("RFC 9116 (security.txt)", "https://www.rfc-editor.org/rfc/rfc9116"),
    "owasp-headers": ("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/"),
    # Certificate & TLS
    "tls-guide": ("MDN TLS guide", f"{MDN}/TLS"),
    "rfc8996": ("RFC 8996 (deprecating TLS 1.0 and 1.1)", "https://www.rfc-editor.org/rfc/rfc8996"),
    # Email
    "spf": ("RFC 7208 (SPF)", "https://www.rfc-editor.org/rfc/rfc7208"),
    "dmarc": ("RFC 7489 (DMARC)", "https://www.rfc-editor.org/rfc/rfc7489"),
    "dkim": ("RFC 6376 (DKIM)", "https://www.rfc-editor.org/rfc/rfc6376"),
    "null-mx": ("RFC 7505 (null MX for domains that receive no email)", "https://www.rfc-editor.org/rfc/rfc7505"),
    "mta-sts": ("RFC 8461 (SMTP MTA Strict Transport Security)", "https://www.rfc-editor.org/rfc/rfc8461"),
    "tls-rpt": ("RFC 8460 (SMTP TLS Reporting)", "https://www.rfc-editor.org/rfc/rfc8460"),
    # Domain & DNS
    "dnssec": ("RFC 4033 (DNS Security Introduction and Requirements)", "https://www.rfc-editor.org/rfc/rfc4033"),
    "caa": ("RFC 8659 (DNS Certification Authority Authorization)", "https://www.rfc-editor.org/rfc/rfc8659"),
    "rdap": ("RFC 9083 (RDAP, registration data of domain names)", "https://www.rfc-editor.org/rfc/rfc9083"),
    # Scoring
    "observatory": ("Mozilla HTTP Observatory scoring",
                    "https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring"),
}
