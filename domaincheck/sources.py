"""Standards and guides each check is based on.

Every finding points to one of these keys, and the report shows the
reference so that readers can check the rule themselves.

Besides the standard (RFC, W3C...), a finding can also cite the guides of
ANSSI, the French national cybersecurity agency, and the security guide of
CNIL, the French data protection authority (for the few topics its website
sheet covers: certificate, TLS version, HTTPS, cookies). Only recommendation numbers
read in the guides themselves are cited; when a topic has no numbered
recommendation, the section of the guide is cited instead. Citing a guide
means "this check relates to that recommendation", not "the domain complies
with ANSSI guidance": the tool only sees what is visible from outside.
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
    "eol": ("endoflife.date (end of support dates of software versions)", "https://endoflife.date/"),
    "owasp-headers": ("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/"),
    # Certificate & TLS
    "tls-guide": ("MDN TLS guide", f"{MDN}/TLS"),
    "rfc8996": ("RFC 8996 (deprecating TLS 1.0 and 1.1)", "https://www.rfc-editor.org/rfc/rfc8996"),
    "tls13": ("RFC 8446 (TLS 1.3)", "https://www.rfc-editor.org/rfc/rfc8446"),
    "rfc9325": ("RFC 9325 (recommendations for the secure use of TLS)", "https://www.rfc-editor.org/rfc/rfc9325"),
    # Email
    "spf": ("RFC 7208 (SPF)", "https://www.rfc-editor.org/rfc/rfc7208"),
    "dmarc": ("RFC 7489 (DMARC)", "https://www.rfc-editor.org/rfc/rfc7489"),
    "dkim": ("RFC 6376 (DKIM)", "https://www.rfc-editor.org/rfc/rfc6376"),
    "null-mx": ("RFC 7505 (null MX for domains that receive no email)", "https://www.rfc-editor.org/rfc/rfc7505"),
    "starttls": ("RFC 3207 (STARTTLS for SMTP)", "https://www.rfc-editor.org/rfc/rfc3207"),
    "dane": ("RFC 7672 (DANE for SMTP)", "https://www.rfc-editor.org/rfc/rfc7672"),
    "mta-sts": ("RFC 8461 (SMTP MTA Strict Transport Security)", "https://www.rfc-editor.org/rfc/rfc8461"),
    "tls-rpt": ("RFC 8460 (SMTP TLS Reporting)", "https://www.rfc-editor.org/rfc/rfc8460"),
    # Domain & DNS
    "dnssec": ("RFC 4033 (DNS Security Introduction and Requirements)", "https://www.rfc-editor.org/rfc/rfc4033"),
    "caa": ("RFC 8659 (DNS Certification Authority Authorization)", "https://www.rfc-editor.org/rfc/rfc8659"),
    "rdap": ("RFC 9083 (RDAP, registration data of domain names)", "https://www.rfc-editor.org/rfc/rfc9083"),
    "ct": ("RFC 9162 (Certificate Transparency)", "https://www.rfc-editor.org/rfc/rfc9162"),
    "transfer-lock": ("RFC 5731 (domain status, including transfer prohibited)",
                      "https://www.rfc-editor.org/rfc/rfc5731#section-2.3"),
    # Scoring
    "observatory": ("Mozilla HTTP Observatory scoring",
                    "https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring"),
}

# --- French guides (ANSSI, CNIL) --------------------------------------------------------
GUIDES: dict[str, tuple[str, str]] = {
    "tls": ("ANSSI TLS guide v1.2 (2020)",
            "https://messervices.cyber.gouv.fr/documents-guides/"
            "anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf"),
    "web": ("ANSSI website guide PA-009 v2.0 (2021)",
            "https://cyber.gouv.fr/uploads/2013/05/anssi-guide-recommandations_mise_en_oeuvre_site_web_"
            "maitriser_standards_securite_cote_navigateur-v2.0.pdf"),
    "dns": ("ANSSI domain name guide BP-038 v1.3 (2017)",
            "https://messervices.cyber.gouv.fr/documents-guides/guide_dns_fr_anssi_1.3.pdf"),
    "internet": ("ANSSI Internet gateway guide PA-066 v3.0 (2020)",
                 "https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-passerelle_internet_securisee-v3.pdf"),
    "cnil": ("CNIL personal data security guide (2024): securing websites",
             "https://www.cnil.fr/fr/securite-securiser-les-sites-web"),
}

# Finding source key -> [(guide, recommendations or section, "" when the guide is cited as a whole)]
GUIDE_REFS: dict[str, list[tuple[str, str]]] = {
    # Website: PA-009
    "redirection": [("web", "R1"), ("cnil", "")],
    "hsts": [("web", "R2")],
    "hsts-preload": [("web", "R2")],
    "csp": [("web", "R14, R15, R16")],
    "xfo": [("web", "R17, R18")],
    "xcto": [("web", "R6")],
    "sri": [("web", "R11, R12")],
    "referrer": [("web", "§5.4")],
    "cookies": [("web", "§5.5.3"), ("cnil", "")],
    "eol": [("cnil", "")],
    # Certificate & TLS
    "tls-guide": [("tls", "R8"), ("cnil", "")],
    "rfc8996": [("tls", "R3, R4"), ("web", "R1"), ("cnil", "")],
    "tls13": [("tls", "R3")],
    # Email: PA-066, section 5.3 (transport) and 5.4 (SPF, DKIM, DMARC)
    "spf": [("internet", "R44")],
    "dkim": [("internet", "R46+")],
    "dmarc": [("internet", "R48+")],
    "mta-sts": [("internet", "§5.3")],
    "starttls": [("internet", "R42")],
    "dane": [("internet", "§5.3")],
    "tls-rpt": [("internet", "§5.3")],
    # Domain & DNS: BP-038, and PA-066 for the email domains
    "dnssec": [("dns", "R4+"), ("internet", "R50+")],
    "transfer-lock": [("dns", "R1, R3+")],
    "ct": [("web", "R3")],
    "rdap": [("dns", "§4.10")],
}


def references(key: str) -> list[tuple[str, str, str, bool]]:
    """[(label, url, recommendation, is_guide)] for a finding source key: the standard first, then the guides.

    The recommendation is "R2" or "§5.4" for a guide (the same in every language), "" otherwise.
    """
    refs = [(*SOURCES[key], "", False)] if key in SOURCES else []
    for guide, recommendation in GUIDE_REFS.get(key, []):
        refs.append((*GUIDES[guide], recommendation, True))
    return refs
