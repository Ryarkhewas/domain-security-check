"""NIS 2 view: which measures of article 21(2) of Directive (EU) 2022/2555 the checks relate to.

NIS 2 asks essential and important entities to take ten kinds of
cybersecurity measures, points (a) to (j) of article 21(2). An external audit
only sees a small part of them: it can give evidence for some measures (the
use of encryption, the maintenance of what is exposed, the inventory of
subdomains...), and says nothing about the others (risk analysis, incident
handling, training...). The report says so: this is a reading grid, not a
compliance assessment.

The labels below summarise each point; they are not quotations of the text.
No network access here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Result, Status

DIRECTIVE_URL = "https://eur-lex.europa.eu/eli/dir/2022/2555/oj"

NIS2_MEASURES = {
    "a": "Risk analysis and information system security policies",
    "b": "Incident handling",
    "c": "Business continuity (backups, disaster recovery, crisis management)",
    "d": "Supply chain security",
    "e": "Security in acquisition, development and maintenance, including vulnerability handling and disclosure",
    "f": "Assessing the effectiveness of the risk-management measures",
    "g": "Basic cyber hygiene practices and cybersecurity training",
    "h": "Use of cryptography and encryption",
    "i": "Human resources security, access control and asset management",
    "j": "Multi-factor authentication and secured communications",
}

# Finding source -> points of article 21(2) the check gives evidence for
MAPPING = {
    # encryption of the site, of the email in transit, signed DNS answers
    "redirection": "h", "hsts": "h", "hsts-preload": "h", "tls-guide": "h", "rfc8996": "h", "tls13": "h",
    "rfc9325": "h", "starttls": "h", "mta-sts": "h", "tls-rpt": "h", "dane": "h", "dnssec": "h", "caa": "h",
    # maintenance of what is exposed, vulnerability disclosure
    "csp": "e", "xfo": "e", "xcto": "e", "referrer": "e", "sri": "e", "cookies": "e", "permissions": "e",
    "corp": "e", "coop": "e", "coep": "e", "owasp-headers": "e", "eol": "e", "security-txt": "e",
    # email authentication: basic hygiene against spoofing
    "spf": "g", "dmarc": "g", "dkim": "g", "null-mx": "g",
    # the domain stays registered and under control; subdomains are inventoried
    "rdap": "c", "transfer-lock": "i", "ct": "i",
}
HEADING = "NIS 2 view (article 21)"
INTRO = ("Directive (EU) 2022/2555 (NIS 2) lists in its article 21(2) the cybersecurity measures that essential and "
         "important entities must take. From the Internet, this audit gives evidence for some of them only: this "
         "table links each check to a measure, it is not a compliance assessment.")
NOT_VISIBLE = "Not visible from outside: depends on internal organisation and documents."
NO_PROBLEM = "No problem seen in the related checks."


@dataclass
class Measure:
    letter: str
    label: str
    checks: int  # findings related to this measure
    problems: list[Finding]  # critical and warning ones


def view(r: Result) -> list[Measure]:
    """One line per point of article 21(2), with the related findings of this audit."""
    lines = []
    for letter, label in NIS2_MEASURES.items():
        related = [f for f in r.findings if MAPPING.get(f.source) == letter]
        lines.append(Measure(letter, label, len(related),
                             [f for f in related if f.status in (Status.CRITICAL, Status.WARNING)]))
    return lines
