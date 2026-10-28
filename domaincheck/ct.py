"""Subdomains found in Certificate Transparency logs.

Every certificate issued by a public authority is published in CT logs
(RFC 9162), so the names of a domain's subdomains are public, including
forgotten ones: a test site, an old shop, a former provider. They are read
from crt.sh, or from Cert Spotter when crt.sh does not answer.

A subdomain whose DNS record (CNAME) still points to a name that no longer
exists is "dangling": whoever registers that name at the provider (a cloud
app, a storage bucket...) can serve content on the subdomain. This is called a
subdomain takeover.

The functions that read the answers make no network calls, so they can be
tested on fixed data.
"""

from __future__ import annotations

import re

CRT_SH = "https://crt.sh/"
CERT_SPOTTER = "https://api.certspotter.com/v1/issuances"

# Providers where a deleted resource leaves a name that anyone can register again
# (sources: provider documentation and the "can-i-take-over-xyz" project)
TAKEOVER_SUFFIXES = {
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure",
    "cloudapp.azure.com": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Storage",
    "azureedge.net": "Azure CDN",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "s3.amazonaws.com": "Amazon S3",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "netlify.app": "Netlify",
    "pantheonsite.io": "Pantheon",
    "surge.sh": "Surge",
}


_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def clean_names(raw: list[str], domain: str) -> list[str]:
    """Subdomains of `domain` among names read in certificates: lower case, no wildcard, no duplicates, sorted.

    Only well-formed host names are kept: they are later looked up and, with --subdomains, contacted, so a
    malformed entry ("a/b.example.com", "a@b...") must not turn into an unexpected URL.
    """
    domain = domain.lower().rstrip(".")
    found = set()
    for value in raw:
        for name in str(value).splitlines():
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name != domain and name.endswith("." + domain) and _HOST.match(name):
                found.add(name)
    return sorted(found)


def names_from_crt_sh(entries: list) -> list[str]:
    """Names from a crt.sh JSON answer ([{"name_value": "a.example.com\\nb.example.com", ...}, ...])."""
    names = []
    for entry in entries:
        if isinstance(entry, dict):
            names.append(str(entry.get("name_value", "")))
            names.append(str(entry.get("common_name", "")))
    return names


def names_from_cert_spotter(issuances: list) -> list[str]:
    """Names from a Cert Spotter answer ([{"dns_names": [...]}, ...])."""
    names = []
    for issuance in issuances:
        if isinstance(issuance, dict):
            names += [str(n) for n in issuance.get("dns_names", [])]
    return names


def takeover_provider(target: str) -> str:
    """Name of the provider when a CNAME target belongs to a service open to takeover, else ""."""
    target = target.lower().rstrip(".")
    for suffix, provider in TAKEOVER_SUFFIXES.items():
        if target == suffix or target.endswith("." + suffix) or (suffix == "s3.amazonaws.com" and ".s3" in target
                                                                  and target.endswith(".amazonaws.com")):
            return provider
    return ""
