"""Fixes adapted to where the site, the DNS zone and the mailboxes are hosted.

The platform is recognised from what is already collected: the HTTP response
headers (web server or hosting platform), the NS records (DNS host) and the MX
records (email provider). Each problem found then gets a concrete "how to":
the configuration line for that web server, or the menu to open at that
provider. Menu paths come from each provider's documentation (links given).

No network access here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .i18n import M
from .models import Finding, Fix, Status

# --- Recognising the platforms ---------------------------------------------------------
WEB_NAMES = {
    "cloudflare": "Cloudflare", "netlify": "Netlify", "vercel": "Vercel", "github-pages": "GitHub Pages",
    "iis": "IIS", "nginx": "nginx", "litespeed": "LiteSpeed", "apache": "Apache",
}
DNS_HOSTS = [  # suffix of the NS names -> provider
    ("cloudflare.com", "Cloudflare"), ("ovh.net", "OVHcloud"), ("anycast.me", "OVHcloud"), ("ovh.ca", "OVHcloud"),
    ("gandi.net", "Gandi"), ("ui-dns.com", "IONOS"), ("ui-dns.de", "IONOS"), ("ui-dns.org", "IONOS"),
    ("ui-dns.biz", "IONOS"), ("dns-parking.com", "Hostinger"), ("o2switch.net", "o2switch"),
    ("domaincontrol.com", "GoDaddy"), ("registrar-servers.com", "Namecheap"), ("googledomains.com", "Google Cloud DNS"),
    ("azure-dns.com", "Azure DNS"), ("azure-dns.net", "Azure DNS"), ("azure-dns.org", "Azure DNS"),
    ("azure-dns.info", "Azure DNS"), ("wixdns.net", "Wix"), ("squarespacedns.com", "Squarespace"),
]
MAIL_PROVIDERS = [  # suffix of the MX names -> provider
    ("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"), ("ovh.net", "OVHcloud"), ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"), ("protonmail.ch", "Proton Mail"), ("gandi.net", "Gandi"), ("ionos.fr", "IONOS"),
    ("ionos.com", "IONOS"), ("kundenserver.de", "IONOS"),
]


@dataclass
class Platforms:
    web: str = ""  # key of WEB_NAMES
    dns: str = ""  # provider name
    mail: str = ""  # provider name


def _suffix_match(names: list[str], table: list[tuple[str, str]]) -> str:
    for name in names:
        name = name.lower().rstrip(".")
        for suffix, provider in table:
            if name == suffix or name.endswith("." + suffix):
                return provider
    if any("awsdns-" in n.lower() for n in names):
        return "Amazon Route 53"
    return ""


def detect(headers: dict[str, str], ns: list[str], mx: list[str], domain: str = "") -> Platforms:
    h = {k.lower(): v for k, v in headers.items()}
    server = h.get("server", "").lower()
    if "cf-ray" in h or server == "cloudflare":
        web = "cloudflare"
    elif "x-nf-request-id" in h or server.startswith("netlify"):
        web = "netlify"
    elif "x-vercel-id" in h or server == "vercel":
        web = "vercel"
    elif server == "github.com" and not (domain == "github.com" or domain.endswith(".github.com")):
        web = "github-pages"
    else:
        web = next((key for key, word in (("iis", "microsoft-iis"), ("nginx", "nginx"), ("litespeed", "litespeed"),
                                          ("apache", "apache")) if word in server), "")
    return Platforms(web, _suffix_match(ns, DNS_HOSTS), _suffix_match(mx, MAIL_PROVIDERS))


# --- What to write, platform by platform ------------------------------------------------
HEADER_VALUES = {
    "hsts": ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    "xcto": ("X-Content-Type-Options", "nosniff"),
    "xfo": ("X-Frame-Options", "SAMEORIGIN"),
    "referrer": ("Referrer-Policy", "strict-origin-when-cross-origin"),
    # report-only first, as the recommendation says: nothing breaks while the policy is tuned
    "csp": ("Content-Security-Policy-Report-Only", "default-src 'self'; object-src 'none'; frame-ancestors 'self'"),
    "permissions": ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
}
CLOUDFLARE_DOCS = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/"
LINKS = {
    "netlify": "https://docs.netlify.com/manage/routing/headers/",
    "vercel": "https://vercel.com/docs/project-configuration/vercel-json#headers",
    "github-pages": "https://docs.github.com/en/pages/getting-started-with-github-pages/"
                    "securing-your-github-pages-site-with-https",
    "mozilla-tls": "https://ssl-config.mozilla.org/",
    "google-dkim": "https://knowledge.workspace.google.com/admin/security/set-up-dkim",
    "microsoft-dkim": "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/"
                      "email-authentication-dkim-configure",
    "cloudflare-dnssec": "https://developers.cloudflare.com/dns/dnssec/",
}
DNS_RECORD_SOURCES = {"spf", "dmarc", "caa", "mta-sts", "tls-rpt", "null-mx"}


def _on(platform: str) -> str:
    return M("On {platform}:", platform=WEB_NAMES[platform])


def _header_fix(web: str, name: str, value: str) -> Fix | None:
    if web in ("apache", "litespeed"):
        return Fix(_on(web), f'Header always set {name} "{value}"', code=True)
    if web == "nginx":
        return Fix(_on(web), f'add_header {name} "{value}" always;', code=True)
    if web == "iis":
        return Fix(M("In web.config (system.webServer > httpProtocol > customHeaders):"),
                   f'<add name="{name}" value="{value}" />', code=True)
    if web == "netlify":
        return Fix(M("In the _headers file of the site (Netlify):"), f"/*\n  {name}: {value}", code=True,
                   link=LINKS["netlify"])
    if web == "vercel":
        return Fix(M("In vercel.json:"),
                   f'{{"headers": [{{"source": "/(.*)", "headers": [{{"key": "{name}", "value": "{value}"}}]}}]}}',
                   code=True, link=LINKS["vercel"])
    if web == "cloudflare":
        return Fix(_on(web), M("add the header {name}: {value} with a response header Transform Rule (Rules "
                               "section of the dashboard), or on the origin server.", name=name, value=value))
    if web == "github-pages":
        return Fix(_on(web), M("HTTP headers cannot be added. Put the site behind a service that can add them (a "
                               "CDN such as Cloudflare) or move it to a host that allows it."))
    return None


def fix_for(f: Finding, p: Platforms) -> Fix | None:
    """A platform-specific way to apply the recommendation of a finding, if one is known."""
    src, web = f.source, p.web
    if src == "hsts" and web == "cloudflare":
        return Fix(_on(web), M("Edge Certificates > HTTP Strict Transport Security (HSTS) > Enable HSTS."),
                   link=CLOUDFLARE_DOCS + "http-strict-transport-security/")
    if src == "csp" and not str(getattr(f.detail, "template", f.detail)).startswith("Missing"):
        return None  # an existing policy to tighten: no generic line fits
    if src in HEADER_VALUES:
        return _header_fix(web, *HEADER_VALUES[src])
    if src == "redirection":
        if web in ("apache", "litespeed"):
            return Fix(M("On {platform} (.htaccess):", platform=WEB_NAMES[web]),
                       "RewriteEngine On\nRewriteCond %{HTTPS} off\n"
                       "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]", code=True)
        if web == "nginx":
            return Fix(M("On nginx (server block listening on port 80):"), "return 301 https://$host$request_uri;",
                       code=True)
        if web == "cloudflare":
            return Fix(_on(web), M("Edge Certificates > Always Use HTTPS."), link=CLOUDFLARE_DOCS + "always-use-https/")
        if web == "github-pages":
            return Fix(_on(web), M("Settings > Pages > Enforce HTTPS, in the site's repository."),
                       link=LINKS["github-pages"])
        return None
    if src in ("rfc8996", "tls13"):
        if web in ("apache", "litespeed"):
            return Fix(_on(web), "SSLProtocol -all +TLSv1.2 +TLSv1.3", code=True)
        if web == "nginx":
            return Fix(_on(web), "ssl_protocols TLSv1.2 TLSv1.3;", code=True)
        if web == "cloudflare":
            return Fix(_on(web), M("Edge Certificates > Minimum TLS Version: TLS 1.2 (TLS 1.3 is set on the same "
                                   "page)."), link=CLOUDFLARE_DOCS + "minimum-tls/")
        return None
    if src == "rfc9325" and web in ("apache", "litespeed", "nginx"):
        return Fix(_on(web), M("the Mozilla SSL Configuration Generator gives a ready configuration for this server "
                               "(\"Intermediate\" profile)."), link=LINKS["mozilla-tls"])
    if src == "owasp-headers":
        if web == "apache":
            return Fix(M("On Apache (main configuration; for PHP, expose_php = Off in php.ini):"),
                       "ServerTokens Prod\nServerSignature Off", code=True)
        if web == "nginx":
            return Fix(_on(web), "server_tokens off;", code=True)
        return None
    if src == "dkim":
        if p.mail == "Google Workspace":
            return Fix(M("On Google Workspace:"), M("Admin console > Apps > Google Workspace > Gmail > Authenticate "
                                                   "email, then Generate new record and Start authentication."),
                       link=LINKS["google-dkim"])
        if p.mail == "Microsoft 365":
            return Fix(M("On Microsoft 365:"), M("Defender portal > Policies & rules > Threat policies > Email "
                                                "authentication settings > DKIM."), link=LINKS["microsoft-dkim"])
        if p.mail:
            return Fix(M("On {provider}:", provider=p.mail), M("turn on DKIM signing in the email administration "
                                                               "interface, then publish the record it gives."))
        return None
    if src == "dnssec":
        if p.dns == "Cloudflare":
            return Fix(M("On Cloudflare:"), M("DNS > Settings > Enable DNSSEC, then copy the DS record to the "
                                              "registrar."), link=LINKS["cloudflare-dnssec"])
        if p.dns:
            return Fix(M("On {provider}:", provider=p.dns), M("turn on DNSSEC in the settings of the DNS zone."))
        return None
    if src in DNS_RECORD_SOURCES and p.dns:
        return Fix(M("On {provider}:", provider=p.dns), M("add or edit the record in the DNS zone of the domain."))
    return None


def add_fixes(findings: list[Finding], platforms: Platforms) -> None:
    """Attach a platform-specific fix to each finding that has a recommendation to apply."""
    for f in findings:
        if f.status in (Status.CRITICAL, Status.WARNING, Status.INFO) and f.recommendation:
            f.fix = fix_for(f, platforms)
