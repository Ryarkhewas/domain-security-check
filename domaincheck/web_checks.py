"""Website security checks, aligned with Mozilla HTTP Observatory.

Each check reproduces one Observatory test and uses its score modifier
(see https://github.com/mdn/mdn-http-observatory, src/grader/charts.js,
MPL 2.0). Two Observatory tests are not implemented because they need more
than the home page headers: Subresource Integrity (HTML parsing) and the
HSTS preload bonus (official preload list). CORS is not tested either: the
only case it penalises requires sending a forged Origin header.

Two extra checks (Permissions-Policy, version disclosure) are shown but not
scored, since the Observatory does not score them.

No network access here: the functions analyse data that was already collected.
"""

from __future__ import annotations

import re
from typing import Mapping

from .models import Category, CookieInfo, Finding, HTTPInfo, Status

W = Category.WEB
SIX_MONTHS = 15_552_000  # seconds; the Observatory accepts this common value

DANGEROUSLY_BROAD = {"ftp:", "http:", "https:", "*", "http://*", "http://*.*", "https://*", "https://*.*"}
UNSAFE_INLINE = {"'unsafe-inline'", "data:"}
NONCE_HASH_PREFIXES = ("'sha256-", "'sha384-", "'sha512-", "'nonce-")


def status_for(points: int) -> Status:
    """Display status derived from the Observatory modifier."""
    if points > 0:
        return Status.OK
    if points == 0:
        return Status.OK
    if points <= -30:
        return Status.CRITICAL
    return Status.WARNING


def _f(title, points, detail, recommendation="", source="", status=None) -> Finding:
    return Finding(W, title, status or status_for(points), detail, recommendation, points, source)


def header(headers: Mapping[str, str], name: str) -> str | None:
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return None


# --- Redirection ---------------------------------------------------------------
def check_redirection(http: HTTPInfo, host: str) -> Finding:
    title, src = "HTTP to HTTPS redirect", "redirection"
    if http.redirect_cert_error:
        return _f(title, -20, "An invalid certificate was encountered while following the redirects.",
                  "Fix the certificate of every host involved in the redirects.", src)
    if http.http_redirects_to_https is None:
        return _f(title, 0, "The site does not answer on plain HTTP (port 80). No redirect needed.", source=src)
    chain = http.redirect_chain
    if not http.http_redirects_to_https:
        if len(chain) <= 1:
            return _f(title, -20, "The site is still reachable over unencrypted HTTP, without a redirect.",
                      "Set up a permanent (301) redirect from HTTP to HTTPS.", src)
        return _f(title, -20, "The site redirects, but the final page is not served over HTTPS.",
                  "Make the redirects end on an HTTPS address.", src)
    first = chain[1] if len(chain) > 1 else ""
    if first and not first.startswith("https://"):
        return _f(title, -10, "The site ends on HTTPS, but the first redirect goes to another HTTP address.",
                  f"Redirect http://{host} directly to https://{host} first, so that HSTS can apply.", src)
    if first and _host(first) != host:
        return _f(title, -5, f"The first redirect goes to a different host ({_host(first)}), which prevents HSTS on {host}.",
                  f"Redirect http://{host} to https://{host} first, then to the other host.", src)
    return _f(title, 0, "Visitors arriving over HTTP are redirected to HTTPS.", source=src)


def _host(url: str) -> str:
    return re.sub(r"^[a-z]+://", "", url).split("/")[0].split(":")[0].lower()


# --- HSTS -----------------------------------------------------------------------
def check_hsts(headers: Mapping[str, str]) -> Finding:
    title, src = "HSTS", "hsts"
    hsts = header(headers, "Strict-Transport-Security")
    if not hsts:
        return _f(title, -20, "Missing: the browser is not required to use HTTPS on later visits.",
                  "Add \"Strict-Transport-Security: max-age=31536000; includeSubDomains\".", src)
    m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
    if not m:
        return _f(title, -20, f"The header cannot be understood: \"{hsts}\".",
                  "Use the form \"max-age=31536000; includeSubDomains\".", src)
    age = int(m.group(1))
    if age < SIX_MONTHS:
        return _f(title, -10, f"Present but short duration (max-age={age}).",
                  "Use at least 6 months (max-age=15552000), ideally 1 year.", src)
    return _f(title, 0, f"Present (max-age={age}).", source=src)


# --- CSP ------------------------------------------------------------------------
def parse_csp(policy: str) -> dict[str, set[str]]:
    """Parse one CSP policy. Raise ValueError on a duplicated directive (invalid)."""
    directives: dict[str, set[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in directives and name not in ("report-uri", "report-to"):
            raise ValueError(f"duplicate directive {name}")
        values = {t.lower() for t in tokens[1:]}
        if not values and name.endswith("-src"):
            values = {"'none'"}
        directives[name] = values
    if not directives:
        raise ValueError("empty policy")
    return directives


def check_csp(headers: Mapping[str, str]) -> Finding:
    title, src = "Content-Security-Policy", "csp"
    raw = header(headers, "Content-Security-Policy")
    if not raw:
        if header(headers, "Content-Security-Policy-Report-Only"):
            return _f(title, -25,
                      "Only a test policy exists (Content-Security-Policy-Report-Only): violations are reported, "
                      "but nothing is blocked.",
                      "Once the reports are clean, enforce the policy with the Content-Security-Policy header.", src)
        return _f(title, -25, "Missing: no limit on which scripts the page can load (protection against XSS injection).",
                  "Define a CSP suited to the site, starting in \"Report-Only\" mode.", src)
    try:
        csp = parse_csp(raw.split(",")[0])  # the first policy carries the main rules
    except ValueError as e:
        return _f(title, -25, f"The policy cannot be parsed ({e}).",
                  "Check the syntax, for instance with Google's CSP Evaluator.", src)

    default = csp.get("default-src")
    script_src = set(csp.get("script-src") or default or {"*"})
    object_src = set(csp.get("object-src") or default or {"*"})
    style_src = set(csp.get("style-src") or default or {"*"})

    # Nonces and hashes make browsers ignore 'unsafe-inline'
    for sources in (script_src, style_src):
        if any(s.startswith(NONCE_HASH_PREFIXES) for s in sources):
            sources.discard("'unsafe-inline'")
    if "'strict-dynamic'" in script_src:
        if any(s.startswith(NONCE_HASH_PREFIXES) for s in script_src):
            script_src = {s for s in script_src
                          if s not in ("'self'", "'unsafe-inline'") and not s.startswith(tuple(DANGEROUSLY_BROAD))}
        else:
            return _f(title, -25, "'strict-dynamic' is used without a nonce or hash, which makes the policy invalid.",
                      "Add a nonce or hash to script-src, or remove 'strict-dynamic'.", src)

    active = [s for d, v in csp.items() if d not in ("img-src", "media-src", "script-src") for s in v] + list(script_src)
    passive = [s for d in ("img-src", "media-src") for s in (csp.get(d) or default or set())]

    if script_src & (DANGEROUSLY_BROAD | UNSAFE_INLINE) or object_src & DANGEROUSLY_BROAD:
        return _f(title, -20,
                  "Present, but unsafe: script-src allows 'unsafe-inline', data: or overly broad sources, "
                  "or script-src / object-src are not restricted.",
                  "Remove 'unsafe-inline' and data: from script-src, avoid broad sources such as https:, "
                  "and set object-src and script-src.", src)
    if any(s.startswith(("http:", "ftp:")) for s in active):
        return _f(title, -20, "Present, but allows scripts or other active content to be loaded over plain HTTP.",
                  "Load every resource over HTTPS and remove http: sources from the policy.", src)
    if "'unsafe-eval'" in script_src | style_src:
        return _f(title, -10, "Present, but allows 'unsafe-eval'.",
                  "Remove the use of eval() from the code, then remove 'unsafe-eval' from the policy.", src)
    if any(s.startswith(("http:", "ftp:")) for s in passive):
        return _f(title, -10, "Present, but allows images or media to be loaded over plain HTTP.",
                  "Load images and media over HTTPS only.", src)
    if style_src & (DANGEROUSLY_BROAD | UNSAFE_INLINE):
        return _f(title, 0, "Present; only style-src allows unsafe sources such as 'unsafe-inline'.",
                  "Lock down style-src by removing 'unsafe-inline', data: and broad sources.", src)
    if default == {"'none'"}:
        return _f(title, 10, "Present and strict (default-src 'none', no unsafe sources).", source=src)
    return _f(title, 5, "Present, without 'unsafe-inline' or 'unsafe-eval'.",
              "For the maximum score, set default-src to 'none' and allow each resource type explicitly.", src)


def _frame_ancestors_protects(headers: Mapping[str, str]) -> bool:
    raw = header(headers, "Content-Security-Policy")
    if not raw:
        return False
    try:
        csp = parse_csp(raw.split(",")[0])
    except ValueError:
        return False
    fa = csp.get("frame-ancestors")
    return bool(fa) and not (fa & DANGEROUSLY_BROAD)


# --- Simple headers -------------------------------------------------------------
def check_xfo(headers: Mapping[str, str]) -> Finding:
    title, src = "Clickjacking protection", "xfo"
    if _frame_ancestors_protects(headers):
        return _f(title, 5, "Protected by the CSP frame-ancestors directive.", source=src)
    xfo = header(headers, "X-Frame-Options")
    if not xfo:
        return _f(title, -20, "The site can be displayed inside a frame on another site (clickjacking risk).",
                  "Add \"X-Frame-Options: SAMEORIGIN\" or \"frame-ancestors 'self'\" in the CSP.", src)
    value = xfo.strip().lower()
    if value in ("deny", "sameorigin"):
        return _f(title, 5, f"X-Frame-Options set to {value.upper()}.", source=src)
    if value.startswith("allow-from"):
        return _f(title, 0, "X-Frame-Options uses ALLOW-FROM, which modern browsers ignore.",
                  "Use the CSP frame-ancestors directive instead.", src)
    return _f(title, -20, f"X-Frame-Options cannot be understood: \"{xfo}\".",
              "Use \"X-Frame-Options: SAMEORIGIN\" or DENY.", src)


def check_xcto(headers: Mapping[str, str]) -> Finding:
    title, src = "X-Content-Type-Options", "xcto"
    xcto = header(headers, "X-Content-Type-Options")
    if not xcto:
        return _f(title, -5, "Missing: the browser may misinterpret the type of some files.",
                  "Add \"X-Content-Type-Options: nosniff\".", src)
    if xcto.strip().lower() == "nosniff":
        return _f(title, 0, "Present (nosniff).", source=src)
    return _f(title, -5, f"Invalid value: \"{xcto}\".", "The only valid value is \"nosniff\".", src)


REFERRER_GOOD = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
REFERRER_BAD = {"origin", "origin-when-cross-origin", "unsafe-url", "no-referrer-when-downgrade"}


def check_referrer(headers: Mapping[str, str]) -> Finding:
    title, src = "Referrer-Policy", "referrer"
    raw = header(headers, "Referrer-Policy")
    if not raw:
        return _f(title, 0, "Missing: browsers apply their default policy (strict-origin-when-cross-origin in recent versions).",
                  "Add \"Referrer-Policy: strict-origin-when-cross-origin\" (worth bonus points).", src,
                  status=Status.INFO)
    # Browsers use the last value they recognise
    known = [v.strip().lower() for v in raw.split(",") if v.strip().lower() in REFERRER_GOOD | REFERRER_BAD]
    if not known:
        return _f(title, -5, f"Value not recognised: \"{raw}\".", "Use \"strict-origin-when-cross-origin\".", src)
    if known[-1] in REFERRER_GOOD:
        return _f(title, 5, f"Present ({known[-1]}).", source=src)
    return _f(title, -5, f"Set to \"{known[-1]}\", which can leak full page addresses to other sites.",
              "Use \"strict-origin-when-cross-origin\".", src)


def _isolation(headers, name, title, src, good: dict[str, str], neutral: set[str]) -> Finding:
    raw = header(headers, name)
    if not raw:
        return _f(title, 0, "Not set (optional; earns bonus points when set).", source=src, status=Status.INFO)
    value = raw.split(";")[0].strip().lower()
    if value in good:
        return _f(title, 10, good[value], source=src)
    if value in neutral:
        return _f(title, 0, f"Set to \"{value}\", which keeps the default, permissive behaviour.", source=src,
                  status=Status.INFO)
    return _f(title, -5, f"Value not recognised: \"{raw}\".", source=src)


def check_corp(headers):
    return _isolation(headers, "Cross-Origin-Resource-Policy", "Cross-Origin-Resource-Policy", "corp",
                      {"same-origin": "Set to same-origin: resources cannot leak into other origins.",
                       "same-site": "Set to same-site: resources cannot leak into other sites."},
                      {"cross-origin"})


def check_coop(headers):
    return _isolation(headers, "Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy", "coop",
                      {"same-origin": "Set to same-origin: the page is isolated from the windows that open it.",
                       "same-origin-allow-popups": "Set to same-origin-allow-popups: the page is isolated from its opener.",
                       "noopener-allow-popups": "Set to noopener-allow-popups: the page is isolated from its opener."},
                      {"unsafe-none"})


def check_coep(headers):
    return _isolation(headers, "Cross-Origin-Embedder-Policy", "Cross-Origin-Embedder-Policy", "coep",
                      {"require-corp": "Set to require-corp: only explicitly allowed cross-origin resources load.",
                       "credentialless": "Set to credentialless: cross-origin resources load without credentials."},
                      {"unsafe-none"})


# --- Cookies --------------------------------------------------------------------
# Observatory results, from best to worst, with their modifiers
_COOKIE_RESULTS = [
    (5, "All cookies use the Secure flag, session cookies use HttpOnly, and SameSite is set."),
    (0, "All cookies use the Secure flag and session cookies use HttpOnly, but some cookies have no SameSite flag."),
    (-5, "Some cookies lack the Secure flag, but HSTS prevents sending them over HTTP."),
    (-10, "A session cookie lacks the Secure flag, but HSTS prevents sending it over HTTP."),
    (-20, "Some cookies lack the Secure flag and can be sent over unencrypted HTTP."),
    (-20, "A cookie uses SameSite=None without the Secure flag."),
    (-20, "An anti-CSRF cookie is set without the SameSite flag."),
    (-30, "A session cookie lacks the HttpOnly flag: JavaScript (and XSS attacks) can read it."),
    (-40, "A session cookie lacks the Secure flag and can be sent over unencrypted HTTP."),
]


def check_cookies(cookies: list[CookieInfo], hsts: bool) -> Finding:
    title, src = "Cookies", "cookies"
    if not cookies:
        return _f(title, 0, "No cookies set on the home page.", source=src, status=Status.INFO)
    worst = None  # index into _COOKIE_RESULTS
    missing_samesite = False

    def worse(i):
        nonlocal worst
        if worst is None or _COOKIE_RESULTS[i][0] < _COOKIE_RESULTS[worst][0]:
            worst = i

    for c in cookies:
        name = c.name.lower()
        session = "login" in name or "sess" in name
        if not c.secure and c.samesite == "none":
            worse(5)
        if not c.secure:
            worse(2 if hsts else 4)
        if "csrf" in name and not c.samesite:
            worse(6)
        if session and not c.secure:
            worse(3 if hsts else 8)
        if session and not c.httponly:
            worse(7)
        if not c.samesite:
            missing_samesite = True
    if worst is None:
        worst = 1 if missing_samesite else 0
    points, detail = _COOKIE_RESULTS[worst]
    names = ", ".join(c.name for c in cookies[:5]) + ("…" if len(cookies) > 5 else "")
    recommendation = "" if points > 0 else "Set Secure on every cookie, HttpOnly on session cookies, and SameSite=Lax or Strict."
    return _f(title, points, f"{detail} (cookies: {names})", recommendation, src)


# --- Not scored by the Observatory ---------------------------------------------
def check_permissions_policy(headers) -> Finding:
    if header(headers, "Permissions-Policy"):
        return Finding(W, "Permissions-Policy", Status.OK, "Present.", source="permissions")
    return Finding(W, "Permissions-Policy", Status.INFO,
                   "Missing: no restriction on access to browser features (camera, microphone, geolocation).",
                   "Add for example \"Permissions-Policy: camera=(), microphone=(), geolocation=()\".",
                   source="permissions")


def check_version_disclosure(headers) -> Finding | None:
    leaks = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = header(headers, name)
        if val and re.search(r"\d", val):
            leaks.append(f"{name}: {val}")
    if not leaks:
        return None
    return Finding(W, "Software version disclosure", Status.WARNING,
                   "The server announces its versions (" + "; ".join(leaks) + "), which helps an attacker target known "
                   "vulnerabilities.", "Hide version numbers in the server configuration.", source="owasp-headers")


# --- All website checks ---------------------------------------------------------
def check_website(http: HTTPInfo, host: str) -> list[Finding]:
    findings = [check_redirection(http, host)]
    if not http.https_reachable:
        return findings
    h = http.headers
    hsts = check_hsts(h)
    findings += [
        check_csp(h), check_cookies(http.cookies, hsts.points == 0), hsts, check_referrer(h),
        check_xcto(h), check_xfo(h), check_corp(h), check_coop(h), check_coep(h),
        check_permissions_policy(h),
    ]
    leak = check_version_disclosure(h)
    if leak:
        findings.append(leak)
    return findings
