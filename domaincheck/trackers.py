"""Trackers loaded before consent: advertising and analytics cookies and scripts present as soon as the page opens.

In the EU (ePrivacy directive, article 5(3)) and according to the CNIL's
guidelines, most trackers may only be placed once the visitor has agreed.
A visitor who has just arrived has not clicked anything yet, so anything
these services set or load at that moment comes before consent.

Two ways to look:
- from the page received (always): tracker scripts and pixels written in the
  HTML without being held back for consent, and tracker cookies set by the
  server itself. Trackers that a tag manager adds later in JavaScript are not
  seen this way;
- with a real browser (--browser, needs Playwright): the page is loaded and
  left alone for a few seconds, without clicking the banner, and every request
  and cookie is recorded.

Audience measurement tools that the CNIL allows without consent under
conditions (Matomo, for instance, when configured accordingly) are not listed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# name -> (hosts or host/path prefixes, cookie name prefixes)
TRACKERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Google Analytics": (("google-analytics.com", "analytics.google.com", "googletagmanager.com/gtag/js"),
                         ("_ga", "_gid", "_gat")),
    "Google Ads / DoubleClick": (("googleadservices.com", "doubleclick.net", "googlesyndication.com"),
                                 ("_gcl_", "IDE", "test_cookie")),
    "Meta (Facebook) Pixel": (("connect.facebook.net", "facebook.com/tr"), ("_fbp", "_fbc")),
    "LinkedIn Insight": (("snap.licdn.com", "px.ads.linkedin.com"), ("li_fat_id", "_li_")),
    "TikTok Pixel": (("analytics.tiktok.com",), ("_ttp", "_tt_enable_cookie")),
    "Hotjar": (("static.hotjar.com", "script.hotjar.com"), ("_hj",)),
    "Microsoft Clarity": (("clarity.ms",), ("_clck", "_clsk")),
    "Microsoft Advertising (Bing)": (("bat.bing.com",), ("_uetsid", "_uetvid")),
    "Pinterest Tag": (("s.pinimg.com/ct", "ct.pinterest.com"), ("_pin_unauth", "_pinterest_")),
    "X (Twitter) Pixel": (("static.ads-twitter.com", "analytics.twitter.com", "ads-api.twitter.com"), ("muc_ads",)),
    "Snap Pixel": (("sc-static.net", "tr.snapchat.com"), ("_scid",)),
    "Criteo": (("static.criteo.net", "dynamic.criteo.com", "sslwidget.criteo.com"), ("cto_",)),
    "Taboola": (("cdn.taboola.com", "trc.taboola.com"), ("t_gid",)),
    "Outbrain": (("amplify.outbrain.com", "widgets.outbrain.com"), ("obuid",)),
    "Yandex Metrica": (("mc.yandex.ru", "mc.yandex.com"), ("_ym_",)),
    "YouTube (embedded video)": (("youtube.com/embed", "www.youtube.com/iframe_api"), ("VISITOR_INFO1_LIVE", "YSC")),
}

# Consent banner services, recognised by their script hosts or names
CMPS = {
    "Axeptio": ("axept.io",), "Didomi": ("privacy-center.org", "didomi"), "OneTrust": ("cookielaw.org", "optanon"),
    "Cookiebot": ("cookiebot.com",), "tarteaucitron": ("tarteaucitron",), "Sirdata": ("consentframework.com",),
    "Usercentrics": ("usercentrics.eu",), "Quantcast Choice": ("quantcast.mgr.consensu.org", "cmp.quantcast.com"),
    "CookieYes": ("cookieyes.com",), "Complianz": ("complianz",), "iubenda": ("iubenda.com",),
    "Osano": ("osano.com",), "TrustArc": ("trustarc.com",), "Commanders Act": ("trustcommander.net",),
    "Klaro": ("klaro",), "Termly": ("termly.io",),
}


@dataclass
class TrackerInfo:
    mode: str = "page"  # "page": from the HTML received; "browser": loaded in a real browser
    found: dict[str, list[str]] = field(default_factory=dict)  # tracker -> evidence (hosts, cookie names)
    held_back: list[str] = field(default_factory=list)  # trackers present but waiting for consent
    cmp: str = ""  # consent banner service recognised
    error: str = ""


def tracker_of_url(url: str) -> str:
    """Tracker a URL belongs to, "" if none."""
    parsed = urlparse(url if "//" in url else "//" + url)
    host = (parsed.hostname or "").lower()
    where = host + parsed.path
    for name, (hosts, _) in TRACKERS.items():
        for h in hosts:
            if "/" in h:
                if where.startswith(h) or where.startswith("www." + h):
                    return name
            elif host == h or host.endswith("." + h):
                return name
    return ""


def tracker_of_cookie(cookie: str) -> str:
    """Tracker a cookie belongs to, from its name ("_ga_ABC123" -> Google Analytics), "" if none."""
    for name, (_, prefixes) in TRACKERS.items():
        for p in prefixes:
            if cookie == p or ((p.startswith("_") or p.endswith("_")) and cookie.startswith(p)):
                return name
    return ""


def cmp_in(text: str) -> str:
    lower = text.lower()
    return next((name for name, words in CMPS.items() if any(w in lower for w in words)), "")


_TAG = re.compile(r"<(script|iframe|img)\b([^>]*)>", re.I)
_SRC = re.compile(r"\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)
_TYPE = re.compile(r"\btype\s*=\s*[\"']([^\"']+)[\"']", re.I)
_INLINE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.I | re.S)
_URL_IN_CODE = re.compile(r"(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s\"'<>)]*)?", re.I)


def _held_back(attributes: str) -> bool:
    """Scripts that a consent tool releases only after consent are written with another type or a consent mark."""
    kind = _TYPE.search(attributes)
    if kind and kind.group(1).strip().lower() not in ("text/javascript", "module", "application/javascript"):
        return True
    return bool(re.search(r"data-(cookieconsent|category|cookiecategory|consent|service|cookiescript)\b",
                          attributes, re.I))


def from_page(body: str, cookie_names: list[str]) -> TrackerInfo:
    """Trackers written in the page's HTML (sources and inline code) and tracker cookies set by the server."""
    info = TrackerInfo(mode="page", cmp=cmp_in(body))

    def add(name: str, evidence: str) -> None:
        if evidence not in info.found.setdefault(name, []):
            info.found[name].append(evidence)

    for tag, attributes in _TAG.findall(body):
        match = _SRC.search(attributes)
        src = match.group(1) if match else ""
        name = tracker_of_url(src) if src else ""
        if name:
            if tag.lower() == "script" and _held_back(attributes):
                info.held_back.append(name)
            else:
                add(name, urlparse(src if "//" in src else "//" + src).hostname or "")
    for attributes, code in _INLINE.findall(body):
        for url in _URL_IN_CODE.findall(code):
            name = tracker_of_url(url)
            if name:
                if _held_back(attributes):
                    info.held_back.append(name)
                else:
                    add(name, urlparse(url if url.startswith("http") else "https:" + url).hostname or "")
    for cookie in cookie_names:
        name = tracker_of_cookie(cookie)
        if name:
            add(name, f"cookie {cookie}")
    info.held_back = sorted(set(info.held_back) - set(info.found))
    return info


def from_browser(urls: list[str], cookies: list[str], body: str) -> TrackerInfo:
    """Trackers seen by a real browser: requests made and cookies present, before any click."""
    info = TrackerInfo(mode="browser", cmp=cmp_in(body + " " + " ".join(urls)))
    for url in urls:
        name = tracker_of_url(url)
        host = urlparse(url).hostname or ""
        if name and host not in info.found.setdefault(name, []):
            info.found[name].append(host)
    for cookie in cookies:
        name = tracker_of_cookie(cookie)
        if name and f"cookie {cookie}" not in info.found.setdefault(name, []):
            info.found[name].append(f"cookie {cookie}")
    info.found = {k: v for k, v in info.found.items() if v}
    return info


# --- Checks ---------------------------------------------------------------------------------
def check_trackers(info: TrackerInfo | None):
    """One finding: trackers present before any consent (not scored: a privacy rule, not a security setting)."""
    from .i18n import M
    from .models import Category, Finding, Status

    if info is None:
        return []
    title, src = "Trackers before consent", "trackers"
    if info.error:
        return [Finding(Category.WEB, title, Status.INFO, M("Could not be checked ({error}).", error=info.error),
                        points=None, source=src)]
    banner = M(" Consent banner: {cmp}.", cmp=info.cmp) if info.cmp else M(" No known consent banner found.")
    held = M(" Waiting for consent: {names}.", names=", ".join(info.held_back)) if info.held_back else ""
    if not info.found:
        scope = (M("No tracker loaded or cookie set by a known advertising or analytics service when the page opens, "
                   "before any click.") if info.mode == "browser" else
                 M("No known tracker in the page's HTML, and no tracker cookie set by the server. Trackers added "
                   "later by a tag manager are only seen with --browser."))
        return [Finding(Category.WEB, title, Status.OK, M("{scope}{held}{banner}", scope=scope, held=held,
                                                           banner=banner), points=None, source=src)]
    listed = "; ".join(f"{name} ({', '.join(evidence[:3])})" for name, evidence in info.found.items())
    if info.mode == "browser":
        detail = M("As soon as the page opens, before any click on a banner, these services are contacted or set "
                   "cookies: {listed}.{held}{banner}", listed=listed, held=held, banner=banner)
        status = Status.WARNING
    else:
        detail = M("The page loads these services directly, without holding them back for consent: {listed}."
                   "{held}{banner}", listed=listed, held=held, banner=banner)
        status = Status.INFO if info.cmp else Status.WARNING  # the banner tool may still block them: to verify
    return [Finding(Category.WEB, title, status, detail,
                    M("Load these services only after the visitor agrees, through the consent banner (or a tag "
                      "manager in consent mode); audience measurement may be exempt under the CNIL's conditions."),
                    None, src)]
