"""Outdated software: the CMS of the site (WordPress, Joomla, Drupal, TYPO3, PrestaShop) and PHP.

They are recognised from what the home page already shows to any visitor:
the <meta name="generator"> tag, the X-Generator and X-Powered-By headers, and
the paths of the page's own files (WordPress adds its version to them). No
other page is requested.

Whether a version still gets security fixes comes from endoflife.date, a
public, community-maintained database of support dates. Its answers are
downloaded once and kept for three days. If it cannot be reached, the software
is still reported, without a support status.

The functions that read pages and answers make no network calls.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import requests

from .i18n import Date, M
from .models import Category, Finding, Status

API = "https://endoflife.date/api/{product}.json"
MAX_AGE = 3 * 24 * 3600
NAMES = {"wordpress": "WordPress", "joomla": "Joomla", "drupal": "Drupal", "typo3": "TYPO3",
         "prestashop": "PrestaShop", "php": "PHP"}
WITH_LIFECYCLE = {"wordpress", "joomla", "drupal", "typo3", "php"}  # products endoflife.date covers


@dataclass
class Software:
    product: str  # key of NAMES
    version: str = ""  # "" when the site hides it
    seen_in: str = ""  # where it was recognised (for the report)


@dataclass
class Cycle:
    name: str  # "6.4", "8.2"...
    eol: date | bool  # end of security support: a date, or True / False
    latest: str = ""


# --- Recognising the software -------------------------------------------------------------
_GENERATOR = re.compile(r"<meta\b[^>]*\bname\s*=\s*[\"']generator[\"'][^>]*>", re.I)
_CONTENT = re.compile(r"\bcontent\s*=\s*[\"']([^\"']*)[\"']", re.I)
_VERSION = r"(\d+(?:\.\d+){0,3})"


def _generators(body: str) -> list[str]:
    found = []
    for tag in _GENERATOR.findall(body):
        content = _CONTENT.search(tag)
        if content:
            found.append(content.group(1).strip())
    return found


def detect(headers: dict[str, str], body: str) -> list[Software]:
    """Software recognised on the home page, at most one entry per product."""
    h = {k.lower(): v for k, v in headers.items()}
    found: dict[str, Software] = {}

    def add(product: str, version: str, seen_in) -> None:
        current = found.get(product)
        if current is None or (version and not current.version):
            found[product] = Software(product, version, seen_in)

    sources: list = [(g, M("generator tag of the page")) for g in _generators(body)]
    sources.append((h.get("x-generator", ""), "X-Generator"))
    for text, where in sources:
        lower = text.lower()
        for product, word in (("wordpress", "wordpress"), ("joomla", "joomla"), ("drupal", "drupal"),
                              ("typo3", "typo3"), ("prestashop", "prestashop")):
            if word in lower:
                version = re.search(word + r"!?\s*(?:cms\s*)?" + _VERSION, lower)
                add(product, version.group(1) if version else "", where)
    if re.search(r"/wp-(?:content|includes)/", body):
        version = re.search(r"/wp-includes/[^\"'?]+\?ver=" + _VERSION + r"[\"'&]", body)
        add("wordpress", version.group(1) if version else "", M("addresses of the page's files"))
    if re.search(r"\bvar\s+prestashop\s*=", body) or "/modules/ps_" in body:
        add("prestashop", "", M("scripts of the page"))
    php = re.search(r"\bphp/" + _VERSION, h.get("x-powered-by", ""), re.I)
    if php:
        add("php", php.group(1), "X-Powered-By")
    return list(found.values())


# --- Support dates (endoflife.date) ---------------------------------------------------------
def parse_cycles(data: list) -> list[Cycle]:
    """Cycles from an endoflife.date answer ([{"cycle": "6.4", "eol": "2024-01-01" | true | false, ...}])."""
    cycles = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict) or "cycle" not in item:
            continue
        eol = item.get("eol", False)
        if isinstance(eol, str):
            try:
                eol = date.fromisoformat(eol[:10])
            except ValueError:
                eol = False
        cycles.append(Cycle(str(item["cycle"]), eol if isinstance(eol, (bool, date)) else False,
                            str(item.get("latest") or "")))
    return cycles


def cache_file(product: str) -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "domain-security-check" / f"endoflife-{product}.json"


def load_cycles(product: str, timeout: float = 15) -> list[Cycle]:
    """Support cycles of a product, from the cache if recent. Raise RequestException / ValueError on failure."""
    path = cache_file(product)
    if path.exists() and time.time() - path.stat().st_mtime < MAX_AGE:
        try:
            return parse_cycles(json.loads(path.read_text(encoding="utf-8")))
        except ValueError:
            pass
    r = requests.get(API.format(product=product), timeout=timeout)
    r.raise_for_status()
    data = r.json()
    cycles = parse_cycles(data)
    if not cycles:
        raise ValueError(f"no release cycle for {product}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass
    return cycles


def _numbers(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version))


def cycle_of(version: str, cycles: list[Cycle]) -> Cycle | None:
    """The cycle a version belongs to: "6.4.2" -> "6.4", "8.2.12" -> "8.2" (the longest matching name)."""
    numbers = _numbers(version)
    matches = [c for c in cycles if _numbers(c.name) and numbers[:len(_numbers(c.name))] == _numbers(c.name)]
    return max(matches, key=lambda c: len(_numbers(c.name)), default=None)


def ended(c: Cycle, today: date) -> bool:
    return c.eol is True or (isinstance(c.eol, date) and not isinstance(c.eol, bool) and c.eol <= today)


# --- Checks ---------------------------------------------------------------------------------
def check_software(found: list[Software], lifecycles: dict[str, list[Cycle] | None], now: datetime,
                   host: str = "") -> list[Finding]:
    """One finding per piece of software: unsupported version (critical), update available (warning), up to date.

    Not scored: the website grade stays the Observatory's. Problems still appear among the priority actions.
    `host` names the subdomain when the software was found on one.
    """
    findings = []
    today = now.astimezone(timezone.utc).date()
    where = M(" on {host}", host=host) if host else ""
    for s in found:
        name = NAMES[s.product]
        title = M("Software: {name}", name=name) if not host else M("Software on {host}: {name}", host=host, name=name)
        cycles = lifecycles.get(s.product)
        if not s.version:
            findings.append(Finding(Category.WEB, title, Status.INFO,
                                    M("{name} is used{where} ({seen}); its version is not shown, so whether it is up "
                                      "to date cannot be checked from outside.", name=name, where=where,
                                      seen=s.seen_in),
                                    M("Check that {name} and its extensions are updated automatically.", name=name),
                                    None, "eol"))
            continue
        label = f"{name} {s.version}"
        cycle = cycle_of(s.version, cycles) if cycles else None
        if cycle is None and cycles and len(_numbers(s.version)) == 1:
            # Only the major version is shown ("Drupal 10"): conclusive only if all its cycles have ended
            same_major = [c for c in cycles if _numbers(c.name)[:1] == _numbers(s.version)]
            if same_major and all(ended(c, today) for c in same_major):
                cycle = max(same_major, key=lambda c: _numbers(c.name))
            elif same_major:
                findings.append(Finding(Category.WEB, title, Status.INFO,
                                        M("{label} is used{where} ({seen}): this major version is still supported, "
                                          "but the exact version is not shown.", label=label, where=where,
                                          seen=s.seen_in),
                                        M("Check that {name} and its extensions are updated automatically.",
                                          name=name), None, "eol"))
                continue
        if cycle is None:
            reason = (M("support dates unavailable") if s.product in WITH_LIFECYCLE and cycles is None
                      else M("version not listed in the support dates"))
            findings.append(Finding(Category.WEB, title, Status.INFO,
                                    M("{label} is used{where} ({seen}); {reason}.", label=label, where=where,
                                      seen=s.seen_in, reason=reason),
                                    M("Check that {name} is a version that still gets security fixes.", name=name),
                                    None, "eol"))
            continue
        if ended(cycle, today):
            since = M(" since {date}", date=Date(datetime(cycle.eol.year, cycle.eol.month, cycle.eol.day,
                                                          tzinfo=timezone.utc))) \
                if isinstance(cycle.eol, date) and not isinstance(cycle.eol, bool) else ""
            findings.append(Finding(Category.WEB, title, Status.CRITICAL,
                                    M("{label}{where} no longer gets security fixes{since}: every flaw found since "
                                      "then stays open, and attackers scan for these versions automatically.",
                                      label=label, where=where, since=since),
                                    M("Upgrade {name} to a supported version (test on a copy of the site first), "
                                      "and hide the version number.", name=name), None, "eol"))
        elif cycle.latest and _numbers(s.version) < _numbers(cycle.latest):
            findings.append(Finding(Category.WEB, title, Status.WARNING,
                                    M("{label}{where} is not up to date: version {latest} fixes known problems.",
                                      label=label, where=where, latest=cycle.latest),
                                    M("Update {name} to {latest} and turn on automatic minor updates.", name=name,
                                      latest=cycle.latest), None, "eol"))
        else:
            findings.append(Finding(Category.WEB, title, Status.OK,
                                    M("{label}{where} is a supported, up-to-date version (the number is still "
                                      "visible: hiding it gives attackers less to go on).", label=label, where=where),
                                    points=None, source="eol"))
    return findings
