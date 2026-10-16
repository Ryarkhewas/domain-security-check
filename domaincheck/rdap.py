"""RDAP: registration data of a domain name (expiry date, status, registrar).

RDAP is the public, structured successor of WHOIS (RFC 9082, 9083). The server
to ask depends on the top-level domain: IANA publishes the list (the
"bootstrap" file, RFC 9224), which is downloaded once and kept for a week.

The functions that read RDAP answers make no network calls, so they can be
tested on fixed data.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_AGE = 7 * 24 * 3600
TRANSFER_LOCKS = {"client transfer prohibited", "server transfer prohibited"}


def cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "domain-security-check" / "rdap-bootstrap.json"


def parse_bootstrap(data: dict) -> dict[str, str]:
    """{tld: base URL of its RDAP server}, from the IANA bootstrap file."""
    servers: dict[str, str] = {}
    for tlds, urls in data.get("services", []):
        https = [u for u in urls if u.startswith("https://")] or urls
        if https:
            for tld in tlds:
                servers[tld.lower()] = https[0]
    return servers


def load_bootstrap(timeout: float = 20) -> dict[str, str]:
    """Cached bootstrap if recent, otherwise a fresh download. Raise OSError / RequestException on failure."""
    path = cache_file()
    if path.exists() and time.time() - path.stat().st_mtime < MAX_AGE:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            pass
    r = requests.get(BOOTSTRAP_URL, timeout=timeout)
    r.raise_for_status()
    servers = parse_bootstrap(r.json())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(servers), encoding="utf-8")
    except OSError:
        pass
    return servers


def server_for(domain: str, servers: dict[str, str]) -> str | None:
    """RDAP base URL for a registrable domain (example.co.uk -> the server of "uk", or of "co.uk" if listed)."""
    labels = domain.lower().rstrip(".").split(".")
    for i in range(1, len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in servers:
            return servers[suffix]
    return None


def parse_date(value: str) -> datetime | None:
    """RFC 3339 date as used by RDAP ("2027-08-14T07:01:44Z"), on Python 3.10 too."""
    text = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    if "." in text:  # fractional seconds of any length: drop them
        head, _, tail = text.partition(".")
        offset = next((tail[i:] for i in range(len(tail)) if tail[i] in "+-"), "")
        text = head + offset
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def read_answer(data: dict) -> tuple[datetime | None, list[str], str]:
    """(expiry date, statuses, registrar name) from an RDAP domain answer."""
    expires = None
    for event in data.get("events", []):
        if isinstance(event, dict) and event.get("eventAction") == "expiration":
            expires = parse_date(str(event.get("eventDate", "")))
    statuses = [str(s).lower() for s in data.get("status", []) if isinstance(s, str)]
    registrar = ""
    for entity in data.get("entities", []):
        if isinstance(entity, dict) and "registrar" in entity.get("roles", []):
            registrar = _vcard_name(entity.get("vcardArray")) or str(entity.get("handle", ""))
    return expires, statuses, registrar


def _vcard_name(vcard) -> str:
    """The "fn" (formatted name) of a jCard: ["vcard", [["fn", {}, "text", "Name"], ...]]."""
    try:
        for item in vcard[1]:
            if item[0] == "fn":
                return str(item[3])
    except (TypeError, IndexError, KeyError):
        pass
    return ""
