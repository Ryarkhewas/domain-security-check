"""HSTS preload list: domains that browsers always open over HTTPS.

The list is Chromium's (also used by Firefox, Safari and Edge), the same file
Mozilla HTTP Observatory reads (src/retrieve-hsts.js). It is downloaded once
and kept in a local cache for a week. If it cannot be downloaded, preloading
is reported as unknown and simply not taken into account.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import requests

LIST_URL = "https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json"
MAX_AGE = 7 * 24 * 3600


def cache_file() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "domain-security-check" / "hsts-preload.json"


def parse_list(text: str) -> dict[str, bool]:
    """{domain: include_subdomains} for the entries that force HTTPS."""
    data = json.loads(re.sub(r"^\s*//.*$", "", text, flags=re.M))
    return {e["name"].strip().lower(): bool(e.get("include_subdomains"))
            for e in data.get("entries", []) if e.get("mode") == "force-https"}


class PreloadList:
    def __init__(self, entries: dict[str, bool]):
        self.entries = entries

    def covers(self, host: str) -> bool:
        """True if host is preloaded, itself or through a parent with include_subdomains."""
        host = host.lower().rstrip(".")
        if host in self.entries:
            return True
        parts = host.split(".")
        return any(self.entries.get(".".join(parts[i:]), False) for i in range(1, len(parts)))

    @classmethod
    def load(cls, timeout: int = 30) -> PreloadList:
        """Cached list if recent, otherwise a fresh download. Raise OSError / RequestException on failure."""
        path = cache_file()
        if path.exists() and time.time() - path.stat().st_mtime < MAX_AGE:
            try:
                return cls(json.loads(path.read_text(encoding="utf-8")))
            except ValueError:
                pass  # corrupted cache: download again
        r = requests.get(LIST_URL, timeout=timeout)
        r.raise_for_status()
        entries = parse_list(r.text)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(entries), encoding="utf-8")
        except OSError:
            pass  # no cache, still usable
        return cls(entries)
