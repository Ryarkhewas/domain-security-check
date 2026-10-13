"""HSTS preload list parsing and lookups (no download)."""

import json
import os
import time

from domaincheck import hsts_preload
from domaincheck.hsts_preload import PreloadList, parse_list

SAMPLE = """{
  // Comments are allowed in Chromium's file
  "entries": [
    { "name": "example.com", "policy": "bulk-18-weeks", "mode": "force-https", "include_subdomains": true },
    { "name": "only.test", "policy": "custom", "mode": "force-https" },
    { "name": "pinned.test", "policy": "custom", "pins": "google" }
  ]
}"""


def test_parse_keeps_force_https_entries():
    assert parse_list(SAMPLE) == {"example.com": True, "only.test": False}


def test_covers():
    p = PreloadList(parse_list(SAMPLE))
    assert p.covers("example.com") and p.covers("a.b.example.com") and p.covers("EXAMPLE.com.")
    assert p.covers("only.test") and not p.covers("www.only.test")  # no include_subdomains
    assert not p.covers("pinned.test") and not p.covers("example.org")


def test_load_uses_a_recent_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    cache = hsts_preload.cache_file()
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"cached.test": True}))

    def no_download(*a, **k):
        raise AssertionError("should use the cache")

    monkeypatch.setattr(hsts_preload.requests, "get", no_download)
    assert PreloadList.load().covers("www.cached.test")


def test_load_downloads_when_the_cache_is_old(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    cache = hsts_preload.cache_file()
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"old.test": True}))
    old = time.time() - 8 * 24 * 3600
    os.utime(cache, (old, old))

    class Response:
        text = SAMPLE

        def raise_for_status(self):
            pass

    monkeypatch.setattr(hsts_preload.requests, "get", lambda url, timeout: Response())
    p = PreloadList.load()
    assert p.covers("example.com") and not p.covers("old.test")
    assert json.loads(cache.read_text()) == {"example.com": True, "only.test": False}
