"""HTTP requests must look like a browser, while keeping the tool identifiable."""

import requests

from domaincheck import collector as collector_module
from domaincheck.collector import BROWSER_HEADERS, Collector


class FakeResponse:
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers or {}


def make_collector():
    c = Collector.__new__(Collector)
    c.timeout = 1
    return c


def test_requests_use_browser_headers(monkeypatch):
    calls = []

    def fake_get(url, headers, timeout, allow_redirects):
        calls.append((url, headers))
        return FakeResponse(url.replace("http://", "https://"), {"Strict-Transport-Security": "max-age=31536000"})

    monkeypatch.setattr(collector_module.requests, "get", fake_get)
    info = make_collector().http("example.com")

    assert [u for u, _ in calls] == ["https://example.com", "http://example.com"]
    for _, headers in calls:
        assert headers["User-Agent"].startswith("Mozilla/5.0")
        assert "Chrome/" in headers["User-Agent"]
        assert "domain-security-check" in headers["User-Agent"]  # still identifiable
        assert "text/html" in headers["Accept"]
    assert info.https_reachable and info.http_redirects_to_https is True


def test_browser_headers_are_not_mutated_between_calls(monkeypatch):
    def fake_get(url, headers, timeout, allow_redirects):
        headers["X-Changed"] = "1"
        return FakeResponse(url)

    monkeypatch.setattr(collector_module.requests, "get", fake_get)
    make_collector().http("example.com")
    assert "X-Changed" not in BROWSER_HEADERS


def test_http_failure_is_reported_as_unreachable(monkeypatch):
    def fake_get(url, headers, timeout, allow_redirects):
        raise requests.ConnectionError("down")

    monkeypatch.setattr(collector_module.requests, "get", fake_get)
    info = make_collector().http("example.com")
    assert info.https_reachable is False
    assert info.http_redirects_to_https is None
