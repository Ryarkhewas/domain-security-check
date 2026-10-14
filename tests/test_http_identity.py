"""HTTP collection: browser-like requests, cookies across the session, page HTML, preload status."""

import pytest
import requests

from domaincheck import collector as collector_module
from domaincheck.collector import BROWSER_HEADERS, Collector
from domaincheck.hsts_preload import PreloadList


class FakeResponse:
    def __init__(self, url, headers=None, content=b"", history=()):
        self.url, self.headers, self.content, self.history = url, headers or {}, content, list(history)
        self.encoding = "utf-8"


class FakeCookie:
    def __init__(self, name, secure=True, rest=None):
        self.name, self.secure, self._rest = name, secure, rest or {}


class FakeSession:
    """Records calls; answers with the response built by `answer(url)`."""

    calls: list = []
    answer = None

    def __init__(self):
        self.cookies = []

    def get(self, url, headers, timeout, allow_redirects):
        FakeSession.calls.append((url, headers))
        response = FakeSession.answer(url)
        if url.endswith("/robots.txt"):
            self.cookies.append(FakeCookie("robots_cookie", rest={"HttpOnly": None}))  # no SameSite
        else:
            self.cookies.append(FakeCookie("home", rest={"HttpOnly": None, "SameSite": "Lax"}))
        return response


@pytest.fixture
def fake_http(monkeypatch):
    FakeSession.calls = []
    monkeypatch.setattr(collector_module.requests, "Session", FakeSession)
    monkeypatch.setattr(Collector, "_preload", False)  # no preload list download in unit tests
    return FakeSession


def make_collector():
    c = Collector.__new__(Collector)
    c.timeout = 1
    return c


def redirect_to_https(url):
    if url.startswith("http://"):
        return FakeResponse(url.replace("http://", "https://"), history=[FakeResponse(url)])
    headers = {"Strict-Transport-Security": "max-age=31536000", "Content-Type": "text/html; charset=utf-8"}
    return FakeResponse(url, headers,
                        b"<script src='https://cdn.example.net/a.js'></script>")


def test_requests_use_browser_headers(fake_http):
    fake_http.answer = redirect_to_https
    info = make_collector().http("example.com")

    urls = [u for u, _ in fake_http.calls]
    assert urls == ["https://example.com", "https://example.com/robots.txt", "http://example.com"]
    for _, headers in fake_http.calls:
        assert headers["User-Agent"].startswith("Mozilla/5.0")
        assert "Chrome/" in headers["User-Agent"]
        assert "domain-security-check" in headers["User-Agent"]  # still identifiable
    assert "text/html" in fake_http.calls[0][1]["Accept"]
    assert info.https_reachable and info.http_redirects_to_https is True
    assert info.redirect_chain == ["http://example.com", "https://example.com"]


def test_cookies_are_collected_across_the_session(fake_http):
    fake_http.answer = redirect_to_https
    info = make_collector().http("example.com")
    by_name = {c.name: c for c in info.cookies}
    assert set(by_name) == {"home", "robots_cookie"}  # the robots.txt cookie counts, as in the Observatory
    assert by_name["home"].samesite == "lax" and by_name["robots_cookie"].samesite is None


def test_html_page_is_kept_for_the_sri_check(fake_http):
    fake_http.answer = redirect_to_https
    info = make_collector().http("example.com")
    assert info.content_type == "text/html"
    assert "cdn.example.net" in info.body


def test_browser_headers_are_not_mutated_between_calls(fake_http):
    def answer(url):
        fake_http.calls[-1][1]["X-Changed"] = "1"
        return FakeResponse(url)

    fake_http.answer = answer
    make_collector().http("example.com")
    assert "X-Changed" not in BROWSER_HEADERS


def test_http_failure_is_reported_as_unreachable(fake_http):
    def answer(url):
        raise requests.ConnectionError("down")

    fake_http.answer = answer
    info = make_collector().http("example.com")
    assert info.https_reachable is False
    assert info.http_redirects_to_https is None
    assert info.hsts_preloaded is None  # list unavailable: unknown


def test_preload_status_covers_every_redirect_host(fake_http, monkeypatch):
    def answer(url):
        if url.startswith("http://"):
            return FakeResponse("https://www.example.com/", history=[FakeResponse(url)])
        return FakeResponse(url)

    fake_http.answer = answer
    monkeypatch.setattr(Collector, "_preload", PreloadList({"example.com": True}))
    info = make_collector().http("example.com")
    assert info.hsts_preloaded is True and info.redirects_preloaded is True

    monkeypatch.setattr(Collector, "_preload", PreloadList({"example.com": False}))  # subdomains not included
    info = make_collector().http("example.com")
    assert info.hsts_preloaded is True and info.redirects_preloaded is False


# --- MTA-STS policy download --------------------------------------------------
def test_mta_sts_policy_is_fetched_without_redirects(monkeypatch):
    c = make_collector()
    c.txt = lambda name: {"_mta-sts.example.com": ["v=STSv1; id=1"],
                          "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:r@example.com"]}.get(name, [])
    calls = []

    class Policy:
        status_code, text = 200, "version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400\n"

    def fake_get(url, headers, timeout, allow_redirects):
        calls.append((url, allow_redirects))
        return Policy()

    monkeypatch.setattr(collector_module.requests, "get", fake_get)
    info = c.mta_sts("example.com")
    assert calls == [("https://mta-sts.example.com/.well-known/mta-sts.txt", False)]
    assert "mode: enforce" in info.policy and info.tls_rpt


def test_mta_sts_policy_errors_are_kept(monkeypatch):
    c = make_collector()
    c.txt = lambda name: ["v=STSv1; id=1"] if name.startswith("_mta-sts") else []

    class Moved:
        status_code, text = 301, ""

    monkeypatch.setattr(collector_module.requests, "get", lambda *a, **k: Moved())
    info = c.mta_sts("example.com")
    assert info.policy is None and info.error == "HTTP 301"


def test_no_policy_download_without_mta_sts_record(monkeypatch):
    c = make_collector()
    c.txt = lambda name: []

    def no_call(*a, **k):
        raise AssertionError("should not download")

    monkeypatch.setattr(collector_module.requests, "get", no_call)
    assert c.mta_sts("example.com").policy is None
