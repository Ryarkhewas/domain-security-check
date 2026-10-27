"""Trackers before consent: from the page received, and from a real browser."""

from __future__ import annotations

import http.server
import threading

import pytest

from domaincheck.collector import Collector
from domaincheck.models import Status
from domaincheck.trackers import (
    TrackerInfo,
    check_trackers,
    from_browser,
    from_page,
    tracker_of_cookie,
    tracker_of_url,
)


def test_urls_and_cookies():
    assert tracker_of_url("https://www.google-analytics.com/g/collect") == "Google Analytics"
    assert tracker_of_url("https://www.googletagmanager.com/gtag/js?id=G-1") == "Google Analytics"
    assert tracker_of_url("https://www.googletagmanager.com/gtm.js?id=GTM-1") == ""  # the tag manager alone
    assert tracker_of_url("//connect.facebook.net/en_US/fbevents.js") == "Meta (Facebook) Pixel"
    assert tracker_of_url("https://www.youtube-nocookie.com/embed/x") == ""
    assert tracker_of_url("https://example.com/analytics.js") == ""
    assert tracker_of_cookie("_ga_ABC123") == "Google Analytics"
    assert tracker_of_cookie("_fbp") == "Meta (Facebook) Pixel"
    assert tracker_of_cookie("_hjSessionUser_123") == "Hotjar"
    assert tracker_of_cookie("PHPSESSID") == ""
    assert tracker_of_cookie("IDEA") == ""


def test_page_with_trackers_and_no_banner():
    body = ('<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
            '<script>!function(f,b,e,v,n,t,s){t.src="https://connect.facebook.net/en_US/fbevents.js"}()</script>')
    info = from_page(body, ["_gcl_au", "session"])
    assert set(info.found) == {"Google Analytics", "Meta (Facebook) Pixel", "Google Ads / DoubleClick"}
    (f,) = check_trackers(info)
    assert (f.status, f.points) == (Status.WARNING, None) and "No known consent banner" in f.detail


def test_scripts_held_back_by_the_banner():
    body = ('<script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js"></script>'
            '<script type="text/plain" class="optanon-category-C0002" '
            'src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
            '<script data-cookieconsent="marketing" type="text/plain">fbq("init")</script>')
    info = from_page(body, [])
    assert info.found == {} and info.held_back == ["Google Analytics"] and info.cmp == "OneTrust"
    (f,) = check_trackers(info)
    assert f.status == Status.OK and "Waiting for consent: Google Analytics" in f.detail


def test_banner_present_but_scripts_loaded_directly_is_to_verify():
    body = '<script src="https://static.axept.io/sdk.js"></script><script src="https://static.hotjar.com/c/h.js"></script>'
    (f,) = check_trackers(from_page(body, []))
    assert f.status == Status.INFO and "Axeptio" in f.detail


def test_browser_results_are_warnings():
    info = from_browser(["https://region1.google-analytics.com/g/collect?v=2", "https://example.com/"],
                        ["_ga", "_ga_X", "session"], "<html></html>")
    assert info.found == {"Google Analytics": ["region1.google-analytics.com", "cookie _ga", "cookie _ga_X"]}
    assert check_trackers(info)[0].status == Status.WARNING
    assert check_trackers(TrackerInfo(mode="browser"))[0].status == Status.OK
    assert check_trackers(TrackerInfo(mode="browser", error="Playwright is not installed"))[0].status == Status.INFO
    assert check_trackers(None) == []


@pytest.fixture
def site():
    page = (b"<html><body><script>document.cookie='_ga=GA1.1.1; path=/';</script>"
            b"<img src='https://www.facebook.com/tr?id=1&ev=PageView'></body></html>")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def test_real_browser(site):
    pytest.importorskip("playwright")
    info = Collector(timeout=10).browser_trackers(site, wait=1)
    if info.error and "Executable doesn't exist" in info.error:
        pytest.skip("Chromium is not installed for Playwright")
    assert not info.error, info.error
    assert "cookie _ga" in info.found["Google Analytics"]
    assert "www.facebook.com" in info.found["Meta (Facebook) Pixel"]


def test_without_playwright(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_playwright(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_playwright)
    assert Collector().browser_trackers("example.com").error == "Playwright is not installed"
