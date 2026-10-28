"""security.txt (RFC 9116): collection and check (no network)."""

from datetime import datetime, timezone

import pytest

from domaincheck import collector as collector_module
from domaincheck.collector import Collector
from domaincheck.models import SecurityTxtInfo, Status
from domaincheck.web_checks import check_security_txt, parse_security_txt

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)
URL = "https://example.com/.well-known/security.txt"
GOOD = ("# Our policy\nContact: mailto:security@example.com\nExpires: 2027-06-30T22:00:00.000Z\n"
        "Preferred-Languages: fr, en\n")



pytestmark = pytest.mark.usefixtures("plain_http")

def check(content, url=URL):
    return check_security_txt(SecurityTxtInfo(url, content), NOW)


def test_valid_file():
    f = check(GOOD)
    assert f.status == Status.OK and f.points is None
    assert "mailto:security@example.com" in f.detail and "2027-06-30" in f.detail


@pytest.mark.parametrize("content, words", [
    ("Expires: 2027-06-30T22:00:00Z\n", "Contact"),
    ("Contact: mailto:a@example.com\n", "Expires"),
    ("Contact: mailto:a@example.com\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n", "Expires"),
    ("Contact: mailto:a@example.com\nExpires: 2025-01-01T00:00:00Z\n", "expired"),
])
def test_invalid_files(content, words):
    f = check(content)
    assert f.status == Status.WARNING and f.points is None and words in f.detail


def test_missing_file_and_old_address():
    missing = check_security_txt(SecurityTxtInfo(), NOW)
    assert missing.status == Status.INFO and missing.recommendation
    old = check(GOOD, "https://example.com/security.txt")
    assert old.status == Status.OK and "/.well-known/security.txt" in old.detail


def test_signed_file():
    signed = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + GOOD +
              "-----BEGIN PGP SIGNATURE-----\nabc: def\n-----END PGP SIGNATURE-----\n")
    fields = parse_security_txt(signed)
    assert fields["contact"] == ["mailto:security@example.com"] and "hash" not in fields and "abc" not in fields


class Response:
    def __init__(self, status, content_type, text=""):
        self.status_code, self.headers, self.text = status, {"Content-Type": content_type}, text


@pytest.mark.parametrize("answers, found", [
    ({"/.well-known/security.txt": Response(200, "text/plain; charset=utf-8", GOOD)}, URL),
    ({"/.well-known/security.txt": Response(404, "text/html"),
      "/security.txt": Response(200, "text/plain", GOOD)}, "https://example.com/security.txt"),
    ({"/.well-known/security.txt": Response(200, "text/html", "<html>Not found</html>"),
      "/security.txt": Response(200, "text/html", "<html>")}, ""),  # soft 404 pages do not count
])
def test_collection(monkeypatch, answers, found):
    def get(url, headers, timeout, allow_redirects):
        path = url.split("example.com", 1)[1]
        return answers.get(path, Response(404, "text/html"))

    monkeypatch.setattr(collector_module.requests, "get", get)
    c = Collector.__new__(Collector)
    c.timeout, c.allow_private = 1, False
    info = c.security_txt("example.com")
    assert info.url == found and (info.content is not None) == bool(found)
