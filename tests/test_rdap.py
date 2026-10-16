"""Domain registration data (RDAP): bootstrap, answers, checks (no network)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from domaincheck import collector as collector_module
from domaincheck import rdap
from domaincheck.collector import Collector
from domaincheck.dns_checks import check_registration
from domaincheck.models import RDAPInfo, Status

NOW = datetime(2026, 10, 16, tzinfo=timezone.utc)
BOOTSTRAP = {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                          [["fr"], ["http://rdap.nic.fr/", "https://rdap.nic.fr/"]],
                          [["co.uk"], ["https://rdap.example-uk/"]]]}
ANSWER = {
    "events": [{"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00.123Z"}],
    "status": ["client delete prohibited", "client transfer prohibited"],
    "entities": [{"roles": ["registrar"], "handle": "292",
                  "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "MarkMonitor Inc."]]]}],
}


def test_bootstrap_prefers_https_and_finds_the_longest_suffix():
    servers = rdap.parse_bootstrap(BOOTSTRAP)
    assert servers["fr"] == "https://rdap.nic.fr/"
    assert rdap.server_for("example.com", servers) == "https://rdap.verisign.com/com/v1/"
    assert rdap.server_for("shop.co.uk", servers) == "https://rdap.example-uk/"
    assert rdap.server_for("example.zz", servers) is None


@pytest.mark.parametrize("text, expected", [
    ("2028-09-14T04:00:00Z", datetime(2028, 9, 14, 4, tzinfo=timezone.utc)),
    ("2028-09-14T04:00:00.123Z", datetime(2028, 9, 14, 4, tzinfo=timezone.utc)),
    ("2028-09-14T06:00:00+02:00", datetime(2028, 9, 14, 4, tzinfo=timezone.utc)),
    ("2028-09-14", datetime(2028, 9, 14, tzinfo=timezone.utc)),
    ("nonsense", None),
])
def test_dates(text, expected):
    assert rdap.parse_date(text) == expected


def test_answer():
    expires, statuses, registrar = rdap.read_answer(ANSWER)
    assert expires == datetime(2028, 9, 14, 4, tzinfo=timezone.utc)
    assert "client transfer prohibited" in statuses and registrar == "MarkMonitor Inc."
    assert rdap.read_answer({}) == (None, [], "")


def info(days=None, statuses=("client transfer prohibited",), error=""):
    expires = NOW + timedelta(days=days) if days is not None else None
    return RDAPInfo("example.com", expires, list(statuses), "Registrar SA", error)


@pytest.mark.parametrize("days, status, points", [
    (400, Status.OK, 0), (20, Status.WARNING, -10), (5, Status.CRITICAL, -30), (-3, Status.CRITICAL, -50)])
def test_expiry(days, status, points):
    expiry = check_registration(info(days), NOW)[0]
    assert (expiry.status, expiry.points) == (status, points)
    assert "Registrar SA" in expiry.detail


def test_transfer_lock():
    assert check_registration(info(400), NOW)[1].status == Status.OK
    unlocked = check_registration(info(400, ["active"]), NOW)[1]
    assert (unlocked.status, unlocked.points) == (Status.WARNING, -5)
    assert len(check_registration(info(400, []), NOW)) == 1  # no status published: no lock finding


def test_unknown_expiry_and_errors_are_not_scored():
    assert check_registration(info(None), NOW)[0].points is None
    failed = check_registration(info(error="HTTP 404"), NOW)
    assert len(failed) == 1 and failed[0].points is None and failed[0].status == Status.INFO


class Answer:
    def __init__(self, status, data):
        self.status_code, self._data = status, data

    def json(self):
        return self._data


def make_collector():
    c = Collector.__new__(Collector)
    c.timeout = 1
    return c


def test_collection(monkeypatch):
    monkeypatch.setattr(collector_module, "load_bootstrap", lambda timeout: rdap.parse_bootstrap(BOOTSTRAP))
    calls = []

    def get(url, timeout, headers):
        calls.append(url)
        return Answer(200, ANSWER)

    monkeypatch.setattr(collector_module.requests, "get", get)
    result = make_collector().rdap("www.example.com")
    assert calls == ["https://rdap.verisign.com/com/v1/domain/example.com"]  # the registrable domain
    assert result.domain == "example.com" and result.registrar == "MarkMonitor Inc."


def test_collection_errors(monkeypatch):
    monkeypatch.setattr(collector_module, "load_bootstrap", lambda timeout: rdap.parse_bootstrap(BOOTSTRAP))
    assert make_collector().rdap("example.zz").error == "no RDAP server for this extension"
    monkeypatch.setattr(collector_module.requests, "get", lambda url, timeout, headers: Answer(404, {}))
    assert make_collector().rdap("example.com").error == "HTTP 404"


def test_bootstrap_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return BOOTSTRAP

    monkeypatch.setattr(rdap.requests, "get", lambda url, timeout: Response())
    assert rdap.load_bootstrap()["com"].startswith("https://rdap.verisign.com")
    assert json.loads(rdap.cache_file().read_text())["fr"] == "https://rdap.nic.fr/"

    def no_download(url, timeout):
        raise AssertionError("should use the cache")

    monkeypatch.setattr(rdap.requests, "get", no_download)
    assert "net" in rdap.load_bootstrap()
