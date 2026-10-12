import json

import pytest

import domain_check as cli
from domaincheck.audit import InvalidDomain, compute_score, email_domain, find_dmarc, normalize_domain, run_audit
from domaincheck.demo import DemoCollector
from domaincheck.models import Category, Finding, Status
from domaincheck.report import render_html, render_json


@pytest.mark.parametrize("text, expected", [
    ("example.com", "example.com"),
    ("  HTTPS://WWW.Example.com/contact?x=1 ", "www.example.com"),
    ("http://example.com:8080/", "example.com"),
    ("example.com.", "example.com"),
    ("Boulangerie-Élysée.fr", "boulangerie-élysée.fr".encode("idna").decode()),
])
def test_normalization(text, expected):
    assert normalize_domain(text) == expected


@pytest.mark.parametrize("text", ["", "localhost", "example", "-example.com", "ex ample.com", "192.168.1.1"])
def test_invalid_domain(text):
    with pytest.raises(InvalidDomain):
        normalize_domain(text)


def test_email_domain():
    assert email_domain("www.example.com") == "example.com"
    assert email_domain("shop.example.com") == "shop.example.com"


def _f(status):
    return Finding(Category.WEB, "t", status, "d")


def test_score():
    assert compute_score([_f(Status.OK)] * 5) == (100, "A")
    assert compute_score([_f(Status.CRITICAL)] * 2) == (60, "C")
    assert compute_score([_f(Status.CRITICAL)] * 6) == (0, "F")
    assert compute_score([_f(Status.INFO)] * 10) == (100, "A")


class Spy(DemoCollector):
    """Record the names queried, to check the orchestration."""

    def __init__(self):
        self.calls = []

    def txt(self, name):
        self.calls.append(("txt", name))
        return super().txt(name)

    def certificate(self, host):
        self.calls.append(("cert", host))
        return super().certificate(host)


def test_www_email_checks_on_root_domain():
    spy = Spy()
    r = run_audit("https://www.example.com", collector=spy)
    assert r.domain == "www.example.com"
    assert ("txt", "example.com") in spy.calls
    assert ("txt", "_dmarc.example.com") in spy.calls
    assert ("cert", "www.example.com") in spy.calls


def test_full_demo():
    r = run_audit("bakery-example.com", collector=DemoCollector())
    assert r.grade == "C"
    assert {f.category for f in r.findings} == set(Category)


def test_html_escapes_content():
    class Trap(DemoCollector):
        def http(self, host):
            info = super().http(host)
            info.headers["Server"] = "<script>alert(1)</script>/1.0"
            return info

    html = render_html(run_audit("example.com", collector=Trap()))
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html


def test_valid_json():
    data = json.loads(render_json(run_audit("example.com", collector=DemoCollector())))
    assert data["domain"] == "example.com"
    assert data["findings"][0]["status"] in {"ok", "warning", "critical", "info"}


def test_cli_demo(tmp_path, capsys):
    output = tmp_path / "r.html"
    assert cli.main(["--demo", "-o", str(output), "--author", "Test"]) == 0
    assert "by Test" in output.read_text(encoding="utf-8")
    assert "grade C" in capsys.readouterr().out


def test_cli_invalid_domain(capsys):
    assert cli.main(["not a domain"]) == 1


class TxtOnly(DemoCollector):
    """Collector whose TXT answers come from a dict, recording each query."""

    def __init__(self, records):
        self.records = records
        self.queries = []

    def txt(self, name):
        self.queries.append(name)
        return self.records.get(name, [])


def test_find_dmarc_on_the_domain_itself():
    c = TxtOnly({"_dmarc.shop.example.com": ["v=DMARC1; p=none"]})
    assert find_dmarc(c, "shop.example.com") == (["v=DMARC1; p=none"], "")


def test_find_dmarc_walks_up_to_parent():
    c = TxtOnly({"_dmarc.example.com": ["v=DMARC1; p=reject"]})
    records, parent = find_dmarc(c, "a.b.example.com")
    assert (records, parent) == (["v=DMARC1; p=reject"], "example.com")
    assert c.queries == ["_dmarc.a.b.example.com", "_dmarc.b.example.com", "_dmarc.example.com"]


def test_find_dmarc_never_queries_the_tld():
    c = TxtOnly({})
    assert find_dmarc(c, "shop.example.com") == ([], "")
    assert "_dmarc.com" not in c.queries


def test_subdomain_audit_inherits_parent_policy():
    class Sub(DemoCollector):
        def txt(self, name):
            if name == "_dmarc.example.com":
                return ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
            if name.startswith("_dmarc."):
                return []
            return super().txt(name)

    r = run_audit("docs.example.com", collector=Sub())
    dmarc = next(f for f in r.findings if f.title == "DMARC (anti-spoofing policy)")
    assert dmarc.status == Status.OK and "Inherited from example.com" in dmarc.detail
