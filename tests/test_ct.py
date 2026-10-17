"""Subdomains from Certificate Transparency logs and dangling DNS records."""

from __future__ import annotations

import dns.resolver
import pytest

from domaincheck import collector as collector_module
from domaincheck.collector import _subdomain_state
from domaincheck.ct import clean_names, names_from_cert_spotter, names_from_crt_sh, takeover_provider
from domaincheck.dns_checks import check_subdomains
from domaincheck.models import Status, SubdomainInfo


def test_names_are_cleaned():
    raw = ["*.example.com\nwww.example.com", "WWW.example.com.", "example.com", "evil-example.com",
           "a.b.example.com", "contact@example.com", "other.org"]
    assert clean_names(raw, "example.com") == ["a.b.example.com", "www.example.com"]


def test_crt_sh_and_cert_spotter_answers():
    crt = [{"common_name": "example.com", "name_value": "a.example.com\nb.example.com"}, "garbage"]
    assert names_from_crt_sh(crt) == ["a.example.com\nb.example.com", "example.com"]
    spotter = [{"id": "1", "dns_names": ["example.com", "c.example.com"]}, {"id": "2"}]
    assert names_from_cert_spotter(spotter) == ["example.com", "c.example.com"]


@pytest.mark.parametrize("target, provider", [
    ("shop-2019.azurewebsites.net", "Azure App Service"),
    ("myapp.herokuapp.com.", "Heroku"),
    ("bucket.s3.amazonaws.com", "Amazon S3"),
    ("bucket.s3-website-eu-west-1.amazonaws.com", "Amazon S3"),
    ("ghs.googlehosted.com", ""),
    ("notazurewebsites.net", ""),
])
def test_takeover_provider(target, provider):
    assert takeover_provider(target) == provider


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers  # {(name, rtype): "ok" | exception}

    def resolve(self, name, rtype):
        outcome = self.answers.get((name, rtype), dns.resolver.NoAnswer())
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def nxdomain(name, canonical):
    class NX(dns.resolver.NXDOMAIN):
        @property
        def canonical_name(self):
            return dns.name.from_text(canonical)

    return NX(qnames=[dns.name.from_text(name)])


def test_subdomain_states():
    r = FakeResolver({
        ("www.example.com", "A"): "ok",
        ("v6.example.com", "AAAA"): "ok",
        ("old.example.com", "A"): nxdomain("old.example.com", "app.azurewebsites.net"),
        ("gone.example.com", "A"): nxdomain("gone.example.com", "gone.example.com"),
        ("slow.example.com", "A"): dns.exception.Timeout(),
    })
    assert _subdomain_state(r, "www.example.com") == ("resolving", "")
    assert _subdomain_state(r, "v6.example.com") == ("resolving", "")
    assert _subdomain_state(r, "old.example.com") == ("dangling", "app.azurewebsites.net")
    assert _subdomain_state(r, "gone.example.com") == ("gone", "")
    assert _subdomain_state(r, "slow.example.com") == ("unknown", "")
    assert _subdomain_state(r, "empty.example.com") == ("gone", "")


def test_collector_falls_back_to_cert_spotter(monkeypatch):
    calls = []

    class Answer:
        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            if self.data is None:
                raise collector_module.requests.HTTPError("502 Bad Gateway")

        def json(self):
            return self.data

    def fake_get(url, params=None, **kwargs):
        calls.append(url)
        if "crt.sh" in url:
            return Answer(None)
        return Answer([] if params.get("after") else [{"id": "7", "dns_names": ["www.example.com"]}])

    monkeypatch.setattr(collector_module.requests, "get", fake_get)
    monkeypatch.setattr(collector_module.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(collector_module, "_subdomain_state", lambda resolver, name: ("resolving", ""))
    info = collector_module.Collector().subdomains("example.com")
    assert (info.source, info.names, info.resolving) == ("Cert Spotter", ["www.example.com"], ["www.example.com"])
    assert calls.count("https://crt.sh/") == 3


def test_both_logs_down(monkeypatch):
    def fake_get(url, **kwargs):
        raise collector_module.requests.ConnectionError("down")

    monkeypatch.setattr(collector_module.requests, "get", fake_get)
    monkeypatch.setattr(collector_module.time, "sleep", lambda seconds: None)
    info = collector_module.Collector().subdomains("example.com")
    assert info.error and not info.names
    assert check_subdomains(info)[0].status == Status.INFO


def test_takeover_is_critical():
    info = SubdomainInfo(["old.example.com", "www.example.com"], "crt.sh", ["www.example.com"],
                         [("old.example.com", "shop.azurewebsites.net")])
    (f,) = check_subdomains(info)
    assert (f.status, f.points) == (Status.CRITICAL, -30)
    assert "old.example.com → shop.azurewebsites.net (Azure App Service)" in f.detail


def test_other_dangling_record_is_a_warning():
    info = SubdomainInfo(["old.example.com"], "crt.sh", [], [("old.example.com", "old.provider.example")])
    (f,) = check_subdomains(info)
    assert (f.status, f.points) == (Status.WARNING, -10)


def test_clean_subdomains():
    names = [f"s{i}.example.com" for i in range(20)]
    (f,) = check_subdomains(SubdomainInfo(names, "crt.sh", names, [], unknown=0))
    assert f.status == Status.OK and f.points == 0
    assert "and 8 more" in f.detail
    (f,) = check_subdomains(SubdomainInfo([], "crt.sh"))
    assert f.status == Status.OK


def test_audit_can_skip_ct_logs():
    from domaincheck.audit import run_audit
    from domaincheck.demo import DemoCollector

    r = run_audit("bakery-example.com", collector=DemoCollector(), ct_logs=False)
    assert not any(f.source == "ct" for f in r.findings)


def test_failed_lookups_are_retried_through_public_resolvers(monkeypatch):
    monkeypatch.setattr(collector_module.requests, "get", lambda url, **kw: type("A", (), {
        "raise_for_status": lambda self: None,
        "json": lambda self: [{"name_value": "a.example.com\nb.example.com"}]})())
    public = object()
    monkeypatch.setattr(collector_module, "_public_resolver", lambda timeout: public)
    monkeypatch.setattr(collector_module, "_subdomain_state",
                        lambda resolver, name: ("resolving", "") if resolver is public or name.startswith("a.")
                        else ("unknown", ""))
    info = collector_module.Collector().subdomains("example.com")
    assert (info.resolving, info.unknown) == (["a.example.com", "b.example.com"], 0)


def test_unknown_lookups_are_counted():
    info = SubdomainInfo(["a.example.com", "b.example.com"], "crt.sh", ["a.example.com"], [], unknown=1)
    assert "(1 could not be looked up)" in check_subdomains(info)[0].detail
