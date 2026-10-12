"""The collector must tell "does not exist" apart from "could not check"."""

import dns.exception
import dns.resolver
import pytest

from domaincheck.collector import CollectionError, Collector, DomainNotFound


class FakeTXTRecord:
    def __init__(self, text):
        self.strings = [text.encode()]


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers  # (name, type) -> list | exception

    def resolve(self, name, rtype, search=True):
        r = self.answers.get((name, rtype), dns.resolver.NoAnswer())
        if isinstance(r, Exception):
            raise r
        return r


def collector(answers):
    c = Collector.__new__(Collector)
    c.timeout = 1
    c.resolver = FakeResolver(answers)
    return c


def test_missing_txt_returns_empty_list():
    c = collector({("example.com", "TXT"): dns.resolver.NoAnswer()})
    assert c.txt("example.com") == []
    c = collector({("_dmarc.example.com", "TXT"): dns.resolver.NXDOMAIN()})
    assert c.txt("_dmarc.example.com") == []


def test_txt_read():
    c = collector({("example.com", "TXT"): [FakeTXTRecord("v=spf1 -all")]})
    assert c.txt("example.com") == ["v=spf1 -all"]


@pytest.mark.parametrize("failure", [dns.exception.Timeout(), dns.resolver.NoNameservers()])
def test_dns_failure_is_not_absence(failure):
    c = collector({("example.com", "TXT"): failure})
    with pytest.raises(CollectionError):
        c.txt("example.com")


def test_domain_not_found():
    c = collector({("unknown.com", "SOA"): dns.resolver.NXDOMAIN()})
    with pytest.raises(DomainNotFound):
        c.check_exists("unknown.com")


def test_existing_subdomain_without_soa():
    c = collector({("www.example.com", "SOA"): dns.resolver.NoAnswer()})
    c.check_exists("www.example.com")  # does not raise


def test_existence_check_failure():
    c = collector({("example.com", "SOA"): dns.exception.Timeout()})
    with pytest.raises(CollectionError):
        c.check_exists("example.com")
