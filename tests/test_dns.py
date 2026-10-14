"""Domain & DNS checks (DNSSEC, CAA) and their collection, without network."""

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest

from domaincheck.collector import CollectionError, Collector, _ds_matches
from domaincheck.dns_checks import check_caa, check_dnssec
from domaincheck.models import CAAInfo, DNSSECInfo, Status

# --- DNSSEC -------------------------------------------------------------------
ZONE = dns.name.from_text("example.com.")


def dnskey(public_key: str):
    return dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, f"257 3 13 {public_key}")


KEY = dnskey("mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==")
OTHER_KEY = dnskey("oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==")


def test_ds_matching_the_key():
    ds = dns.dnssec.make_ds(ZONE, KEY, "SHA256")
    assert _ds_matches(ZONE, [ds], [KEY]) is True
    assert _ds_matches(ZONE, [ds], [OTHER_KEY]) is None  # different key tag: nothing to compare
    wrong = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                                f"{ds.key_tag} 13 2 {'00' * 32}")
    assert _ds_matches(ZONE, [wrong], [KEY]) is False


@pytest.mark.parametrize("info, status, points", [
    (DNSSECInfo(zone="example.com"), Status.WARNING, -15),
    (DNSSECInfo(zone="example.com", ds_count=1, dnskey_count=2, ds_matches=True), Status.OK, 0),
    (DNSSECInfo(zone="example.com", ds_count=1, dnskey_count=2, ds_matches=None), Status.OK, 0),
    (DNSSECInfo(zone="example.com", ds_count=1, dnskey_count=0), Status.CRITICAL, -50),
    (DNSSECInfo(zone="example.com", ds_count=1, dnskey_count=2, ds_matches=False), Status.CRITICAL, -50),
    (DNSSECInfo(error="timeout"), Status.INFO, None),
])
def test_dnssec(info, status, points):
    f = check_dnssec(info)
    assert (f.status, f.points) == (status, points)


# --- CAA ----------------------------------------------------------------------
@pytest.mark.parametrize("records, website, status, points", [
    ([], True, Status.WARNING, -5),
    ([(0, "issue", "letsencrypt.org")], True, Status.OK, 0),
    ([(0, "issue", "pki.goog; cansignhttpexchanges=yes"), (0, "issuewild", "pki.goog")], True, Status.OK, 0),
    ([(0, "iodef", "mailto:security@example.com")], True, Status.WARNING, -5),
    ([(0, "issue", ";")], True, Status.WARNING, -10),
    ([(0, "issue", ";")], False, Status.OK, 0),
    ([(128, "tbs", "x"), (0, "issue", "letsencrypt.org")], True, Status.WARNING, -10),
    ([(128, "issue", "letsencrypt.org")], True, Status.OK, 0),  # known tag: the critical flag is harmless
])
def test_caa(records, website, status, points):
    f = check_caa(CAAInfo(records, "example.com"), website)
    assert (f.status, f.points) == (status, points)


def test_caa_lists_the_allowed_authorities():
    f = check_caa(CAAInfo([(0, "issue", "pki.goog; x=y"), (0, "issue", "letsencrypt.org")], "example.com"), True)
    assert "letsencrypt.org, pki.goog" in f.detail and "example.com" in f.detail


def test_caa_error_is_not_scored():
    assert check_caa(CAAInfo(error="SERVFAIL"), True).points is None


# --- Collection ---------------------------------------------------------------
class FakeCAA:
    def __init__(self, flags, tag, value):
        self.flags, self.tag, self.value = flags, tag.encode(), value.encode()


def make_collector(answers):
    """Collector whose DNS answers come from a dict {(name, type): answer or exception}."""
    c = Collector.__new__(Collector)
    c.timeout = 1

    def resolve(name, rtype):
        answer = answers.get((str(name).rstrip("."), rtype))
        if isinstance(answer, Exception):
            raise answer
        return answer

    c._resolve = resolve
    return c


def test_caa_climbs_to_the_parent_but_not_the_tld():
    c = make_collector({("example.com", "CAA"): [FakeCAA(0, "issue", "letsencrypt.org")]})
    info = c.caa("shop.example.com")
    assert info.owner == "example.com" and info.records == [(0, "issue", "letsencrypt.org")]
    asked = []
    c2 = make_collector({})
    c2._resolve = lambda name, rtype: asked.append(name)
    assert c2.caa("shop.example.com").records == []
    assert asked == ["shop.example.com", "example.com"]  # never "com"


def test_caa_query_failure_is_reported_not_raised():
    c = make_collector({("example.com", "CAA"): CollectionError("SERVFAIL")})
    assert c.caa("example.com").error == "SERVFAIL"
