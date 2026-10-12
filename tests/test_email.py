import pytest

from domaincheck.email_checks import check_dkim, check_dmarc, check_mx, check_spf
from domaincheck.models import Status


def statuses(findings):
    return [f.status for f in findings]


@pytest.mark.parametrize("record, expected", [
    ("v=spf1 include:_spf.google.com -all", Status.OK),
    ("v=spf1 include:_spf.google.com ~all", Status.OK),
    ("v=spf1 include:_spf.google.com ?all", Status.WARNING),
    ("v=spf1 +all", Status.CRITICAL),
    ("v=spf1 a mx all", Status.CRITICAL),
    ("v=spf1 include:_spf.google.com", Status.WARNING),
    ("v=spf1 redirect=_spf.example.com", Status.OK),
])
def test_spf_all_rule(record, expected):
    findings = check_spf([record, "other=txt"])
    assert findings[0].status == expected


def test_spf_missing():
    assert statuses(check_spf(["google-site-verification=x"])) == [Status.CRITICAL]


def test_spf_duplicate():
    f = check_spf(["v=spf1 -all", "v=spf1 mx -all"])
    assert f[0].status == Status.CRITICAL and "2 SPF records" in f[0].detail


def test_spf_too_many_lookups():
    includes = " ".join(f"include:s{i}.example.com" for i in range(11))
    f = check_spf([f"v=spf1 {includes} -all"])
    assert any("DNS lookups" in x.title and x.status == Status.WARNING for x in f)


def test_spf_all_is_not_counted_as_a():
    f = check_spf(["v=spf1 " + " ".join(f"include:s{i}.com" for i in range(10)) + " -all"])
    assert len(f) == 1  # 10 lookups: at the limit, no warning


@pytest.mark.parametrize("record, expected", [
    ("v=DMARC1; p=reject; rua=mailto:a@b.com", Status.OK),
    ("v=DMARC1; p=quarantine; rua=mailto:a@b.com", Status.OK),
    ("v=DMARC1; p=none; rua=mailto:a@b.com", Status.WARNING),
    ("v=DMARC1; p=whatever; rua=mailto:a@b.com", Status.CRITICAL),
    ("v=DMARC1; rua=mailto:a@b.com", Status.CRITICAL),
])
def test_dmarc_policy(record, expected):
    assert check_dmarc([record])[0].status == expected


def test_dmarc_missing_and_duplicate():
    assert statuses(check_dmarc([])) == [Status.CRITICAL]
    assert statuses(check_dmarc(["v=DMARC1; p=none", "v=DMARC1; p=reject"])) == [Status.CRITICAL]


def test_dmarc_pct_and_rua():
    f = check_dmarc(["v=DMARC1; p=reject; pct=50"])
    titles = [x.title for x in f]
    assert "DMARC: coverage" in titles and "DMARC: reports" in titles


def test_dmarc_spaces_and_case():
    assert check_dmarc(["v=DMARC1 ; P=Reject ; rua=mailto:x@y.com"])[0].status == Status.OK


def test_dkim():
    assert check_dkim(["google"], ["google", "default"])[0].status == Status.OK
    assert check_dkim([], ["google", "default"])[0].status == Status.INFO


def test_mx():
    assert check_mx([])[0].status == Status.INFO
    assert check_mx(["mx.example.com"])[0].status == Status.OK
