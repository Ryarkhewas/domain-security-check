import pytest

from domaincheck.email_checks import (
    check_dkim,
    check_dmarc,
    check_mta_sts,
    check_mx,
    check_spf,
    effective_dmarc_policy,
    mx_matches,
    parse_mta_sts_policy,
)
from domaincheck.models import MTASTSInfo, Status


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


def test_dmarc_inherited_from_parent():
    f = check_dmarc(["v=DMARC1; p=reject; rua=mailto:a@b.com"], inherited_from="example.com")
    assert f[0].status == Status.OK
    assert f[0].detail.startswith("Inherited from example.com")


def test_dmarc_inherited_uses_subdomain_policy():
    # sp= applies to subdomains and takes precedence over p=
    record = ["v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com"]
    assert check_dmarc(record, inherited_from="example.com")[0].status == Status.WARNING
    assert check_dmarc(record)[0].status == Status.OK  # on the domain itself, p= applies


def test_missing_spf_is_only_a_warning_when_dmarc_is_enforced():
    strict = check_spf([], dmarc_enforced=True)[0]
    assert (strict.status, strict.points) == (Status.WARNING, -10)
    loose = check_spf([], dmarc_enforced=False)[0]
    assert (loose.status, loose.points) == (Status.CRITICAL, -30)


@pytest.mark.parametrize("records, parent, expected", [
    (["v=DMARC1; p=reject"], "", "reject"),
    (["v=DMARC1; p=quarantine; sp=none"], "example.com", "none"),  # subdomain policy applies
    (["v=DMARC1; p=quarantine; sp=none"], "", "quarantine"),
    ([], "", ""), (["v=DMARC1; p=bogus"], "", ""), (["v=DMARC1; p=none", "v=DMARC1; p=reject"], "", ""),
])
def test_effective_dmarc_policy(records, parent, expected):
    assert effective_dmarc_policy(records, parent) == expected


def test_email_findings_cite_their_standard():
    assert check_spf(["v=spf1 -all"])[0].source == "spf"
    assert check_dmarc(["v=DMARC1; p=reject"])[0].source == "dmarc"
    assert check_dkim([], ["a"])[0].points is None  # not finding a selector is not penalised


# --- MTA-STS and TLS reporting ------------------------------------------------
POLICY = "version: STSv1\nmode: {mode}\nmx: mx1.example.net\nmx: *.mail.example.net\nmax_age: 604800\n"
MX = ["mx1.example.net", "b.mail.example.net"]


def sts(mode="enforce", policy=None, txt=("v=STSv1; id=20260101",), error="", rpt=()):
    return MTASTSInfo(list(txt), POLICY.format(mode=mode) if policy is None else policy, error, list(rpt))


def mta(info, mx=MX):
    return next(f for f in check_mta_sts(info, mx) if f.title.startswith("MTA-STS"))


@pytest.mark.parametrize("info, status, points", [
    (MTASTSInfo(), Status.WARNING, -5),
    (sts(), Status.OK, 0),
    (sts("testing"), Status.INFO, 0),
    (sts("none"), Status.WARNING, -5),
    (sts(txt=("v=STSv1;",)), Status.WARNING, -10),  # no id
    (sts(txt=("v=STSv1; id=1", "v=STSv1; id=2")), Status.WARNING, -10),
    (MTASTSInfo(["v=STSv1; id=1"], None, "HTTP 404"), Status.WARNING, -15),
    (sts(policy="version: STSv1\nmode: enforce\nmx: mx1.example.net\n"), Status.WARNING, -15),  # no max_age
    (sts(policy="version: STSv1\nmode: strict\nmx: a\nmax_age: 1\n"), Status.WARNING, -15),
])
def test_mta_sts(info, status, points):
    f = mta(info)
    assert (f.status, f.points) == (status, points)


def test_enforce_with_unlisted_mx_is_critical():
    f = mta(sts(), ["mx1.example.net", "backup.other.net"])
    assert (f.status, f.points) == (Status.CRITICAL, -30) and "backup.other.net" in f.detail
    assert mta(sts("testing"), ["backup.other.net"]).points == 0  # testing: reported only


@pytest.mark.parametrize("host, pattern, match", [
    ("mx1.example.net", "mx1.example.net", True),
    ("MX1.example.net.", "mx1.example.net", True),
    ("b.mail.example.net", "*.mail.example.net", True),
    ("a.b.mail.example.net", "*.mail.example.net", False),  # the wildcard covers one label only
    ("mail.example.net", "*.mail.example.net", False),
])
def test_mx_patterns(host, pattern, match):
    assert mx_matches(host, pattern) is match


def test_no_mta_sts_finding_without_incoming_mail():
    assert check_mta_sts(MTASTSInfo(), []) == []
    assert check_mta_sts(MTASTSInfo(), [""]) == []  # null MX


def test_tls_reporting_is_shown_but_not_scored():
    findings = {f.title: f for f in check_mta_sts(sts(rpt=["v=TLSRPTv1; rua=mailto:r@example.com"]), MX)}
    assert findings["TLS reporting (TLS-RPT)"].status == Status.OK
    assert findings["TLS reporting (TLS-RPT)"].points is None
    missing = {f.title: f for f in check_mta_sts(sts(), MX)}["TLS reporting (TLS-RPT)"]
    assert missing.status == Status.INFO and missing.points is None


def test_policy_parsing_handles_crlf():
    assert parse_mta_sts_policy("version: STSv1\r\nmx: a\r\nmx: b\r\n")["mx"] == ["a", "b"]
