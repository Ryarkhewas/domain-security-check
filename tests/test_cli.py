"""Command line: one domain, several domains, domain files (no network: the audit is faked)."""

import json

import pytest

from domaincheck import cli
from domaincheck.audit import InvalidDomain, run_audit
from domaincheck.collector import CollectionError
from domaincheck.demo import DemoCollector


@pytest.fixture
def fake_audit(monkeypatch):
    """run_audit on demo data; "down.example" fails like a DNS outage, "bad" is invalid."""
    def audit(domain):
        if domain == "down.example":
            raise CollectionError("DNS resolution failed")
        if domain == "bad":
            raise InvalidDomain("Invalid domain name: 'bad'")
        return run_audit(domain, collector=DemoCollector())

    monkeypatch.setattr(cli, "run_audit", audit)


def test_read_domain_file(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text("# clients\nexample.com\n\n  example.org  # shop\n", encoding="utf-8")
    assert cli.read_domain_file(f) == ["example.com", "example.org"]


def test_single_domain(fake_audit, tmp_path, capsys):
    assert cli.main(["example.com", "-d", str(tmp_path)]) == 0
    assert (tmp_path / "example.com.html").exists()
    assert not (tmp_path / "index.html").exists()
    assert "overall grade" in capsys.readouterr().out


def test_several_domains_get_reports_and_an_index(fake_audit, tmp_path, capsys):
    domains = tmp_path / "domains.txt"
    domains.write_text("example.org\nEXAMPLE.com\n", encoding="utf-8")
    code = cli.main(["example.com", "down.example", "--file", str(domains), "-d", str(tmp_path / "out")])
    assert code == 3  # one domain could not be audited
    out = tmp_path / "out"
    assert sorted(p.name for p in out.iterdir()) == ["example.com.html", "example.org.html", "index.html"]
    index = (out / "index.html").read_text(encoding="utf-8")
    assert 'href="example.com.html"' in index and "Not audited: DNS resolution failed" in index
    printed = capsys.readouterr().out
    assert "example.org" in printed and "not audited" in printed


def test_several_domains_json(fake_audit, tmp_path, capsys):
    assert cli.main(["example.com", "bad", "--json", "-d", str(tmp_path)]) == 3
    data = json.loads(capsys.readouterr().out)
    assert [r["domain"] for r in data["results"]] == ["example.com"]
    assert "bad" in data["errors"]


def test_output_file_is_for_one_domain_only(fake_audit, tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["example.com", "example.org", "-o", str(tmp_path / "x.html")])


def test_missing_domain_file(tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["--file", str(tmp_path / "nope.txt")])
