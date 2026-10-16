"""Changes since the previous audit of a domain."""

import json
from datetime import timedelta
from html import unescape

import pytest

from domaincheck import cli
from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.history import compare, load_previous
from domaincheck.models import Category, HTTPInfo, Status
from domaincheck.report import console_summary, render_html, render_index, render_json


def demo(**http):
    class Collector(DemoCollector):
        def http(self, host):
            info = super().http(host)
            for key, value in http.items():
                setattr(info, key, value)
            return info

    return run_audit("example.com", collector=Collector())


def saved(result) -> dict:
    return json.loads(render_json(result))


def test_no_change():
    before = saved(demo())
    changes = compare(before, demo())
    assert changes.nothing


def test_fixed_problems_and_better_grades():
    before = saved(demo())
    after = demo(http_redirects_to_https=True, redirect_chain=["http://example.com/", "https://example.com/"],
                 headers={"Strict-Transport-Security": "max-age=31536000", "X-Content-Type-Options": "nosniff",
                          "X-Frame-Options": "DENY"})
    changes = compare(before, after)
    fixed = {c.title for c in changes.fixed}
    assert {"HTTP to HTTPS redirect", "HSTS", "Clickjacking protection", "Software version disclosure"} <= fixed
    web = next(g for g in changes.grades if g.key == "WEB")
    assert (web.old, web.new) == ("F", after.grades["WEB"].grade) and web.better
    assert not changes.new


def test_new_and_worse_problems():
    before = demo(http_redirects_to_https=True, redirect_chain=["http://example.com/", "https://example.com/"])
    after = demo(cookies=[], headers={})  # X-Content-Type-Options removed: new problem
    changes = compare(saved(before), after)
    assert [c.title for c in changes.new] == ["HTTP to HTTPS redirect", "X-Content-Type-Options"]
    redirect = changes.new[0]
    assert (redirect.old, redirect.new) == (Status.OK.value, Status.WARNING.value)

    previous = saved(after)
    certificate = next(f for f in previous["findings"] if f["title"] == "HTTPS certificate")
    certificate["status"] = "ok"
    tls = next(f for f in after.findings if f.title == "HTTPS certificate")
    tls.status = Status.CRITICAL  # warning before, critical now
    certificate["status"] = "warning"
    assert [c.title for c in compare(previous, after).worse] == ["HTTPS certificate"]


def test_areas_the_previous_version_did_not_check_are_skipped():
    before = saved(demo())
    before["findings"] = [f for f in before["findings"] if f["category"] != Category.DNS.value]
    assert not [c for c in compare(before, demo()).new if c.category == "DNS"]


def test_load_previous(tmp_path):
    assert load_previous(tmp_path / "missing.json") is None
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert load_previous(tmp_path / "bad.json") is None
    (tmp_path / "other.json").write_text('{"a": 1}', encoding="utf-8")
    assert load_previous(tmp_path / "other.json") is None


@pytest.mark.parametrize("lang, heading, fixed", [
    ("en", "Changes since the audit of", "Fixed ("),
    ("fr", "Évolution depuis l'audit du", "Corrigés ("),
])
def test_changes_are_shown_in_every_output(lang, heading, fixed):
    before = saved(demo())
    before["date"] = (demo().date - timedelta(days=7)).isoformat()
    after = demo(headers={"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"})
    after.changes = compare(before, after)
    html = unescape(render_html(after, lang=lang))
    assert heading in html and fixed in html
    assert heading in console_summary(after, lang)
    index = render_index([after], {}, lang=lang)
    assert "→" in index or "1" in index
    from domaincheck.pdf_report import render_pdf

    pytest.importorskip("reportlab")
    assert render_pdf(after, lang=lang).startswith(b"%PDF-")


def test_first_audit_and_no_change_on_the_index():
    first = demo()
    assert "first audit" in render_index([first], {})
    again = demo()
    again.changes = compare(saved(first), again)
    assert "no change" in render_index([again], {})
    assert "No change since the audit of" in render_html(again)


def test_cli_compares_with_the_previous_run(tmp_path, monkeypatch, capsys):
    state = {"headers": {}}

    def audit(domain, collector=None):
        class Collector(DemoCollector):
            def http(self, host):
                return HTTPInfo(True, headers=dict(state["headers"]), http_redirects_to_https=False)

        return run_audit(domain, collector=Collector())

    monkeypatch.setattr(cli, "run_audit", audit)
    assert cli.main(["example.com", "-d", str(tmp_path)]) == 0
    first = json.loads((tmp_path / "example.com.json").read_text(encoding="utf-8"))
    assert first["changes"] is None
    capsys.readouterr()

    state["headers"] = {"X-Content-Type-Options": "nosniff"}
    assert cli.main(["example.com", "-d", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "Changes since the audit of" in out and "X-Content-Type-Options" in out
    assert "Changes since the audit of" in (tmp_path / "example.com.html").read_text(encoding="utf-8")


def test_cli_ignores_a_previous_result_for_another_domain(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run_audit", lambda d, collector=None: run_audit(d, collector=DemoCollector()))
    other = saved(run_audit("other.example", collector=DemoCollector()))
    (tmp_path / "old.json").write_text(json.dumps(other), encoding="utf-8")
    assert cli.main(["example.com", "-d", str(tmp_path), "--previous", str(tmp_path / "old.json")]) == 0
    assert json.loads((tmp_path / "example.com.json").read_text(encoding="utf-8"))["changes"] is None
