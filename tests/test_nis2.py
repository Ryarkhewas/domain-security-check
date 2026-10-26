"""NIS 2 view: article 21(2) measures and the checks related to them."""

from __future__ import annotations

from domaincheck import cli
from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.nis2 import MAPPING, NIS2_MEASURES, view
from domaincheck.report import render_html
from domaincheck.sources import SOURCES


def demo():
    return run_audit("bakery-example.com", collector=DemoCollector())


def test_ten_measures_and_known_sources():
    assert list(NIS2_MEASURES) == list("abcdefghij")
    assert set(MAPPING) <= set(SOURCES)
    assert set(MAPPING.values()) <= set(NIS2_MEASURES)


def test_every_scored_source_of_the_demo_is_mapped():
    unmapped = {f.source for f in demo().findings if f.source and f.source not in MAPPING}
    assert unmapped == set(), unmapped


def test_view_of_the_demo():
    lines = {m.letter: m for m in view(demo())}
    assert lines["a"].checks == 0 and lines["b"].checks == 0  # not visible from outside
    assert lines["h"].checks > 5 and lines["h"].problems  # HSTS, redirect, old TLS...
    assert any(f.source == "ct" for f in lines["i"].problems)  # subdomain open to takeover
    assert any(f.source == "eol" for f in lines["e"].problems)  # PHP 7.4


def test_report_section_only_on_demand():
    r = demo()
    assert "NIS 2 view" not in render_html(r)
    html = render_html(r, nis2=True)
    assert "NIS 2 view (article 21)" in html and "it is not a compliance assessment" in html
    assert "https://eur-lex.europa.eu/eli/dir/2022/2555/oj" in html
    assert "Not visible from outside" in html
    fr = render_html(r, lang="fr", nis2=True)
    assert "Lecture NIS 2 (article 21)" in fr and "Utilisation de la cryptographie et du chiffrement" in fr


def test_cli_option(tmp_path):
    out = tmp_path / "r.html"
    assert cli.main(["--demo", "--nis2", "--pdf", "-o", str(out)]) == 0
    assert "NIS 2 view" in out.read_text(encoding="utf-8")
