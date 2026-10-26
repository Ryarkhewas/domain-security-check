"""Outdated software: recognition on the home page, support dates, findings."""

from __future__ import annotations

from datetime import date, datetime, timezone

from domaincheck import software
from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.models import Status
from domaincheck.software import Cycle, Software, check_software, cycle_of, detect, parse_cycles

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)
WP = [Cycle("6.8", False, "6.8.3"), Cycle("6.4", date(2025, 1, 1), "6.4.5")]


def products(found):
    return {(s.product, s.version) for s in found}


def test_generator_tags():
    body = ('<meta name="generator" content="WordPress 6.4.2" />'
            '<meta content="Joomla! - Open Source Content Management" name="generator">')
    assert products(detect({}, body)) == {("wordpress", "6.4.2"), ("joomla", "")}
    assert products(detect({"X-Generator": "Drupal 10 (https://www.drupal.org)"}, "")) == {("drupal", "10")}
    assert products(detect({}, '<meta name="generator" content="TYPO3 CMS">')) == {("typo3", "")}


def test_wordpress_from_file_addresses():
    body = '<script src="https://ex.com/wp-includes/js/wp-emoji-release.min.js?ver=6.8.1"></script>'
    assert products(detect({}, body)) == {("wordpress", "6.8.1")}
    assert products(detect({}, '<link href="/wp-content/themes/x/style.css">')) == {("wordpress", "")}


def test_version_from_generator_wins_over_hidden_one():
    body = '<link href="/wp-content/a.css"><meta name="generator" content="WordPress 6.8.3">'
    assert products(detect({}, body)) == {("wordpress", "6.8.3")}


def test_prestashop_and_php():
    assert products(detect({"X-Powered-By": "PHP/7.4.3"}, "<script>var prestashop = {};</script>")) == {
        ("prestashop", ""), ("php", "7.4.3")}
    assert detect({"Server": "nginx"}, "<html></html>") == []


def test_parse_cycles():
    cycles = parse_cycles([{"cycle": "8.3", "eol": "2027-12-31", "latest": "8.3.12"},
                           {"cycle": "7.4", "eol": True, "latest": "7.4.33"}, {"no": "cycle"}, "junk"])
    assert cycles == [Cycle("8.3", date(2027, 12, 31), "8.3.12"), Cycle("7.4", True, "7.4.33")]
    assert parse_cycles({"not": "a list"}) == []


def test_cycle_of():
    assert cycle_of("6.4.2", WP).name == "6.4"
    assert cycle_of("6.8", WP).name == "6.8"
    assert cycle_of("5.9.1", WP) is None
    assert cycle_of("10.3.6", [Cycle("10", False), Cycle("10.3", False)]).name == "10.3"


def by_status(findings):
    return [(f.status, f.points) for f in findings]


def test_unsupported_version_is_critical_but_not_scored():
    (f,) = check_software([Software("wordpress", "6.4.2", "tag")], {"wordpress": WP}, NOW)
    assert by_status([f]) == [(Status.CRITICAL, None)]
    assert "since 2025-01-01" in f.detail


def test_update_available():
    (f,) = check_software([Software("wordpress", "6.8.1", "tag")], {"wordpress": WP}, NOW)
    assert f.status == Status.WARNING and "6.8.3" in f.detail


def test_up_to_date_hidden_and_unknown():
    assert check_software([Software("wordpress", "6.8.3", "tag")], {"wordpress": WP}, NOW)[0].status == Status.OK
    assert check_software([Software("joomla", "", "tag")], {}, NOW)[0].status == Status.INFO
    (f,) = check_software([Software("wordpress", "6.9.0", "tag")], {"wordpress": None}, NOW)
    assert f.status == Status.INFO and "support dates unavailable" in f.detail


def test_major_version_only():
    drupal = [Cycle("11.1", False, "11.1.4"), Cycle("10.4", False, "10.4.2"), Cycle("9.5", date(2023, 11, 1))]
    assert check_software([Software("drupal", "10", "X-Generator")], {"drupal": drupal}, NOW)[0].status == Status.INFO
    assert check_software([Software("drupal", "9", "X-Generator")], {"drupal": drupal}, NOW)[0].status == \
        Status.CRITICAL


def test_on_a_subdomain():
    (f,) = check_software([Software("php", "7.4.3", "header")], {"php": [Cycle("7.4", True)]}, NOW,
                          host="shop.example.com")
    assert "on shop.example.com" in f.detail and "shop.example.com" in str(f.title)


def test_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    calls = []

    class Answer:
        def raise_for_status(self):
            pass

        def json(self):
            return [{"cycle": "8.3", "eol": False, "latest": "8.3.1"}]

    monkeypatch.setattr(software.requests, "get", lambda url, timeout: calls.append(url) or Answer())
    assert software.load_cycles("php")[0].name == "8.3"
    assert software.load_cycles("php")[0].latest == "8.3.1"
    assert calls == ["https://endoflife.date/api/php.json"]


def test_demo_reports_php_7_4():
    r = run_audit("bakery-example.com", collector=DemoCollector())
    php = [f for f in r.findings if f.source == "eol"]
    assert len(php) == 1 and php[0].status == Status.CRITICAL
    assert r.grades["WEB"].score == 15  # not scored: the website grade stays the Observatory's
