"""Summary for decision makers: risks, effort, impact, grade after the quick fixes."""

from __future__ import annotations

from datetime import datetime, timezone

from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.models import Category, CategoryGrade, Finding, Result, Status
from domaincheck.report import console_summary, render_html
from domaincheck.scoring import category_grades, overall_grade
from domaincheck.sources import SOURCES
from domaincheck.summary import (
    EFFORT,
    HIGH,
    LOW,
    MEDIUM,
    PROJECT,
    QUICK,
    RISKS,
    actions,
    effort_line,
    grade_after_quick_fixes,
    impact_of,
    main_risks,
)


def demo():
    return run_audit("bakery-example.com", collector=DemoCollector())


def result(findings):
    grades = category_grades(findings, True, "")
    return Result("example.com", datetime(2026, 10, 18, tzinfo=timezone.utc), findings, grades, overall_grade(grades))


def f(source, points, status=Status.WARNING, category=Category.WEB):
    return Finding(category, source, status, "detail", "Fix it.", points, source)


def test_every_effort_and_risk_key_is_a_known_source():
    assert set(EFFORT) <= set(SOURCES)
    assert set(RISKS) <= set(SOURCES)


def test_impact():
    assert impact_of(f("hsts", -5, Status.CRITICAL)) == HIGH
    assert impact_of(f("hsts", -20)) == HIGH
    assert impact_of(f("hsts", -10)) == MEDIUM
    assert impact_of(f("hsts", None)) == LOW


def test_actions_put_high_impact_and_quick_fixes_first():
    r = result([f("csp", -25), f("hsts", -20), f("referrer", -5), Finding(Category.WEB, "ok", Status.OK, "", "", 0)])
    assert [(a.finding.source, a.impact, a.effort) for a in actions(r)] == [
        ("hsts", HIGH, QUICK), ("csp", HIGH, PROJECT), ("referrer", LOW, QUICK)]


def test_risks_add_up_and_are_distinct():
    r = result([f("spf", -20, category=Category.EMAIL), f("dmarc", -20, category=Category.EMAIL), f("csp", -25),
                f("xfo", -20)])
    risks = main_risks(r)
    assert risks[0][0].startswith("Anyone can send emails")  # spf + dmarc: -40
    assert len({sentence for sentence, _ in risks}) == len(risks) == 3


def test_critical_risk_comes_first():
    r = result([f("hsts", -20), f("ct", -30, Status.CRITICAL, Category.DNS)])
    assert main_risks(r)[0][0].startswith("A forgotten subdomain")


def test_grade_after_quick_fixes():
    r = demo()
    assert (r.grade, grade_after_quick_fixes(r)) == ("F", "C")
    clean = result([Finding(Category.WEB, "x", Status.OK, "", "", 0)])
    assert grade_after_quick_fixes(clean) == clean.grade


def test_effort_line():
    assert "9 quick fix(es)" in effort_line(demo())
    assert effort_line(result([])) == ""


def test_reports_show_the_summary():
    r = demo()
    html = render_html(r)
    assert "Summary for decision makers" in html and "from F to C" in html
    assert 'class="tag impact-high"' in html and "Quick fix (under 30 min)" in html
    fr = render_html(r, lang="fr")
    assert "Synthèse pour la direction" in fr and "Impact fort" in fr
    assert "Main risks" in console_summary(r)


def test_nothing_to_fix():
    r = result([Finding(Category.WEB, "x", Status.OK, "", "", 0)])
    r.grades = {"WEB": CategoryGrade(100, "A")}
    assert "No priority action" in render_html(r)
