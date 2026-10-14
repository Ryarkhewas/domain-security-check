"""Scoring follows Mozilla HTTP Observatory (src/scanner/index.js, src/grader)."""

import pytest

from domaincheck.models import Category, CategoryGrade, Finding, Status
from domaincheck.scoring import (
    category_grades,
    grade_for_score,
    observatory_score,
    overall_grade,
    simple_score,
)


def f(points, cat=Category.WEB):
    return Finding(cat, "t", Status.OK, "d", points=points)


@pytest.mark.parametrize("score, grade", [
    (145, "A+"), (100, "A+"), (99, "A"), (90, "A"), (89, "A-"), (85, "A-"), (84, "B+"), (70, "B"),
    (65, "B-"), (60, "C+"), (50, "C"), (45, "C-"), (40, "D+"), (30, "D"), (25, "D-"), (24, "F"), (0, "F"), (-10, "F")])
def test_grade_chart(score, grade):
    assert grade_for_score(score) == grade


def test_no_a_plus_without_bonus_categories():
    assert grade_for_score(100, allow_plus=False) == "A"


def test_bonus_only_counts_when_still_at_least_90():
    assert observatory_score([f(-5), f(10), f(5)]) == 110  # 95 after penalties: bonuses added
    assert observatory_score([f(-25), f(10), f(5)]) == 75  # 75 after penalties: bonuses ignored
    assert observatory_score([f(-10), f(10)]) == 100  # exactly 90: bonuses count


def test_unscored_findings_are_ignored():
    assert observatory_score([f(None), f(-20)]) == 80
    assert simple_score([f(None, Category.EMAIL), f(-20, Category.EMAIL)]) == 80


def test_scores_never_go_below_zero():
    assert observatory_score([f(-100), f(-50)]) == 0
    assert simple_score([f(-150)]) == 0


def test_category_grades_and_cap():
    findings = [f(-5), f(0, Category.TLS), f(-40, Category.EMAIL)]
    g = category_grades(findings, website_exists=True, cap_reason="")
    assert (g["WEB"].grade, g["TLS"].grade, g["EMAIL"].grade) == ("A", "A", "C+")
    capped = category_grades(findings, website_exists=True, cap_reason="the HTTPS certificate has expired")
    assert capped["WEB"].grade == "F" and "expired" in capped["WEB"].note


def test_no_website_means_not_applicable():
    g = category_grades([f(-20, Category.EMAIL)], website_exists=False, cap_reason="")
    assert g["WEB"].grade == g["TLS"].grade == "N/A"
    assert overall_grade(g) == "B+"  # only email counts


def test_overall_is_the_weakest_grade():
    g = {"WEB": CategoryGrade(105, "A+"), "TLS": CategoryGrade(100, "A"), "EMAIL": CategoryGrade(62, "C+")}
    assert overall_grade(g) == "C+"
    assert overall_grade({"WEB": CategoryGrade(None, "N/A")}) == "N/A"
