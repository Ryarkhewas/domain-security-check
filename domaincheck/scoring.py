"""Grades: one per category, plus an overall grade (the weakest category).

Website: Mozilla HTTP Observatory algorithm. Start at 100, add the penalties;
bonuses only count if the score is still 90 or more after the penalties.
The grade comes from the score rounded down to a multiple of 5.

Certificate & TLS, Email: start at 100 and add the (negative) points. Same
grade chart, but without A+ since these categories have no bonuses.
"""

from __future__ import annotations

from .i18n import M
from .models import Category, CategoryGrade, Finding

# Mozilla HTTP Observatory grade chart (src/grader/charts.js)
GRADE_CHART = {100: "A+", 95: "A", 90: "A", 85: "A-", 80: "B+", 75: "B", 70: "B", 65: "B-", 60: "C+",
               55: "C", 50: "C", 45: "C-", 40: "D+", 35: "D", 30: "D", 25: "D-", 20: "F", 15: "F",
               10: "F", 5: "F", 0: "F"}
MINIMUM_SCORE_FOR_EXTRA_CREDIT = 90
GRADE_ORDER = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D+", "D", "D-", "F"]
CAPPED_WEB_SCORE = 20  # highest score that still gives an F


def grade_for_score(score: int, allow_plus: bool = True) -> str:
    score = max(score, 0)
    grade = GRADE_CHART[min(score - score % 5, 100)]
    return "A" if grade == "A+" and not allow_plus else grade


def observatory_score(findings: list[Finding]) -> int:
    points = [f.points for f in findings if f.points is not None]
    with_bonus = 100 + sum(points)
    without_bonus = 100 + sum(p for p in points if p < 0)
    score = with_bonus if without_bonus >= MINIMUM_SCORE_FOR_EXTRA_CREDIT else without_bonus
    return max(score, 0)


def simple_score(findings: list[Finding]) -> int:
    return max(0, min(100, 100 + sum(f.points for f in findings if f.points is not None)))


def category_grades(findings: list[Finding], website_exists: bool, cap_reason: str) -> dict[str, CategoryGrade]:
    by_cat = {c: [f for f in findings if f.category == c] for c in Category}
    grades: dict[str, CategoryGrade] = {}

    if not website_exists:
        note: str = M("No website answers on this domain.")
        grades[Category.WEB.name] = CategoryGrade(None, "N/A", note)
        grades[Category.TLS.name] = CategoryGrade(None, "N/A", note)
    else:
        web = observatory_score(by_cat[Category.WEB])
        note = ""
        if cap_reason and web > CAPPED_WEB_SCORE:
            web, note = CAPPED_WEB_SCORE, M("Capped at F: {reason}.", reason=cap_reason)
        grades[Category.WEB.name] = CategoryGrade(web, grade_for_score(web), note)
        tls = simple_score(by_cat[Category.TLS])
        grades[Category.TLS.name] = CategoryGrade(tls, grade_for_score(tls, allow_plus=False))

    mail = simple_score(by_cat[Category.EMAIL])
    grades[Category.EMAIL.name] = CategoryGrade(mail, grade_for_score(mail, allow_plus=False))
    if any(f.points is not None for f in by_cat[Category.DNS]):
        dns = simple_score(by_cat[Category.DNS])
        grades[Category.DNS.name] = CategoryGrade(dns, grade_for_score(dns, allow_plus=False))
    else:
        grades[Category.DNS.name] = CategoryGrade(None, "N/A", M("DNSSEC and CAA could not be checked."))
    return grades


def overall_grade(grades: dict[str, CategoryGrade]) -> str:
    applicable = [g.grade for g in grades.values() if g.grade in GRADE_ORDER]
    return max(applicable, key=GRADE_ORDER.index) if applicable else "N/A"
