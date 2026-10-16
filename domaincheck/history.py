"""Changes since the previous audit of the same domain.

Each report is saved with its result in JSON (<domain>.json next to the HTML
report). On the next audit, that file is read before being replaced, and the
two audits are compared: grades that went up or down, problems fixed, new
problems, and problems that got worse or better. This is what a regular
follow-up (for instance a weekly audit) shows to the domain owner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .models import Category, Result, Status
from .scoring import GRADE_ORDER

PROBLEMS = (Status.CRITICAL.value, Status.WARNING.value)


@dataclass
class GradeChange:
    key: str  # "OVERALL" or a Category name ("WEB", "TLS", ...)
    old: str
    new: str

    @property
    def better(self) -> bool:
        if self.old not in GRADE_ORDER or self.new not in GRADE_ORDER:
            return False
        return GRADE_ORDER.index(self.new) < GRADE_ORDER.index(self.old)


@dataclass
class FindingChange:
    category: str  # Category name
    title: str
    old: str  # status value, "" if the check did not exist
    new: str  # status value, "" if the check no longer appears


@dataclass
class Changes:
    previous_date: datetime
    grades: list[GradeChange] = field(default_factory=list)
    fixed: list[FindingChange] = field(default_factory=list)
    new: list[FindingChange] = field(default_factory=list)
    worse: list[FindingChange] = field(default_factory=list)
    better: list[FindingChange] = field(default_factory=list)

    @property
    def nothing(self) -> bool:
        return not (self.grades or self.fixed or self.new or self.worse or self.better)


def load_previous(path: Path) -> dict | None:
    """Result of the previous audit saved at path, or None (no file, or a file that cannot be read)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "findings" not in data or "date" not in data:
        return None
    return data


def compare(previous: dict, current: Result) -> Changes:
    """What changed between a previous audit (as saved in JSON) and the current one."""
    try:
        previous_date = datetime.fromisoformat(previous["date"])
    except (TypeError, ValueError):
        previous_date = current.date
    changes = Changes(previous_date)

    old_grades = {"OVERALL": previous.get("grade", "")} | {
        k: (g or {}).get("grade", "") for k, g in (previous.get("grades") or {}).items()}
    new_grades = {"OVERALL": current.grade} | {k: g.grade for k, g in current.grades.items()}
    for key, new in new_grades.items():
        old = old_grades.get(key)
        if old and old != new:
            changes.grades.append(GradeChange(key, old, new))

    names = {c.value: c.name for c in Category}
    old_status: dict[tuple[str, str], str] = {
        (names.get(str(f.get("category", "")), ""), str(f.get("title", ""))): str(f.get("status", ""))
        for f in previous.get("findings", []) if isinstance(f, dict)}
    new_status = {(f.category.name, str(f.title)): f.status.value for f in current.findings}
    compared = {category for category, _ in old_status}  # areas a previous version did not check are skipped

    for finding in sorted(set(old_status) | set(new_status)):
        category, title = finding
        if category not in compared:
            continue
        old, new = old_status.get(finding, ""), new_status.get(finding, "")
        change = FindingChange(category, title, old, new)
        if old in PROBLEMS and new not in PROBLEMS:
            changes.fixed.append(change)
        elif new in PROBLEMS and old not in PROBLEMS:
            changes.new.append(change)
        elif old == Status.WARNING.value and new == Status.CRITICAL.value:
            changes.worse.append(change)
        elif old == Status.CRITICAL.value and new == Status.WARNING.value:
            changes.better.append(change)
    return changes
