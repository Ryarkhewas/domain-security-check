"""Grades over time: one point per audit of a domain, kept in <report>.history.json.

Each audit adds its date, its overall grade and the grade and score of each
area. The report then draws how the grades evolved (from two audits on), and
shows the same values in a table.
"""

from __future__ import annotations

import contextlib
import json
from datetime import datetime
from pathlib import Path

from .models import Result

AREAS = ["WEB", "TLS", "EMAIL", "DNS"]


def point(r: Result) -> dict:
    return {"date": r.date.isoformat(), "grade": r.grade,
            "grades": {k: g.grade for k, g in r.grades.items()},
            "scores": {k: g.score for k, g in r.grades.items()}}


def _from_result_json(data: dict) -> dict | None:
    """A point from a saved result (<domain>.json of a version without history)."""
    try:
        grades = data["grades"]
        return {"date": str(data["date"]), "grade": str(data["grade"]),
                "grades": {k: g["grade"] for k, g in grades.items()},
                "scores": {k: g["score"] for k, g in grades.items()}}
    except (KeyError, TypeError):
        return None


def load(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    points = data.get("points", []) if isinstance(data, dict) else []
    return [p for p in points if isinstance(p, dict) and "date" in p and "scores" in p]


def update(path: Path, r: Result, previous: dict | None = None) -> list[dict]:
    """Add this audit to the domain's history file and return all points, oldest first.

    `previous` is the last saved result: it starts the history when the file does not exist yet.
    """
    points = load(path)
    if not points and previous and previous.get("domain") == r.domain:
        first = _from_result_json(previous)
        if first:
            points.append(first)
    points.append(point(r))
    points.sort(key=lambda p: p["date"])
    with contextlib.suppress(OSError):  # a read-only folder must not stop the report
        path.write_text(json.dumps({"domain": r.domain, "points": points}, indent=1), encoding="utf-8")
    return points


def day(p: dict) -> str:
    """"2026-10-27" from the point's ISO date."""
    try:
        return datetime.fromisoformat(p["date"]).date().isoformat()
    except ValueError:
        return str(p["date"])[:10]
