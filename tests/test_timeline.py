"""Grades over time: history file and chart."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from domaincheck import cli
from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.report import render_html, render_json, timeline_rows
from domaincheck.timeline import day, load, point, update


def demo(days_ago=0):
    r = run_audit("bakery-example.com", collector=DemoCollector())
    r.date = datetime(2026, 10, 27, tzinfo=timezone.utc) - timedelta(days=days_ago)
    return r


def test_history_file_grows(tmp_path):
    path = tmp_path / "x.history.json"
    assert len(update(path, demo(14))) == 1
    assert len(update(path, demo(7))) == 2
    points = update(path, demo(0))
    assert [day(p) for p in points] == ["2026-10-13", "2026-10-20", "2026-10-27"]
    assert load(path) == points
    assert points[-1]["scores"]["WEB"] == 15 and points[-1]["grades"]["DNS"] == "C-"


def test_history_starts_from_the_previous_result(tmp_path):
    previous = json.loads(render_json(demo(7)))
    points = update(tmp_path / "x.history.json", demo(0), previous)
    assert [day(p) for p in points] == ["2026-10-20", "2026-10-27"]
    other = dict(previous, domain="other.example")
    assert len(update(tmp_path / "y.history.json", demo(0), other)) == 1


def test_unreadable_history_starts_again(tmp_path):
    path = tmp_path / "x.history.json"
    path.write_text("not json", encoding="utf-8")
    assert load(path) == []
    assert len(update(path, demo())) == 1


def test_chart_from_two_audits():
    r = demo()
    r.history = [point(demo(7)), point(r)]
    html = render_html(r)
    assert '<section class="timeline">' in html and html.count("<polyline") == 4
    assert "<title>Website · 2026-10-27 · F (15)</title>" in html  # hover tooltip
    r.history = [point(r)]
    assert '<section class="timeline">' not in render_html(r)
    r.history = None
    assert '<section class="timeline">' not in render_html(r)


def test_table_view():
    header, rows = timeline_rows([point(demo(7)), point(demo())], str)
    assert header[:2] == ["Date", "Overall"] and rows[0][0] == "2026-10-20" and rows[0][2] == "F (15)"


def test_saved_result_does_not_carry_the_history():
    r = demo()
    r.history = [point(r)]
    assert "history" not in json.loads(render_json(r))


def test_cli_draws_the_chart_from_the_second_run(tmp_path):
    out = tmp_path / "r.html"
    assert cli.main(["--demo", "-o", str(out)]) == 0
    assert '<section class="timeline">' not in out.read_text(encoding="utf-8")
    assert cli.main(["--demo", "-o", str(out), "--lang", "fr"]) == 0
    assert "Évolution des notes" in out.read_text(encoding="utf-8")
    assert len(load(tmp_path / "r.history.json")) == 2


def test_pdf_with_the_chart():
    import pytest

    pytest.importorskip("reportlab")
    from domaincheck.pdf_report import render_pdf

    r = demo()
    r.history = [point(demo(7)), point(r)]
    assert render_pdf(r, lang="fr").startswith(b"%PDF")
