"""PDF report (needs the [pdf] extra, installed with [dev])."""

import builtins

import pytest

from domaincheck import cli
from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.pdf_report import render_pdf

pytest.importorskip("reportlab")


def demo():
    return run_audit("example.com", collector=DemoCollector())


def test_pdf_is_produced():
    pdf = render_pdf(demo(), "Loïc Tellier")
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 5_000


def test_text_the_font_cannot_draw_does_not_break_the_pdf():
    r = demo()
    r.findings[0].detail += " → ✓ <b>not markup</b> & co"
    assert render_pdf(r).startswith(b"%PDF-")


def test_cli_writes_the_pdf_next_to_the_html(tmp_path):
    assert cli.main(["--demo", "--pdf", "-o", str(tmp_path / "r.html")]) == 0
    assert (tmp_path / "r.pdf").read_bytes().startswith(b"%PDF-")


def test_cli_explains_how_to_install_reportlab(monkeypatch, tmp_path, capsys):
    real_import = builtins.__import__

    def no_reportlab(name, *args, **kwargs):
        if name == "reportlab" or name.startswith("reportlab."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_reportlab)
    assert cli.main(["--demo", "--pdf", "-o", str(tmp_path / "r.html")]) == 1
    assert "domain-security-check[pdf]" in capsys.readouterr().err
