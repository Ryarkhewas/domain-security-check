"""Branded reports: branding file, command-line options, PDF cover page."""

from __future__ import annotations

import json
import re

import pytest

from domaincheck import cli
from domaincheck.audit import run_audit
from domaincheck.branding import DEFAULT_COLOR, Branding, BrandingError, load, merge
from domaincheck.demo import DemoCollector

reportlab = pytest.importorskip("reportlab")


@pytest.fixture
def logo(tmp_path):
    from PIL import Image

    path = tmp_path / "logo.png"
    Image.new("RGB", (300, 100), "#0f766e").save(path)
    return path


def pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf))


def test_load_and_merge(tmp_path, logo):
    (tmp_path / "brand.json").write_text(json.dumps({"author": "A", "company": "Co", "logo": "logo.png",
                                                     "color": "#0f766e"}), encoding="utf-8")
    b = load(tmp_path / "brand.json")
    assert (b.author, b.company, b.logo, b.color) == ("A", "Co", logo, "#0f766e")
    merged = merge(b, author="", client="Client", color="#123456")
    assert (merged.author, merged.client, merged.color) == ("A", "Client", "#123456")
    assert merged.check() is merged


def test_errors(tmp_path):
    (tmp_path / "bad.json").write_text('{"compagny": "typo"}', encoding="utf-8")
    with pytest.raises(BrandingError, match="unknown key"):
        load(tmp_path / "bad.json")
    with pytest.raises(BrandingError, match="cannot read"):
        load(tmp_path / "missing.json")
    with pytest.raises(BrandingError, match="colour"):
        Branding(color="green").check()
    with pytest.raises(BrandingError, match="logo not found"):
        Branding(logo=tmp_path / "nope.png").check()
    (tmp_path / "logo.gif").write_bytes(b"GIF89a")
    with pytest.raises(BrandingError, match="PNG or JPEG"):
        Branding(logo=tmp_path / "logo.gif").check()


def test_cover_page_only_when_branded(logo):
    from domaincheck.pdf_report import render_pdf

    r = run_audit("bakery-example.com", collector=DemoCollector())
    plain = render_pdf(r, "Author")
    branded = render_pdf(r, lang="fr", branding=Branding("Author", "Co", "c@example.com", "Client", logo, "#0f766e"))
    assert pages(branded) == pages(plain) + 1
    assert not Branding(author="Only an author").custom
    assert Branding(color=DEFAULT_COLOR, client="X").custom


def test_cli_brand_file(tmp_path, logo):
    (tmp_path / "brand.json").write_text(json.dumps({"company": "Co", "logo": str(logo)}), encoding="utf-8")
    out = tmp_path / "r.html"
    assert cli.main(["--demo", "--pdf", "--brand", str(tmp_path / "brand.json"), "--client", "Client",
                     "--author", "Me", "-o", str(out)]) == 0
    assert out.with_suffix(".pdf").stat().st_size > 0
    html = out.read_text(encoding="utf-8")
    assert "Prepared for Client" in html and "Prepared by Me · Co" in html


def test_cli_rejects_a_bad_colour(tmp_path, capsys):
    assert cli.main(["--demo", "--color", "blue", "-o", str(tmp_path / "r.html")]) == 1
    assert "colour" in capsys.readouterr().err
