"""References shown under each finding: the standard, then the ANSSI guides."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.dns_checks import check_registration
from domaincheck.models import RDAPInfo
from domaincheck.observatory import TEST_FOR_SOURCE
from domaincheck.report import render_html
from domaincheck.sources import ANSSI, ANSSI_GUIDES, SOURCES, references


def demo():
    return run_audit("bakery-example.com", collector=DemoCollector())


def test_every_anssi_entry_points_to_a_known_source_and_guide():
    for key, refs in ANSSI.items():
        assert key in SOURCES, key
        assert refs
        for guide, recommendation in refs:
            assert guide in ANSSI_GUIDES
            assert re.fullmatch(r"(R\d+[+-]?)(, R\d+[+-]?)*|§\d+(\.\d+)*", recommendation), recommendation


def test_guides_are_official_pdfs_with_version_and_year():
    for label, url in ANSSI_GUIDES.values():
        assert url.startswith("https://") and "cyber.gouv.fr/" in url and url.endswith(".pdf")
        assert re.search(r"v\d+\.\d+ \(20\d\d\)$", label), label


def test_references_put_the_standard_first():
    refs = references("dnssec")
    assert refs[0] == (*SOURCES["dnssec"], "")
    assert [r[2] for r in refs[1:]] == ["R4+", "R50+"]
    assert references("null-mx") == [(*SOURCES["null-mx"], "")]
    assert references("unknown") == []


def test_every_finding_of_the_demo_has_a_known_source():
    for f in demo().findings:
        assert f.source in SOURCES, (f.title, f.source)


def test_transfer_lock_has_its_own_source():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    info = RDAPInfo("example.com", now + timedelta(days=300), ["active"], "Registrar", "")
    expiry, lock = check_registration(info, now)
    assert (expiry.source, lock.source) == ("rdap", "transfer-lock")
    assert "transfer-lock" not in TEST_FOR_SOURCE


def test_html_report_lists_every_reference():
    html = render_html(demo())
    assert "Sources:" in html
    assert "ANSSI website guide PA-009 v2.0 (2021), R2</a>" in html
    assert "ANSSI Internet gateway guide PA-066 v3.0 (2020), R44</a>" in html
    assert not re.search(r"compl\w* (with )?anssi|anssi[- ]compliant", html.lower())


def test_french_report_translates_the_guide_names():
    html = render_html(demo(), lang="fr")
    assert "Sources :" in html
    assert "Guide ANSSI site web PA-009 v2.0 (2021), R2</a>" in html
    assert "Guide ANSSI noms de domaine BP-038 v1.3 (2017), R4+</a>" in html
    assert not re.search(r"conforme? (à l.|aux? )?(recommandations )?(de l.)?anssi", html.lower())
