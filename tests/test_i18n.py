"""Report languages: every text has its French translation, with the same placeholders."""

import string

import pytest

from domaincheck import cli
from domaincheck.audit import analyze, run_audit
from domaincheck.demo import DemoCollector
from domaincheck.i18n import Joined, M, MissingTranslation, date, tr
from domaincheck.locales.fr import FR
from domaincheck.models import CollectedData, DNSSECInfo, HTTPInfo, MTASTSInfo
from domaincheck.report import console_summary, render_html, render_index
from tests.translatable import translatable_texts

TEXTS = translatable_texts()


def placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def test_every_text_has_a_french_translation():
    missing = sorted(t for t in TEXTS if t not in FR)
    assert not missing, "Missing in locales/fr.py:\n" + "\n".join(missing)


def test_no_unused_translation():
    unused = sorted(t for t in FR if t not in TEXTS)
    assert not unused, "Not used anywhere in the code:\n" + "\n".join(unused)


@pytest.mark.parametrize("english", sorted(FR))
def test_placeholders_are_kept(english):
    assert placeholders(FR[english]) == placeholders(english)


def test_message_is_the_english_text():
    m = M("Present (max-age={age}).", age=300)
    assert m == "Present (max-age=300)." and isinstance(m, str)
    assert tr(m, "fr") == "Présent (max-age=300)."
    assert tr(m, "en") == "Present (max-age=300)."


def test_nested_messages_and_lists_are_translated():
    zone = M("the zone")
    message = M("Not enabled for {zone}: DNS answers are not signed, so a resolver cannot detect forged answers "
                "(redirecting visitors or emails to another server).", zone=zone)
    assert tr(message, "fr").startswith("Non activé pour la zone")
    problems = Joined([M("no mx line"), M("max_age missing or invalid")])
    assert tr(M("The policy file is invalid: {problems}.", problems=problems), "fr") == \
        "Le fichier de politique est invalide : aucune ligne mx, max_age absent ou invalide."


def test_unknown_text_falls_back_to_english_or_fails_in_strict_mode():
    assert tr("Something new", "fr") == "Something new"
    with pytest.raises(MissingTranslation):
        tr("Something new", "fr", strict=True)


def test_dates():
    from datetime import datetime

    assert date(datetime(2026, 10, 16), "fr") == "16/10/2026"
    assert date(datetime(2026, 10, 16), "en") == "2026-10-16"


def results():
    """A few audits covering many branches, rendered in strict mode below."""
    demo = run_audit("example.com", collector=DemoCollector())
    mail_only = analyze(CollectedData("mail.example", ["v=spf1 -all"], ["v=DMARC1; p=reject"], ["mx.example.net"], [],
                                      None, HTTPInfo(False), dnssec=DNSSECInfo(zone="example", ds_count=1),
                                      mta_sts=MTASTSInfo(["v=STSv1; id=1"], None, "HTTP 404")), [])
    return [demo, mail_only]


def test_reports_render_fully_in_french():
    for r in results():
        for f in r.findings:
            for text in (f.title, f.detail, f.recommendation):
                tr(text, "fr", strict=True)
        for g in r.grades.values():
            tr(g.note, "fr", strict=True)
        html = render_html(r, "Loïc Tellier", "fr")
        assert '<html lang="fr">' in html and "Méthode." in html
        assert "Audit passif réalisé par Loïc Tellier" in html
        console_summary(r, "fr")
    assert "Domaines" not in render_index(results(), {"x.example": "DNS"}, lang="fr")
    assert "Non audité : DNS" in render_index(results(), {"x.example": "DNS"}, lang="fr")


def test_french_text_starts_with_a_capital():
    r = results()[1]  # DMARC "reject" without inheritance: the French template starts with {origin}
    html = render_html(r, lang="fr")
    assert "Politique « reject »" in html


def test_cli_french_report(tmp_path, capsys):
    assert cli.main(["--demo", "--lang", "fr", "-o", str(tmp_path / "r.html")]) == 0
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "Actions prioritaires" in html and "Redirection HTTP vers HTTPS" in html
    assert "note globale" in capsys.readouterr().out
