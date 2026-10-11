import json

import pytest

import audit as cli
from auditdomaine.audit import DomaineInvalide, auditer, calculer_score, domaine_email, normaliser_domaine
from auditdomaine.demo import CollecteurDemo
from auditdomaine.modeles import Categorie, Constat, Statut
from auditdomaine.rapport import generer_html, generer_json


@pytest.mark.parametrize("saisie, attendu", [
    ("exemple.fr", "exemple.fr"),
    ("  HTTPS://WWW.Exemple.fr/contact?x=1 ", "www.exemple.fr"),
    ("http://exemple.fr:8080/", "exemple.fr"),
    ("exemple.fr.", "exemple.fr"),
    ("Boulangerie-Élysée.fr", "boulangerie-élysée.fr".encode("idna").decode()),
])
def test_normalisation(saisie, attendu):
    assert normaliser_domaine(saisie) == attendu


@pytest.mark.parametrize("saisie", ["", "localhost", "exemple", "-exemple.fr", "ex ample.fr", "192.168.1.1"])
def test_domaine_invalide(saisie):
    with pytest.raises(DomaineInvalide):
        normaliser_domaine(saisie)


def test_domaine_email():
    assert domaine_email("www.exemple.fr") == "exemple.fr"
    assert domaine_email("boutique.exemple.fr") == "boutique.exemple.fr"


def _c(statut):
    return Constat(Categorie.WEB, "t", statut, "d")


def test_score():
    assert calculer_score([_c(Statut.OK)] * 5) == (100, "A")
    assert calculer_score([_c(Statut.CRITIQUE)] * 2) == (60, "C")
    assert calculer_score([_c(Statut.CRITIQUE)] * 6) == (0, "F")
    assert calculer_score([_c(Statut.INFO)] * 10) == (100, "A")


class Espion(CollecteurDemo):
    """Enregistre les noms interrogés pour vérifier l'orchestration."""

    def __init__(self):
        self.appels = []

    def txt(self, nom):
        self.appels.append(("txt", nom))
        return super().txt(nom)

    def certificat(self, hote):
        self.appels.append(("cert", hote))
        return super().certificat(hote)


def test_www_email_sur_domaine_racine():
    espion = Espion()
    r = auditer("https://www.exemple.fr", collecteur=espion)
    assert r.domaine == "www.exemple.fr"
    assert ("txt", "exemple.fr") in espion.appels
    assert ("txt", "_dmarc.exemple.fr") in espion.appels
    assert ("cert", "www.exemple.fr") in espion.appels


def test_demo_complet():
    r = auditer("boulangerie-exemple.fr", collecteur=CollecteurDemo())
    assert r.note == "C"
    assert {c.categorie for c in r.constats} == set(Categorie)


def test_html_echappe_le_contenu():
    class Piege(CollecteurDemo):
        def http(self, hote):
            info = super().http(hote)
            info.entetes["Server"] = "<script>alert(1)</script>/1.0"
            return info

    html = generer_html(auditer("exemple.fr", collecteur=Piege()))
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html


def test_json_valide():
    data = json.loads(generer_json(auditer("exemple.fr", collecteur=CollecteurDemo())))
    assert data["domaine"] == "exemple.fr"
    assert data["constats"][0]["statut"] in {"ok", "attention", "critique", "info"}


def test_cli_demo(tmp_path, capsys):
    sortie = tmp_path / "r.html"
    assert cli.main(["--demo", "-o", str(sortie), "--auteur", "Test"]) == 0
    assert "par Test" in sortie.read_text(encoding="utf-8")
    assert "note C" in capsys.readouterr().out


def test_cli_domaine_invalide(capsys):
    assert cli.main(["pas un domaine"]) == 1
