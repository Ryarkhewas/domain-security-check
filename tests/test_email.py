import pytest

from auditdomaine.email_checks import analyser_dkim, analyser_dmarc, analyser_mx, analyser_spf
from auditdomaine.modeles import Statut


def statuts(constats):
    return [c.statut for c in constats]


@pytest.mark.parametrize("record, attendu", [
    ("v=spf1 include:_spf.google.com -all", Statut.OK),
    ("v=spf1 include:_spf.google.com ~all", Statut.OK),
    ("v=spf1 include:_spf.google.com ?all", Statut.ATTENTION),
    ("v=spf1 +all", Statut.CRITIQUE),
    ("v=spf1 a mx all", Statut.CRITIQUE),
    ("v=spf1 include:_spf.google.com", Statut.ATTENTION),
    ("v=spf1 redirect=_spf.exemple.fr", Statut.OK),
])
def test_spf_regle_all(record, attendu):
    constats = analyser_spf([record, "autre=txt"])
    assert constats[0].statut == attendu


def test_spf_absent():
    assert statuts(analyser_spf(["google-site-verification=x"])) == [Statut.CRITIQUE]


def test_spf_double():
    c = analyser_spf(["v=spf1 -all", "v=spf1 mx -all"])
    assert c[0].statut == Statut.CRITIQUE and "2 enregistrements" in c[0].detail


def test_spf_trop_de_requetes():
    includes = " ".join(f"include:s{i}.exemple.fr" for i in range(11))
    c = analyser_spf([f"v=spf1 {includes} -all"])
    assert any("requêtes DNS" in x.titre and x.statut == Statut.ATTENTION for x in c)


def test_spf_all_ne_compte_pas_comme_a():
    c = analyser_spf(["v=spf1 " + " ".join(f"include:s{i}.fr" for i in range(10)) + " -all"])
    assert len(c) == 1  # 10 requêtes : à la limite, pas d'alerte


@pytest.mark.parametrize("record, attendu", [
    ("v=DMARC1; p=reject; rua=mailto:a@b.fr", Statut.OK),
    ("v=DMARC1; p=quarantine; rua=mailto:a@b.fr", Statut.OK),
    ("v=DMARC1; p=none; rua=mailto:a@b.fr", Statut.ATTENTION),
    ("v=DMARC1; p=n'importe; rua=mailto:a@b.fr", Statut.CRITIQUE),
    ("v=DMARC1; rua=mailto:a@b.fr", Statut.CRITIQUE),
])
def test_dmarc_politique(record, attendu):
    assert analyser_dmarc([record])[0].statut == attendu


def test_dmarc_absent_et_double():
    assert statuts(analyser_dmarc([])) == [Statut.CRITIQUE]
    assert statuts(analyser_dmarc(["v=DMARC1; p=none", "v=DMARC1; p=reject"])) == [Statut.CRITIQUE]


def test_dmarc_pct_et_rua():
    c = analyser_dmarc(["v=DMARC1; p=reject; pct=50"])
    titres = [x.titre for x in c]
    assert "DMARC : couverture" in titres and "DMARC : rapports" in titres


def test_dmarc_espaces_et_casse():
    assert analyser_dmarc(["v=DMARC1 ; P=Reject ; rua=mailto:x@y.fr"])[0].statut == Statut.OK


def test_dkim():
    assert analyser_dkim(["google"], ["google", "default"])[0].statut == Statut.OK
    assert analyser_dkim([], ["google", "default"])[0].statut == Statut.INFO


def test_mx():
    assert analyser_mx([])[0].statut == Statut.INFO
    assert analyser_mx(["mx.exemple.fr"])[0].statut == Statut.OK
