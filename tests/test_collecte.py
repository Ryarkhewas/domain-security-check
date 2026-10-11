"""Le collecteur doit distinguer « n'existe pas » de « impossible de vérifier »."""

import dns.exception
import dns.resolver
import pytest

from auditdomaine.collecte import Collecteur, DomaineInexistant, ErreurCollecte


class FauxEnregistrementTXT:
    def __init__(self, texte):
        self.strings = [texte.encode()]


class FauxResolver:
    def __init__(self, reponses):
        self.reponses = reponses  # (nom, type) -> liste | exception

    def resolve(self, nom, type_, search=True):
        r = self.reponses.get((nom, type_), dns.resolver.NoAnswer())
        if isinstance(r, Exception):
            raise r
        return r


def collecteur(reponses):
    c = Collecteur.__new__(Collecteur)
    c.timeout = 1
    c.resolver = FauxResolver(reponses)
    return c


def test_txt_absent_renvoie_liste_vide():
    c = collecteur({("exemple.fr", "TXT"): dns.resolver.NoAnswer()})
    assert c.txt("exemple.fr") == []
    c = collecteur({("_dmarc.exemple.fr", "TXT"): dns.resolver.NXDOMAIN()})
    assert c.txt("_dmarc.exemple.fr") == []


def test_txt_lu():
    c = collecteur({("exemple.fr", "TXT"): [FauxEnregistrementTXT("v=spf1 -all")]})
    assert c.txt("exemple.fr") == ["v=spf1 -all"]


@pytest.mark.parametrize("panne", [dns.exception.Timeout(), dns.resolver.NoNameservers()])
def test_panne_dns_n_est_pas_une_absence(panne):
    c = collecteur({("exemple.fr", "TXT"): panne})
    with pytest.raises(ErreurCollecte):
        c.txt("exemple.fr")


def test_domaine_inexistant():
    c = collecteur({("inconnu.fr", "SOA"): dns.resolver.NXDOMAIN()})
    with pytest.raises(DomaineInexistant):
        c.verifier_existence("inconnu.fr")


def test_sous_domaine_existant_sans_soa():
    c = collecteur({("www.exemple.fr", "SOA"): dns.resolver.NoAnswer()})
    c.verifier_existence("www.exemple.fr")  # ne lève rien


def test_existence_panne():
    c = collecteur({("exemple.fr", "SOA"): dns.exception.Timeout()})
    with pytest.raises(ErreurCollecte):
        c.verifier_existence("exemple.fr")
