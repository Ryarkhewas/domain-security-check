"""Orchestration : normalisation du domaine, analyses, notation."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .email_checks import analyser_dkim, analyser_dmarc, analyser_mx, analyser_spf
from .modeles import DonneesCollectees, Resultat, Statut
from .web_checks import analyser_certificat, analyser_entetes, analyser_redirection

PENALITES = {Statut.CRITIQUE: 20, Statut.ATTENTION: 5, Statut.INFO: 0, Statut.OK: 0}
SEUILS_NOTE = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]

_DOMAINE_VALIDE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


class DomaineInvalide(ValueError):
    pass


def normaliser_domaine(saisie: str) -> str:
    """« https://WWW.Exemple.fr/contact » → « www.exemple.fr »"""
    d = saisie.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1].split(":")[0].rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")  # domaines accentués
    except UnicodeError as e:
        raise DomaineInvalide(f"Nom de domaine invalide : {saisie!r}") from e
    if not _DOMAINE_VALIDE.match(d):
        raise DomaineInvalide(f"Nom de domaine invalide : {saisie!r}")
    return d


def domaine_email(domaine: str) -> str:
    """Les enregistrements SPF/DMARC sont sur le domaine principal, pas sur « www »."""
    return domaine[4:] if domaine.startswith("www.") else domaine


def calculer_score(constats) -> tuple[int, str]:
    score = max(0, 100 - sum(PENALITES[c.statut] for c in constats))
    note = next(n for seuil, n in SEUILS_NOTE if score >= seuil)
    return score, note


def analyser(donnees: DonneesCollectees, selecteurs_testes: list[str], maintenant: datetime | None = None) -> Resultat:
    constats = []
    constats += analyser_certificat(donnees.certificat, maintenant)
    constats += analyser_redirection(donnees.http)
    if donnees.http.https_joignable:
        constats += analyser_entetes(donnees.http.entetes)
    constats += analyser_mx(donnees.mx)
    constats += analyser_spf(donnees.txt_racine)
    constats += analyser_dmarc(donnees.txt_dmarc)
    constats += analyser_dkim(donnees.selecteurs_dkim, selecteurs_testes)

    score, note = calculer_score(constats)
    return Resultat(
        domaine=donnees.domaine,
        date=maintenant or datetime.now(timezone.utc),
        constats=constats,
        score=score,
        note=note,
    )


def auditer(saisie: str, collecteur=None) -> Resultat:
    from .collecte import SELECTEURS_DKIM, Collecteur

    domaine = normaliser_domaine(saisie)
    collecteur = collecteur or Collecteur()
    d_mail = domaine_email(domaine)

    if hasattr(collecteur, "verifier_existence"):
        collecteur.verifier_existence(domaine)

    donnees = DonneesCollectees(
        domaine=domaine,
        txt_racine=collecteur.txt(d_mail),
        txt_dmarc=collecteur.txt(f"_dmarc.{d_mail}"),
        mx=collecteur.mx(d_mail),
        selecteurs_dkim=collecteur.selecteurs_dkim(d_mail),
        certificat=collecteur.certificat(domaine),
        http=collecteur.http(domaine),
    )
    return analyser(donnees, SELECTEURS_DKIM)
