"""Analyse de la protection des emails : MX, SPF, DMARC, DKIM.

Ces fonctions ne font aucun accès réseau : elles reçoivent les enregistrements
DNS déjà récupérés, ce qui les rend faciles à tester.
"""

from __future__ import annotations

import re

from .modeles import Categorie, Constat, Statut

C = Categorie.EMAIL

# Mécanismes SPF qui coûtent une requête DNS (limite RFC 7208 : 10)
_MECANISMES_DNS = re.compile(r"^[+\-~?]?(include:|a\b|a:|a/|mx\b|mx:|mx/|ptr|exists:|redirect=)", re.I)


def analyser_mx(mx: list[str]) -> list[Constat]:
    if not mx:
        return [Constat(
            C, "Serveurs de réception (MX)", Statut.INFO,
            "Aucun serveur MX : ce domaine ne reçoit pas d'email.",
            "Si le domaine n'envoie pas non plus d'email, publiez « v=spf1 -all » et une politique "
            "DMARC « p=reject » pour empêcher qu'on l'utilise pour usurper votre identité.",
        )]
    return [Constat(C, "Serveurs de réception (MX)", Statut.OK, f"{len(mx)} serveur(s) : {', '.join(mx[:3])}")]


def analyser_spf(txt_racine: list[str]) -> list[Constat]:
    titre = "SPF (expéditeurs autorisés)"
    spf = [t for t in txt_racine if t.lower().startswith("v=spf1")]

    if not spf:
        return [Constat(
            C, titre, Statut.CRITIQUE,
            "Aucun enregistrement SPF : n'importe qui peut envoyer des emails en se faisant passer pour ce domaine.",
            "Publiez un enregistrement TXT SPF listant vos services d'envoi (ex. « v=spf1 include:_spf.google.com -all »).",
        )]
    if len(spf) > 1:
        return [Constat(
            C, titre, Statut.CRITIQUE,
            f"{len(spf)} enregistrements SPF trouvés : c'est invalide, les serveurs de réception les ignorent tous.",
            "Fusionnez-les en un seul enregistrement SPF.",
        )]

    record = spf[0]
    termes = record.split()[1:]
    constats: list[Constat] = []

    terme_all = next((t for t in termes if t.lower().lstrip("+-~?") == "all"), None)
    if terme_all is None and not any(t.lower().startswith("redirect=") for t in termes):
        constats.append(Constat(
            C, titre, Statut.ATTENTION,
            f"Le SPF ne se termine pas par une règle « all » : « {record} ».",
            "Terminez l'enregistrement par « -all » (ou « ~all » pendant une phase de test).",
        ))
    elif terme_all in ("all", "+all"):
        constats.append(Constat(
            C, titre, Statut.CRITIQUE,
            "Le SPF se termine par « +all » : il autorise le monde entier à envoyer en votre nom.",
            "Remplacez « +all » par « -all ».",
        ))
    elif terme_all == "?all":
        constats.append(Constat(
            C, titre, Statut.ATTENTION,
            "Le SPF se termine par « ?all » (neutre) : il n'apporte quasiment aucune protection.",
            "Passez à « ~all » puis « -all » une fois vos expéditeurs listés.",
        ))
    elif terme_all == "~all":
        constats.append(Constat(
            C, titre, Statut.OK,
            "SPF présent avec « ~all » (échec souple). Correct, surtout combiné à DMARC.",
            "Quand vous êtes sûr de la liste de vos expéditeurs, passez à « -all ».",
        ))
    else:
        constats.append(Constat(C, titre, Statut.OK, "SPF présent et strict (« -all »)."))

    nb_requetes = sum(1 for t in termes if _MECANISMES_DNS.match(t))
    if nb_requetes > 10:
        constats.append(Constat(
            C, "SPF : nombre de requêtes DNS", Statut.ATTENTION,
            f"{nb_requetes} mécanismes nécessitent une requête DNS (limite : 10). Le SPF risque d'être rejeté.",
            "Réduisez le nombre d'« include » ou utilisez un service d'aplatissement SPF.",
        ))
    return constats


def _balises_dmarc(record: str) -> dict[str, str]:
    balises = {}
    for morceau in record.split(";"):
        if "=" in morceau:
            cle, val = morceau.split("=", 1)
            balises[cle.strip().lower()] = val.strip()
    return balises


def analyser_dmarc(txt_dmarc: list[str]) -> list[Constat]:
    titre = "DMARC (politique anti-usurpation)"
    dmarc = [t for t in txt_dmarc if t.lower().replace(" ", "").startswith("v=dmarc1")]

    if not dmarc:
        return [Constat(
            C, titre, Statut.CRITIQUE,
            "Aucune politique DMARC : les messages frauduleux utilisant votre domaine ne sont ni bloqués ni signalés.",
            "Publiez un enregistrement TXT sur _dmarc.<domaine>, en commençant par "
            "« v=DMARC1; p=none; rua=mailto:dmarc@<domaine> » pour observer, puis durcissez.",
        )]
    if len(dmarc) > 1:
        return [Constat(
            C, titre, Statut.CRITIQUE,
            "Plusieurs enregistrements DMARC : c'est invalide, ils sont ignorés.",
            "Conservez un seul enregistrement DMARC.",
        )]

    b = _balises_dmarc(dmarc[0])
    politique = b.get("p", "").lower()
    constats: list[Constat] = []

    if politique == "reject":
        constats.append(Constat(C, titre, Statut.OK, "Politique « reject » : les emails usurpés sont rejetés."))
    elif politique == "quarantine":
        constats.append(Constat(
            C, titre, Statut.OK,
            "Politique « quarantine » : les emails usurpés partent en spam.",
            "Passez à « p=reject » quand les rapports confirment que vos envois légitimes passent.",
        ))
    elif politique == "none":
        constats.append(Constat(
            C, titre, Statut.ATTENTION,
            "Politique « none » : DMARC observe mais ne bloque rien.",
            "Après quelques semaines d'analyse des rapports, passez à « p=quarantine » puis « p=reject ».",
        ))
    else:
        constats.append(Constat(
            C, titre, Statut.CRITIQUE,
            f"Politique DMARC absente ou invalide (p={politique or '?'}).",
            "Corrigez l'enregistrement : la balise p= doit valoir none, quarantine ou reject.",
        ))

    pct = b.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and politique in ("quarantine", "reject"):
        constats.append(Constat(
            C, "DMARC : couverture", Statut.ATTENTION,
            f"La politique ne s'applique qu'à {pct} % des messages.",
            "Montez progressivement à pct=100.",
        ))
    if "rua" not in b:
        constats.append(Constat(
            C, "DMARC : rapports", Statut.INFO,
            "Aucune adresse de rapport (rua) : vous ne voyez pas qui envoie en votre nom.",
            "Ajoutez « rua=mailto:… » pour recevoir les rapports agrégés.",
        ))
    return constats


def analyser_dkim(selecteurs_trouves: list[str], selecteurs_testes: list[str]) -> list[Constat]:
    titre = "DKIM (signature des emails)"
    if selecteurs_trouves:
        return [Constat(C, titre, Statut.OK, f"Clé(s) DKIM trouvée(s) : {', '.join(selecteurs_trouves)}.")]
    return [Constat(
        C, titre, Statut.INFO,
        f"Aucune clé DKIM trouvée parmi les sélecteurs courants testés ({len(selecteurs_testes)}). "
        "Ce n'est pas forcément un problème : le sélecteur peut avoir un autre nom.",
        "Vérifiez dans votre service d'envoi (Google Workspace, Microsoft 365…) que la signature DKIM est activée.",
    )]
