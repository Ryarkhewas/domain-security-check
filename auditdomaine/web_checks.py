"""Analyse du site web : certificat TLS, redirection HTTPS, en-têtes de sécurité.

Aucun accès réseau ici : les fonctions analysent des données déjà collectées.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Mapping

from .modeles import Categorie, Constat, InfoCertificat, InfoHTTP, Statut

W = Categorie.WEB
H = Categorie.ENTETES

SIX_MOIS = 15_552_000  # secondes


def analyser_certificat(cert: InfoCertificat | None, maintenant: datetime | None = None) -> list[Constat]:
    titre = "Certificat HTTPS"
    if cert is None:
        return [Constat(
            W, titre, Statut.CRITIQUE,
            "Impossible d'établir une connexion HTTPS sur le port 443.",
            "Installez un certificat (Let's Encrypt est gratuit) et activez HTTPS.",
        )]
    if not cert.valide:
        return [Constat(
            W, titre, Statut.CRITIQUE,
            f"Le certificat n'est pas reconnu comme valide : {cert.erreur or 'erreur inconnue'}. "
            "Les navigateurs affichent un avertissement aux visiteurs.",
            "Remplacez le certificat par un certificat valide couvrant ce nom de domaine.",
        )]

    constats: list[Constat] = []
    maintenant = maintenant or datetime.now(timezone.utc)
    if cert.expire_le:
        jours = (cert.expire_le - maintenant).days
        date_txt = f"{cert.expire_le:%d/%m/%Y}"
        if jours < 0:
            constats.append(Constat(W, titre, Statut.CRITIQUE, f"Certificat expiré depuis le {date_txt}.",
                                    "Renouvelez le certificat immédiatement."))
        elif jours < 15:
            constats.append(Constat(W, titre, Statut.CRITIQUE, f"Le certificat expire dans {jours} jour(s) ({date_txt}).",
                                    "Renouvelez-le maintenant et mettez en place le renouvellement automatique."))
        elif jours < 30:
            constats.append(Constat(W, titre, Statut.ATTENTION, f"Le certificat expire dans {jours} jours ({date_txt}).",
                                    "Vérifiez que le renouvellement automatique est bien en place."))
        else:
            emetteur = f", émis par {cert.emetteur}" if cert.emetteur else ""
            constats.append(Constat(W, titre, Statut.OK, f"Certificat valide jusqu'au {date_txt} ({jours} jours){emetteur}."))

    if cert.version_tls:
        if cert.version_tls in ("TLSv1", "TLSv1.1", "SSLv3"):
            constats.append(Constat(
                W, "Version du protocole TLS", Statut.CRITIQUE,
                f"Connexion négociée en {cert.version_tls}, une version obsolète et vulnérable.",
                "Désactivez TLS 1.0/1.1 sur le serveur et n'autorisez que TLS 1.2 et 1.3.",
            ))
        else:
            constats.append(Constat(W, "Version du protocole TLS", Statut.OK, f"Connexion négociée en {cert.version_tls}."))
    return constats


def analyser_redirection(http: InfoHTTP) -> list[Constat]:
    titre = "Redirection HTTP → HTTPS"
    if http.http_redirige_vers_https is None:
        return [Constat(W, titre, Statut.INFO, "Le site ne répond pas en HTTP simple (port 80). Rien à rediriger.")]
    if http.http_redirige_vers_https:
        return [Constat(W, titre, Statut.OK, "Les visiteurs arrivant en HTTP sont redirigés vers HTTPS.")]
    return [Constat(
        W, titre, Statut.ATTENTION,
        "Le site reste accessible en HTTP non chiffré, sans redirection.",
        "Configurez une redirection permanente (301) de HTTP vers HTTPS.",
    )]


def _entete(entetes: Mapping[str, str], nom: str) -> str | None:
    for cle, val in entetes.items():
        if cle.lower() == nom.lower():
            return val
    return None


def analyser_entetes(entetes: Mapping[str, str]) -> list[Constat]:
    constats: list[Constat] = []

    # HSTS
    hsts = _entete(entetes, "Strict-Transport-Security")
    if not hsts:
        constats.append(Constat(
            H, "HSTS", Statut.ATTENTION,
            "Absent : le navigateur n'est pas obligé d'utiliser HTTPS lors des visites suivantes.",
            "Ajoutez « Strict-Transport-Security: max-age=31536000; includeSubDomains ».",
        ))
    else:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < SIX_MOIS:
            constats.append(Constat(
                H, "HSTS", Statut.ATTENTION, f"Présent mais durée courte (max-age={age}).",
                "Utilisez au moins 6 mois (max-age=15552000), idéalement 1 an.",
            ))
        else:
            constats.append(Constat(H, "HSTS", Statut.OK, f"Présent (max-age={age})."))

    # CSP
    csp = _entete(entetes, "Content-Security-Policy")
    if not csp:
        constats.append(Constat(
            H, "Content-Security-Policy", Statut.ATTENTION,
            "Absent : aucune limite sur les scripts que la page peut charger (protection contre les injections XSS).",
            "Définissez une politique CSP adaptée au site, en commençant en mode « Report-Only ».",
        ))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        constats.append(Constat(
            H, "Content-Security-Policy", Statut.INFO,
            "Présent, mais autorise « unsafe-inline » ou « unsafe-eval », ce qui réduit fortement son efficacité.",
            "Remplacez les scripts en ligne par des fichiers externes ou des nonces.",
        ))
    else:
        constats.append(Constat(H, "Content-Security-Policy", Statut.OK, "Présent."))

    # Clickjacking
    xfo = _entete(entetes, "X-Frame-Options")
    if (xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN")) or (csp and "frame-ancestors" in csp):
        constats.append(Constat(H, "Protection anti-clickjacking", Statut.OK, "Le site ne peut pas être intégré par un site tiers."))
    else:
        constats.append(Constat(
            H, "Protection anti-clickjacking", Statut.ATTENTION,
            "Le site peut être affiché dans un cadre sur un autre site (risque de clickjacking).",
            "Ajoutez « X-Frame-Options: SAMEORIGIN » ou « frame-ancestors 'self' » dans la CSP.",
        ))

    # nosniff
    xcto = _entete(entetes, "X-Content-Type-Options")
    if xcto and xcto.strip().lower() == "nosniff":
        constats.append(Constat(H, "X-Content-Type-Options", Statut.OK, "Présent (nosniff)."))
    else:
        constats.append(Constat(
            H, "X-Content-Type-Options", Statut.ATTENTION,
            "Absent : le navigateur peut mal interpréter le type de certains fichiers.",
            "Ajoutez « X-Content-Type-Options: nosniff ».",
        ))

    # Referrer / Permissions
    if _entete(entetes, "Referrer-Policy"):
        constats.append(Constat(H, "Referrer-Policy", Statut.OK, "Présent."))
    else:
        constats.append(Constat(
            H, "Referrer-Policy", Statut.INFO,
            "Absent : l'adresse complète des pages peut être transmise aux sites externes.",
            "Ajoutez « Referrer-Policy: strict-origin-when-cross-origin ».",
        ))
    if not _entete(entetes, "Permissions-Policy"):
        constats.append(Constat(
            H, "Permissions-Policy", Statut.INFO,
            "Absent : aucune restriction sur l'accès aux fonctions du navigateur (caméra, micro, géolocalisation).",
            "Ajoutez par exemple « Permissions-Policy: camera=(), microphone=(), geolocation=() ».",
        ))

    # Divulgation de versions
    fuites = []
    for nom in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = _entete(entetes, nom)
        if val and re.search(r"\d", val):
            fuites.append(f"{nom}: {val}")
    if fuites:
        constats.append(Constat(
            H, "Divulgation de versions logicielles", Statut.ATTENTION,
            "Le serveur annonce ses versions (" + " ; ".join(fuites) + "), ce qui aide un attaquant à cibler des failles connues.",
            "Masquez les numéros de version dans la configuration du serveur.",
        ))
    return constats
