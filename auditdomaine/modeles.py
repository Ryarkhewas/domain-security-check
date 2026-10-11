"""Structures de données partagées par les analyses et le rapport."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Statut(str, Enum):
    OK = "ok"
    ATTENTION = "attention"
    CRITIQUE = "critique"
    INFO = "info"


class Categorie(str, Enum):
    WEB = "Site web (HTTPS)"
    ENTETES = "En-têtes de sécurité"
    EMAIL = "Protection des emails"


@dataclass
class Constat:
    categorie: Categorie
    titre: str
    statut: Statut
    detail: str
    recommandation: str = ""


@dataclass
class InfoCertificat:
    """Ce qu'on a pu observer du certificat TLS du site."""

    valide: bool
    expire_le: datetime | None = None
    emetteur: str = ""
    noms: list[str] = field(default_factory=list)
    version_tls: str = ""
    erreur: str = ""


@dataclass
class InfoHTTP:
    """Résultat des requêtes HTTP / HTTPS sur le site."""

    https_joignable: bool
    entetes: dict[str, str] = field(default_factory=dict)
    http_redirige_vers_https: bool | None = None  # None = HTTP injoignable
    erreur: str = ""


@dataclass
class DonneesCollectees:
    """Tout ce qui a été récupéré sur le réseau, avant analyse."""

    domaine: str
    txt_racine: list[str]
    txt_dmarc: list[str]
    mx: list[str]
    selecteurs_dkim: list[str]
    certificat: InfoCertificat | None
    http: InfoHTTP


@dataclass
class Resultat:
    domaine: str
    date: datetime
    constats: list[Constat]
    score: int = 0
    note: str = ""
