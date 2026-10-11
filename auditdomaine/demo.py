"""Collecteur fictif pour démontrer l'outil sans accès réseau.

Les données représentent une petite entreprise imaginaire (« boulangerie-exemple.fr »)
avec une configuration typique : HTTPS en place, mais emails mal protégés.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .modeles import InfoCertificat, InfoHTTP

DOMAINE_DEMO = "boulangerie-exemple.fr"


class CollecteurDemo:
    def txt(self, nom: str) -> list[str]:
        if nom.startswith("_dmarc."):
            return ["v=DMARC1; p=none"]
        return ["v=spf1 include:_spf.hebergeur-exemple.fr ?all", "google-site-verification=abc123"]

    def mx(self, domaine: str) -> list[str]:
        return ["mx1.hebergeur-exemple.fr", "mx2.hebergeur-exemple.fr"]

    def selecteurs_dkim(self, domaine: str) -> list[str]:
        return []

    def certificat(self, hote: str) -> InfoCertificat:
        return InfoCertificat(
            valide=True,
            expire_le=datetime.now(timezone.utc) + timedelta(days=21),
            emetteur="Let's Encrypt",
            noms=[hote, f"www.{hote}"],
            version_tls="TLSv1.3",
        )

    def http(self, hote: str) -> InfoHTTP:
        return InfoHTTP(
            https_joignable=True,
            http_redirige_vers_https=False,
            entetes={
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3",
                "Content-Type": "text/html; charset=UTF-8",
                "X-Content-Type-Options": "nosniff",
            },
        )
