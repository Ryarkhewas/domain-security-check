"""Collecte passive des informations publiques d'un domaine.

Uniquement des requêtes que n'importe quel visiteur ou serveur de messagerie
effectue normalement : lectures DNS, poignée de main TLS, une requête GET sur
la page d'accueil. Aucun scan de ports, aucune tentative d'intrusion.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import requests

from .modeles import InfoCertificat, InfoHTTP

SELECTEURS_DKIM = [
    "default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim",
    "s1", "s2", "smtp", "mandrill", "mxvault", "zoho", "protonmail", "sib",
]
TIMEOUT = 8
USER_AGENT = "audit-domaine/1.0 (audit passif)"


class ErreurCollecte(RuntimeError):
    """La vérification n'a pas pu être faite (réseau, DNS en panne…).

    À ne pas confondre avec « l'enregistrement n'existe pas » : conclure
    « pas de SPF » alors que la requête a échoué serait un faux diagnostic.
    """


class DomaineInexistant(RuntimeError):
    pass


class Collecteur:
    def __init__(self, timeout: float = TIMEOUT):
        self.timeout = timeout
        try:
            self.resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration as e:
            raise ErreurCollecte("Aucun serveur DNS configuré sur cette machine.") from e
        self.resolver.lifetime = timeout

    # --- DNS ---------------------------------------------------------------
    def _resoudre(self, nom: str, type_: str):
        """Renvoie la réponse, ou None si l'enregistrement n'existe pas.

        Lève ErreurCollecte si on ne peut pas savoir (panne, délai dépassé).
        """
        try:
            return self.resolver.resolve(nom, type_)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise ErreurCollecte(f"Résolution DNS impossible pour {nom} ({type_}) : vérifiez votre connexion.") from e

    def verifier_existence(self, domaine: str) -> None:
        try:
            self.resolver.resolve(domaine, "SOA", search=False)
        except dns.resolver.NXDOMAIN as e:
            raise DomaineInexistant(
                f"Le domaine {domaine} n'existe pas (ou votre réseau filtre les requêtes DNS)."
            ) from e
        except dns.resolver.NoAnswer:
            return  # sous-domaine (ex. www) : il existe mais n'a pas de SOA propre
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            raise ErreurCollecte(f"Résolution DNS impossible pour {domaine} : vérifiez votre connexion.") from e

    def txt(self, nom: str) -> list[str]:
        reponse = self._resoudre(nom, "TXT")
        if reponse is None:
            return []
        return [b"".join(r.strings).decode("utf-8", "replace") for r in reponse]

    def mx(self, domaine: str) -> list[str]:
        reponse = self._resoudre(domaine, "MX")
        if reponse is None:
            return []
        return [str(r.exchange).rstrip(".") for r in sorted(reponse, key=lambda r: r.preference)]

    def selecteurs_dkim(self, domaine: str) -> list[str]:
        trouves = []
        for sel in SELECTEURS_DKIM:
            if any("p=" in t for t in self.txt(f"{sel}._domainkey.{domaine}")):
                trouves.append(sel)
        return trouves

    # --- TLS ---------------------------------------------------------------
    def certificat(self, hote: str) -> InfoCertificat | None:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hote, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hote) as tls:
                    cert = tls.getpeercert()
                    version = tls.version() or ""
        except ssl.SSLCertVerificationError as e:
            return InfoCertificat(valide=False, erreur=e.verify_message or str(e))
        except (OSError, ssl.SSLError):
            return None

        expire = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        emetteur = dict(x[0] for x in cert.get("issuer", ()))
        noms = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        return InfoCertificat(
            valide=True,
            expire_le=expire,
            emetteur=emetteur.get("organizationName") or emetteur.get("commonName", ""),
            noms=noms,
            version_tls=version,
        )

    # --- HTTP --------------------------------------------------------------
    def http(self, hote: str) -> InfoHTTP:
        entetes = {"User-Agent": USER_AGENT}
        try:
            r = requests.get(f"https://{hote}", headers=entetes, timeout=self.timeout, allow_redirects=True)
            info = InfoHTTP(https_joignable=True, entetes=dict(r.headers))
        except requests.RequestException as e:
            info = InfoHTTP(https_joignable=False, erreur=str(e))

        try:
            r = requests.get(f"http://{hote}", headers=entetes, timeout=self.timeout, allow_redirects=True)
            info.http_redirige_vers_https = r.url.startswith("https://")
        except requests.exceptions.SSLError:
            # Redirigé vers HTTPS, mais le certificat pose problème : la redirection existe bien.
            info.http_redirige_vers_https = True
        except requests.RequestException:
            info.http_redirige_vers_https = None
        return info
