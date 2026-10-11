"""
audit-domaine — Audit de sécurité passif d'un nom de domaine.

Usage :
    python audit.py exemple.fr
    python audit.py exemple.fr -o rapports/exemple.html --auteur "Votre Nom"
    python audit.py exemple.fr --json
    python audit.py --demo
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from auditdomaine.audit import DomaineInvalide, auditer
from auditdomaine.collecte import DomaineInexistant, ErreurCollecte
from auditdomaine.demo import DOMAINE_DEMO, CollecteurDemo
from auditdomaine.rapport import generer_html, generer_json, resume_console

AVERTISSEMENT = (
    "Rappel : n'auditez que des domaines qui vous appartiennent ou pour lesquels "
    "vous avez l'accord du propriétaire."
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit de sécurité passif d'un nom de domaine (HTTPS, en-têtes, SPF/DKIM/DMARC).")
    p.add_argument("domaine", nargs="?", help="Domaine à auditer (ex. exemple.fr)")
    p.add_argument("-o", "--sortie", type=Path, help="Fichier HTML de sortie (défaut : rapports/<domaine>.html)")
    p.add_argument("--auteur", default="", help="Nom affiché dans le rapport")
    p.add_argument("--json", action="store_true", help="Afficher le résultat en JSON au lieu du résumé")
    p.add_argument("--demo", action="store_true", help="Démonstration sur un domaine fictif, sans accès réseau")
    args = p.parse_args(argv)

    if not args.demo and not args.domaine:
        p.error("indiquez un domaine, ou --demo")

    try:
        if args.demo:
            resultat = auditer(DOMAINE_DEMO, collecteur=CollecteurDemo())
        else:
            print(AVERTISSEMENT, file=sys.stderr)
            resultat = auditer(args.domaine)
    except (DomaineInvalide, DomaineInexistant) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1
    except ErreurCollecte as e:
        print(f"Audit interrompu : {e}\nAucun rapport n'a été produit, pour éviter un diagnostic erroné.", file=sys.stderr)
        return 2

    sortie = args.sortie or Path("rapports") / f"{resultat.domaine}.html"
    sortie.parent.mkdir(parents=True, exist_ok=True)
    sortie.write_text(generer_html(resultat, args.auteur), encoding="utf-8")

    print(generer_json(resultat) if args.json else resume_console(resultat))
    print(f"Rapport HTML : {sortie}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
