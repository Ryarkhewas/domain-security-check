"""domain-security-check — audit de sécurité passif d'un nom de domaine."""

from .audit import DomaineInvalide, auditer, normaliser_domaine

__all__ = ["auditer", "normaliser_domaine", "DomaineInvalide"]
__version__ = "1.0.0"
