"""domain-security-check — passive security audit of a domain name."""

from .audit import InvalidDomain, normalize_domain, run_audit

__all__ = ["run_audit", "normalize_domain", "InvalidDomain"]
__version__ = "1.0.0"
