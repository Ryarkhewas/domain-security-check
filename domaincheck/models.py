"""Data structures shared by the checks, the scoring and the report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    INFO = "info"


class Category(str, Enum):
    WEB = "Website security"
    TLS = "Certificate & TLS"
    EMAIL = "Email protection"


@dataclass
class Finding:
    category: Category
    title: str
    status: Status
    detail: str
    recommendation: str = ""
    points: int | None = None  # score modifier; None = shown but not scored
    source: str = ""  # key into sources.SOURCES


@dataclass
class CertificateInfo:
    """What could be observed about the site's TLS certificate."""

    valid: bool
    expires_at: datetime | None = None
    issuer: str = ""
    names: list[str] = field(default_factory=list)
    tls_version: str = ""
    error: str = ""


@dataclass
class CookieInfo:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None = None  # "strict", "lax", "none", other, or None if absent


@dataclass
class HTTPInfo:
    """Result of the HTTP / HTTPS requests to the site."""

    https_reachable: bool
    headers: dict[str, str] = field(default_factory=dict)
    http_redirects_to_https: bool | None = None  # None = plain HTTP unreachable
    error: str = ""
    redirect_chain: list[str] = field(default_factory=list)  # URLs visited from http://host
    redirect_cert_error: bool = False  # an invalid certificate was hit while following redirects
    cookies: list[CookieInfo] = field(default_factory=list)
    content_type: str = ""  # of the HTTPS home page, without parameters
    body: str = ""  # HTTPS home page HTML (truncated), used for the Subresource Integrity check
    hsts_preloaded: bool | None = None  # in the browsers' HSTS preload list (None = list unavailable)
    redirects_preloaded: bool | None = None  # every host of the HTTP redirect chain is preloaded


@dataclass
class CollectedData:
    """Everything fetched from the network, before analysis."""

    domain: str
    root_txt: list[str]
    dmarc_txt: list[str]
    mx: list[str]
    dkim_selectors: list[str]
    certificate: CertificateInfo | None
    http: HTTPInfo
    dmarc_inherited_from: str = ""  # parent domain whose DMARC policy applies, if any


@dataclass
class CategoryGrade:
    score: int | None  # None = not applicable (e.g. no website)
    grade: str  # "A+" ... "F", or "N/A"
    note: str = ""


@dataclass
class Result:
    domain: str
    date: datetime
    findings: list[Finding]
    grades: dict[str, CategoryGrade] = field(default_factory=dict)  # keyed by Category.name
    grade: str = ""  # overall grade: the weakest category
    cap_reason: str = ""  # why the website / TLS grades were capped, if they were
