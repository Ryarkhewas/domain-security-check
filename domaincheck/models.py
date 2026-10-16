"""Data structures shared by the checks, the scoring and the report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .history import Changes


class Status(str, Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    INFO = "info"


class Category(str, Enum):
    WEB = "Website security"
    TLS = "Certificate & TLS"
    EMAIL = "Email protection"
    DNS = "Domain & DNS"


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
class DNSSECInfo:
    """DNSSEC status of the DNS zone that contains the domain."""

    zone: str = ""
    ds_count: int = 0  # DS records published in the parent zone (the "chain of trust" link)
    dnskey_count: int = 0  # keys published by the zone itself
    ds_matches: bool | None = None  # a DS record matches one of the keys (None = could not compare)
    error: str = ""  # the queries failed: status unknown


@dataclass
class CAAInfo:
    """CAA records: which certificate authorities may issue certificates for the domain."""

    records: list[tuple[int, str, str]] = field(default_factory=list)  # (flags, tag, value)
    owner: str = ""  # domain where the records were found (the domain itself or a parent)
    error: str = ""


@dataclass
class MTASTSInfo:
    """MTA-STS (RFC 8461) and SMTP TLS reporting (RFC 8460) for the email domain."""

    txt: list[str] = field(default_factory=list)  # _mta-sts.<domain> TXT records
    policy: str | None = None  # https://mta-sts.<domain>/.well-known/mta-sts.txt, if fetched
    error: str = ""  # why the policy could not be fetched
    tls_rpt: list[str] = field(default_factory=list)  # _smtp._tls.<domain> TXT records


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
    dnssec: DNSSECInfo | None = None
    caa: CAAInfo | None = None
    mta_sts: MTASTSInfo | None = None


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
    changes: Changes | None = None  # compared with the previous audit of the domain, if there was one
