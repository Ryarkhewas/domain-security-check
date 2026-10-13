"""Data structures shared by the checks and the report."""

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
    WEB = "Website (HTTPS)"
    HEADERS = "Security headers"
    EMAIL = "Email protection"


@dataclass
class Finding:
    category: Category
    title: str
    status: Status
    detail: str
    recommendation: str = ""


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
class HTTPInfo:
    """Result of the HTTP / HTTPS requests to the site."""

    https_reachable: bool
    headers: dict[str, str] = field(default_factory=dict)
    http_redirects_to_https: bool | None = None  # None = plain HTTP unreachable
    error: str = ""


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
class Result:
    domain: str
    date: datetime
    findings: list[Finding]
    score: int = 0
    grade: str = ""
    cap_reason: str = ""  # why the grade was capped, if it was
