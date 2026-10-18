"""Branding of the reports: the auditor's name, company, contact, logo and colour, and the client's name.

It can be given on the command line or in a JSON file, so that it is typed once:

    {
      "author": "Loïc Tellier",
      "company": "Ryark Security",
      "contact": "contact@example.com · 06 00 00 00 00",
      "logo": "logo.png",
      "color": "#1f4e78"
    }

A relative logo path is read from the JSON file's folder.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields, replace
from pathlib import Path

DEFAULT_COLOR = "#1f4e78"
LOGO_TYPES = {".png", ".jpg", ".jpeg"}


class BrandingError(ValueError):
    """The branding file or one of its values cannot be used."""


@dataclass
class Branding:
    author: str = ""
    company: str = ""
    contact: str = ""
    client: str = ""
    logo: Path | None = None
    color: str = DEFAULT_COLOR

    @property
    def custom(self) -> bool:
        """Anything given beyond the author: the PDF then gets a cover page."""
        return bool(self.company or self.contact or self.client or self.logo or self.color != DEFAULT_COLOR)

    def check(self) -> Branding:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", self.color):
            raise BrandingError(f"invalid colour {self.color!r} (expected #RRGGBB, e.g. #1f4e78)")
        if self.logo is not None:
            if not self.logo.is_file():
                raise BrandingError(f"logo not found: {self.logo}")
            if self.logo.suffix.lower() not in LOGO_TYPES:
                raise BrandingError(f"logo must be a PNG or JPEG file: {self.logo}")
        return self


def load(path: Path) -> Branding:
    """Branding from a JSON file. Raise BrandingError if it cannot be read."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise BrandingError(f"cannot read {path}: {e}") from e
    if not isinstance(data, dict):
        raise BrandingError(f"{path} must contain a JSON object")
    known = {f.name for f in fields(Branding)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise BrandingError(f"unknown key(s) in {path}: {', '.join(unknown)} (expected: {', '.join(sorted(known))})")
    values = {k: str(v) for k, v in data.items() if v is not None}
    logo = values.pop("logo", "")
    branding = Branding(**values)  # type: ignore[arg-type]
    if logo:
        logo_path = Path(logo).expanduser()
        branding.logo = logo_path if logo_path.is_absolute() else path.parent / logo_path
    return branding


def merge(base: Branding, **overrides) -> Branding:
    """Command-line values take precedence over the file's (empty values are ignored)."""
    given = {k: v for k, v in overrides.items() if v}
    if "logo" in given:
        given["logo"] = Path(given["logo"]).expanduser()
    return replace(base, **given)
