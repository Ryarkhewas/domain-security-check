"""Report languages.

The checks write their texts in English. Texts with variable parts are built
with M("template {name}", name=value): the result is the English text (a str,
so it can be used and compared like any string) that also remembers its
template and values, which lets the report translate it. Texts without
variable parts are translated by looking them up directly.

The JSON output always stays in English: it is meant for other programs.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

LANGUAGES = ("en", "fr")


class Message(str):
    """English text that keeps its template and values, so that it can be translated."""

    template: str
    params: dict[str, object]

    def __new__(cls, template: str, **params: object) -> Message:
        text = template.format(**params) if params else template
        obj = super().__new__(cls, text)
        obj.template = template
        obj.params = params
        return obj

    def __reduce__(self):  # copies and pickles as plain text
        return (str, (str(self),))


M = Message


class Joined(str):
    """Several messages joined by a separator, each translated separately."""

    items: list[str]
    sep: str

    def __new__(cls, items: Sequence[str], sep: str = ", ") -> Joined:
        obj = super().__new__(cls, sep.join(items))
        obj.items, obj.sep = list(items), sep
        return obj

    def __reduce__(self):
        return (str, (str(self),))


class MissingTranslation(KeyError):
    pass


def catalog(lang: str) -> dict[str, str]:
    if lang == "fr":
        from .locales.fr import FR

        return FR
    return {}


def tr(text: object, lang: str = "en", strict: bool = False) -> str:
    """Text in the requested language; English when no translation exists (or an error if strict)."""
    if lang == "en" or text is None:
        return "" if text is None else str(text)
    entries = catalog(lang)
    if isinstance(text, Joined):
        return text.sep.join(tr(i, lang, strict) for i in text.items)
    if isinstance(text, Message) and text.params:
        template = entries.get(text.template)
        if template is None:
            if strict:
                raise MissingTranslation(text.template)
            return str(text)
        # Values that are messages themselves are translated; the others (names, numbers) are kept
        return template.format(**{k: tr(v, lang, strict) if isinstance(v, (Message, Joined)) else v
                                  for k, v in text.params.items()})
    value = str(text)
    if value in entries:
        return entries[value]
    if strict and value.strip():
        raise MissingTranslation(value)
    return value


def date(d: datetime, lang: str = "en") -> str:
    return f"{d:%d/%m/%Y}" if lang == "fr" else f"{d:%Y-%m-%d}"
