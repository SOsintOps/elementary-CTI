# UI language system (multi-language, English fallback).
#
# Catalogs live in locales/<lang>.json — flat key→string plus a "_meta"
# entry ({"label": "EN", "name": "English"}) for the sidebar switcher.
# Adding a language = adding one file; SUPPORTED_LANGS is derived from the
# directory at import time. Only descriptive strings are cataloged — page
# intros, chrome labels, notices, error messages. Data content is
# source-language and never translated. English is the fallback for any
# key missing from another locale.
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_LANG = "en"
_LOCALES_DIR = Path(__file__).parent / "locales"


def _load_locales() -> dict[str, dict[str, str]]:
    catalogs: dict[str, dict[str, str]] = {}
    for path in sorted(_LOCALES_DIR.glob("*.json")):
        try:
            catalogs[path.stem] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception("Failed to load locale %s", path.name)
    if DEFAULT_LANG not in catalogs:
        raise RuntimeError(f"Default locale {DEFAULT_LANG}.json is missing or invalid")
    return catalogs


_CATALOGS = _load_locales()

# Default language first, then the rest alphabetically — this is the order
# the sidebar switcher renders.
SUPPORTED_LANGS = (
    DEFAULT_LANG,
    *sorted(lang for lang in _CATALOGS if lang != DEFAULT_LANG),
)

# lang -> short label for the switcher (e.g. "EN"); falls back to the code.
LANG_LABELS = {
    lang: (_CATALOGS[lang].get("_meta") or {}).get("label", lang.upper())
    for lang in SUPPORTED_LANGS
}


def translate(key: str, lang: str) -> str:
    catalog = _CATALOGS.get(lang) or _CATALOGS[DEFAULT_LANG]
    value = catalog.get(key)
    if value is None and lang != DEFAULT_LANG:
        value = _CATALOGS[DEFAULT_LANG].get(key)
    return value if value is not None else key
