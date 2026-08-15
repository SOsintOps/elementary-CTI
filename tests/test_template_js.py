"""Tripwire: DOMTokenList calls that a browser refuses at runtime.

`classList.add('a b')` throws InvalidCharacterError — the API takes separate
tokens, not a class string. It looks correct in the source, so nothing catches
it until a user reports that a control is dead: the exception fires inside the
handler and aborts everything after it. That is exactly how the dashboard's
7d/1m/1y tabs died (2026-08-12) — the panel-reveal line never ran, and in
switchVictimsTab neither did the map refresh below it.

Template-wide on purpose: fixing the one file that had it would not stop the
next template from repeating it.
"""

import re
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parents[1] / "src" / "pestilentia" / "web" / "templates"
STATIC = Path(__file__).resolve().parents[1] / "src" / "pestilentia" / "web" / "static"

# A quoted argument holding a space, inside add()/remove()/toggle()/replace().
_BAD_TOKEN = re.compile(
    r"""classList\.(?:add|remove|toggle|replace)\(\s*(['"])([^'"]*\s[^'"]*)\1"""
)


def _sources():
    for root in (TEMPLATES, STATIC):
        if root.exists():
            yield from (p for p in root.rglob("*.html"))
            yield from (p for p in root.rglob("*.js"))


def test_no_classlist_token_contains_a_space():
    offenders = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for match in _BAD_TOKEN.finditer(text):
            line = text[: match.start()].count("\n") + 1
            offenders.append(f"{path.name}:{line} → {match.group(2)!r}")

    assert not offenders, (
        "classList takes separate tokens; a token with a space raises "
        "InvalidCharacterError at runtime and kills the rest of the handler. "
        "Use classList.add('a', 'b'):\n  " + "\n  ".join(offenders)
    )
