# "Circumstantial evidence is a very tricky thing." — Sherlock Holmes
"""Verbatim anchoring — the anti-hallucination floor of Phase 4.

Every value a model hands back has to be found *in the article body* before it
is allowed anywhere near a row. This module answers one question — where does
this text actually occur? — and answers `None` far more often than it answers a
span. **Refusal is the default**: an anchor that cannot be located is not a
warning to be logged, it is a value that gets dropped.

Three things make a literal `body.find(value)` the wrong tool:

**Defanging.** Reports write indicators so they cannot be clicked: `1.2.3[.]4`,
`hxxps://evil[.]com`, `admin[at]evil[.]com`. The model is asked for the value it
saw *and* the canonical form, but either may be the one that is really in the
text, so matching happens on a refanged view of both. Rejecting a defanged
indicator would mean rejecting exactly the ones written by analysts.

**Case and typography.** Hashes appear uppercase in one report and lowercase in
the next; prose picks up curly apostrophes and en dashes that a quoting model
straightens out. Matching is case-insensitive over a normalised view.

**Sub-token matches.** `1.2.3.4` occurs inside `11.2.3.42`, and `example.com`
inside `mail.example.com` — different indicators, and anchoring one to the other
would manufacture evidence. Matches must therefore sit on a token edge. For a
value the edge is strict: a letter or digit next to the match blocks it, and so
does a `.`, `-` or `_` **with a letter or digit beyond it** — which rejects
`example.com` inside `example.com.br` while still anchoring an indicator that
ends a sentence, the commonest position of all. Quotes use the loose edge
(letters and digits only), so a quoted sentence anchors even though the article
closes it with punctuation the model did not repeat.

The offsets returned here are the only ones the project trusts. The schemas in
`ai/schemas.py` deliberately have no offset field: a fabricated offset is
indistinguishable from a real one, so the model is never asked for one.

`Anchor.text` is the body's own wording, defang and case intact — that is what
gets stored as `article_iocs.value_defanged` and shown to an analyst, while the
canonical value comes from `refang()`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

# Zero-width and soft-hyphen characters, which some defanging tools sprinkle
# into indicators. They carry no meaning here and are dropped before matching.
_INVISIBLE = "\u200b\u200c\u200d\u2060\ufeff\u00ad"

# Typographic variants a model straightens out when it quotes prose back:
# curly quotes, en/em dash and the mathematical minus.
#
# Both quotation marks fold to one. Measured on 203 diamond vertices: four
# quotes were verbatim and refused because the article wrote `"Starland RAT."`
# and the model quoted it back as `'Starland RAT.'`. Which mark encloses a
# quotation is a house convention of whoever typed it, so treating the two as
# different is the anchor asserting something about the wording that the wording
# does not mean. Nothing this project anchors is distinguished by that choice.
_PUNCTUATION = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": "'",
    "\u201d": "'",
    '"': "'",
    "\u2013": "-",
    "\u2014": "-",
    "\u2212": "-",
}

# A dash or bullet standing alone between spaces is layout, not a word: the
# article's list marker, or the pair of dashes it sets an aside between. It
# reads as whitespace rather than being dropped, because dropping it would join
# the words either side and a quote that keeps the dash would then stop matching
# one that does not.
#
# Both readings collapse to the same thing, which is the point. A model quoting
# a bulleted line leaves the bullet out, and a model quoting an aside
# straightens the em dash to a hyphen; neither is a different sentence. Only the
# isolated form is layout \u2014 a hyphen inside a word, and the dash inside a
# defanged indicator, are meaning and stay.
_LIST_MARKER = re.compile(r"(?:(?<=\s)|\A)[-*\u2022\u2013\u2014\u2212]+(?=\s|\Z)")

# How a model signals that it has skipped over part of what it is quoting. The
# segments either side are held to the article separately and in order, so an
# elision stays a quotation while a stitch of two distant fragments does not
# become one: the engine never sees them as adjacent, because they are not.
_ELLIPSIS = re.compile(r"\s*(?:\.\s?\.\s?\.|\u2026)\s*")

_OPEN = r"[\[\(\{]"
_CLOSE = r"[\]\)\}]"

# Refang rules, tried left to right at each position. Bracket pairs are matched
# loosely (`[.)` counts): a mismatched pair is a typo in the report, not a
# reason to lose the indicator.
_RULES: tuple[tuple[str, str], ...] = (
    (rf"{_OPEN}\s*(?:\.|dot)\s*{_CLOSE}", "."),
    (rf"{_OPEN}\s*://\s*{_CLOSE}", "://"),
    (rf"{_OPEN}\s*(?::|colon)\s*{_CLOSE}", ":"),
    (rf"{_OPEN}\s*(?:@|at)\s*{_CLOSE}", "@"),
    (rf"{_OPEN}\s*/\s*{_CLOSE}", "/"),
    (r"h(?:xx|\*\*)p", "http"),
    (r"\\\.", "."),
)

_REWRITE = re.compile(
    "|".join(f"(?P<g{index}>{pattern})" for index, (pattern, _) in enumerate(_RULES)),
    re.IGNORECASE,
)
_REPLACEMENTS = {f"g{index}": replacement for index, (_, replacement) in enumerate(_RULES)}

_STRIP_INVISIBLE = {ord(char): None for char in _INVISIBLE}


def refang(text: str) -> str:
    """Undo defanging, leaving everything else — case included — alone.

    Case matters: a Bitcoin address is base58 and a URL path is case-sensitive,
    so the canonical value cannot be lowercased. Only the four characters of a
    rewritten `hxxp` come back in a fixed case, and a URL scheme is
    case-insensitive anyway.
    """
    return _REWRITE.sub(
        lambda match: _REPLACEMENTS[match.lastgroup or ""],
        text.translate(_STRIP_INVISIBLE),
    )


@dataclass(frozen=True)
class Anchor:
    """A located span. `text` is the body's own wording between the offsets."""

    start: int
    end: int
    text: str


def _extends_indicator(text: str, index: int, outwards: int) -> bool:
    """Does the character at `index` carry the match on into a larger token?

    A letter or digit always does. A separator does only when something
    alphanumeric follows it going outwards: that is the difference between
    `example.com` sitting inside `example.com.br` — a different domain — and
    `example.com.` ending a sentence, which is the same domain plus a full stop.
    """
    if not 0 <= index < len(text):
        return False
    char = text[index]
    if char.isalnum():
        return True
    if char in "._-":
        beyond = index + outwards
        return 0 <= beyond < len(text) and text[beyond].isalnum()
    return False


def _extends_word(text: str, index: int, outwards: int) -> bool:
    """Prose edge: only a letter or digit means the match started mid-word.

    `outwards` is unused — punctuation never continues a quotation — but the
    signature matches `_extends_indicator` so `_locate` takes either.
    """
    return 0 <= index < len(text) and text[index].isalnum()


def _normalise(raw: str) -> tuple[str, list[int], list[int]]:
    """Refang, lowercase and collapse whitespace, keeping the way back.

    Returns the normalised text plus, for each of its characters, the half-open
    span of `raw` it came from. A rewrite maps every character it produces onto
    the whole source run, so `[.]` and the `.` it becomes share one span and an
    anchor that ends there still reports the closing bracket.
    """
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []

    def emit(fragment: str, source_start: int, source_end: int) -> None:
        for char in fragment:
            chars.append(char)
            starts.append(source_start)
            ends.append(source_end)

    position, length = 0, len(raw)
    while position < length:
        rewrite = _REWRITE.match(raw, position)
        if rewrite is not None:
            emit(_REPLACEMENTS[rewrite.lastgroup or ""], rewrite.start(), rewrite.end())
            position = rewrite.end()
            continue
        char = raw[position]
        if char in _INVISIBLE:
            position += 1
            continue
        marker = _LIST_MARKER.match(raw, position)
        if marker is not None:
            if chars and chars[-1] != " ":
                emit(" ", marker.start(), marker.end())
            position = marker.end()
            continue
        if char.isspace():
            # A run of whitespace becomes one space, so a quote anchors across
            # the line breaks of the source article.
            run_end = position
            while run_end < length and raw[run_end].isspace():
                run_end += 1
            if chars and chars[-1] != " ":
                emit(" ", position, run_end)
            position = run_end
            continue
        emit(_PUNCTUATION.get(char, char).lower(), position, position + 1)
        position += 1

    return "".join(chars), starts, ends


class AnchorIndex:
    """An article body normalised once, then searched many times.

    A run anchors up to a hundred indicators and ten evidence quotes against the
    same body; normalising per lookup would rescan the article for each one.
    """

    def __init__(self, body: str) -> None:
        self._body = body
        self._text, self._starts, self._ends = _normalise(body)

    @property
    def body(self) -> str:
        return self._body

    def find(self, *candidates: str) -> Anchor | None:
        """Anchor the first candidate that occurs in the body, or refuse.

        Callers pass the value as the model saw it *and* the canonical form —
        `find(ioc.value_as_written, ioc.value)` — because either may be the one
        the article really contains. Order is the caller's preference; the first
        that anchors wins.
        """
        for candidate in candidates:
            found = self._locate(candidate, _extends_indicator)
            if found is not None:
                return found[0]
        return None

    def find_quote(self, quote: str) -> Anchor | None:
        """Anchor a stretch of prose, tolerating the article's own punctuation.

        Used for evidence quotes, where a model reasonably quotes a sentence
        without the full stop that closes it in the article.

        An explicit ellipsis is honoured rather than searched for: each segment
        is held to the article separately, and each must be found *after* the
        one before it. Order is the whole point. Two true fragments taken from
        opposite ends of an article and joined with a full stop assert a
        sentence the article never wrote, and that is the failure this cannot be
        allowed to wave through — so what an elision buys is permission to skip
        forwards, never permission to reorder.

        The anchor returned for a segmented quote spans from the start of the
        first segment to the end of the last, elided middle included: it marks
        the stretch of article the quotation was drawn from, which is what a
        reader following the citation needs to see.
        """
        segments = [segment for segment in _ELLIPSIS.split(quote) if segment.strip()]
        if not segments:
            return None

        first: Anchor | None = None
        last: Anchor | None = None
        resume = 0
        for segment in segments:
            found = self._locate(segment, _extends_word, resume)
            if found is None:
                return None
            located, resume = found
            first = first if first is not None else located
            last = located

        assert first is not None and last is not None
        if first is last:
            return first
        return Anchor(start=first.start, end=last.end, text=self._body[first.start : last.end])

    def scan(self, pattern: re.Pattern[str]) -> Iterator[tuple[str, Anchor]]:
        """Run a pattern over the refanged view, mapping each hit to the body.

        This is how `iocs.py` builds its admissible set: a pattern written for
        clean text finds `1.2.3[.]4` too, and the offset arithmetic stays here
        rather than being redone by every caller. The yielded string is the
        normalised match (lowercased, refanged); the anchor carries the body's
        own wording, which is what a caller should store.
        """
        for match in pattern.finditer(self._text):
            if match.end() == match.start():
                continue
            start = self._starts[match.start()]
            end = self._ends[match.end() - 1]
            yield match.group(0), Anchor(start=start, end=end, text=self._body[start:end])

    def window(self, found: Anchor, width: int = 120) -> str:
        """The body around an anchor, on word edges — context that is real text.

        Used when a model's own context sentence cannot be anchored: a quote we
        cannot find is not context, it is another claim to check.
        """
        left = max(0, found.start - width)
        right = min(len(self._body), found.end + width)
        while left > 0 and not self._body[left - 1].isspace():
            left -= 1
        while right < len(self._body) and not self._body[right].isspace():
            right += 1
        return " ".join(self._body[left:right].split())

    def _locate(
        self,
        candidate: str,
        extends: Callable[[str, int, int], bool],
        from_index: int = 0,
    ) -> tuple[Anchor, int] | None:
        """The anchor, and where in the normalised text it stopped.

        The second half of the pair is what lets a segmented quote resume the
        search after the previous segment instead of from the top, which is how
        "in order" is enforced at all.
        """
        needle, _, _ = _normalise(candidate.strip())
        needle = needle.strip()
        if not needle:
            return None

        at = self._text.find(needle, from_index)
        while at != -1:
            stop = at + len(needle)
            if not (extends(self._text, at - 1, -1) or extends(self._text, stop, 1)):
                start = self._starts[at]
                end = self._ends[stop - 1]
                return Anchor(start=start, end=end, text=self._body[start:end]), stop
            at = self._text.find(needle, at + 1)
        return None


def anchor(body: str, *candidates: str) -> Anchor | None:
    """One-shot `AnchorIndex.find`, for callers with a single value."""
    return AnchorIndex(body).find(*candidates)


def anchor_quote(body: str, quote: str) -> Anchor | None:
    """One-shot `AnchorIndex.find_quote`."""
    return AnchorIndex(body).find_quote(quote)
