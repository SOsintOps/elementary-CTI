# "You have a grand gift for silence, Watson." — Sherlock Holmes
"""House-style checking for the prose the pipeline writes.

The rules and their sources are in `docs/intelligence-writing-style.md`. This
module implements only the part of that document a machine can decide without
judgement, and it is deliberate that the two are not the same size: whether a
paragraph opens on its own bottom line is a judgement, whether it contains the
phrase "and more" is not.

**It measures and does not rewrite.** A checker that edits a model's output is
a second writer nobody has validated, and its corrections would be
indistinguishable from the model's own text in the row that stores them. What
this returns is a list of violations with the rule, the offending words and
where they sit, which is enough to tell whether a change to the prompt worked.

Why deterministic rather than asked of the model: the same reasoning that put
grounding in `iocs.reconcile` instead of in a prompt. A rule the engine applies
can be proved; a rule the model is asked to follow can only be hoped for. The
prompt block carries the rules too, so the common case is written correctly
rather than corrected afterwards, but the prompt is the optimisation and this
is the measurement.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

#: DI manual §9.3, "Keep sentences and paragraphs short". The manual sets no
#: number; this one is ours, chosen so that the 78-word sentence that prompted
#: the whole exercise fails it by a factor of two and an ordinary assessment
#: sentence passes comfortably.
MAX_SENTENCE_WORDS = 35


@dataclass(frozen=True)
class Violation:
    """One breach of the house style, with enough to find it again."""

    rule: str
    text: str
    start: int
    end: int
    note: str

    def __str__(self) -> str:
        return f"{self.rule} at {self.start}: {self.text!r} — {self.note}"


# --- the phrase lists, each traceable to a rule in the guide -----------------

#: DI manual ch. 9, `etc., and so forth`: "Rarely appropriate in DI writing.
#: Enumerating the additional instances is usually more helpful."
OPEN_ENUMERATIONS = (
    "and more",
    "and so forth",
    "and so on",
    "among others",
    "and others",
    "etc.",
    "etc",
)

#: Vague where the pipeline already holds the specific value in `article_iocs`
#: and `article_ttps`, each with a verbatim span behind it.
VAGUE_QUANTIFIERS = (
    "various",
    "certain",
    "several",
    "numerous",
    "multiple",
    "a number of",
    "a variety of",
    "a range of",
)

#: DI manual ch. 9, `absolutes`. Whole thing or nothing; they do not take
#: limiting modifiers, and most uses in the wild mean "notable" instead.
ABSOLUTES = (
    "unique",
    "universal",
    "eternal",
    "fatal",
    "incessant",
    "ultimate",
)

#: The modifiers `absolutes` names as impossible in front of them.
LIMITING_MODIFIERS = ("somewhat", "totally", "more", "less", "very", "rather", "quite")

#: DI manual ch. 9, `fake analysis`: phrases that "betray sloppy thinking and
#: detract from any serious presentation". The list is the manual's own.
FAKE_ANALYSIS = (
    "anything can happen",
    "it is not possible to predict",
    "further developments are to be expected",
    "it is too early to tell",
    "it remains to be seen",
    "only the future will tell",
)

#: DI manual ch. 9, `evidence`: "not a synonym for information or reporting",
#: and "available evidence indicates" is "essentially meaningless". The rest
#: reopen the observed/inferred fence that the schema closes structurally.
HEDGED_ATTRIBUTION = (
    "available evidence",
    "the evidence indicates",
    "evidence suggests",
    "sources say",
    "sources indicate",
    "it is believed",
    "it is thought",
    "reports indicate",
    "reports suggest",
    "it appears that",
    "it would appear",
)

#: DI manual ch. 9 reserves these; the guide names the replacements.
RESERVED_VERBS = {
    "exacerbate": "worsen, heighten, intensify, widen or deepen",
    "exacerbated": "worsened, heightened, intensified, widened or deepened",
    "exacerbates": "worsens, heightens, intensifies, widens or deepens",
    "decimate": "only of people, and only where deaths are involved",
    "decimated": "only of people, and only where deaths are involved",
}

#: A conditional needs a limiting condition or it "carries little analytic
#: weight" (DI manual ch. 9, `could, may, might`).
CONDITIONALS = ("could", "may", "might")
LIMITING_CONDITIONS = ("if", "unless", "provided", "should", "when", "once", "where")

#: Advice belongs in `recommendations_md`. In a summary it sits outside the
#: paragraph's own bottom line and duplicates the field that holds it.
#:
#: `advise` and its forms were missing from the first version, so "The Ukrainian
#: cyber agency advises restricting corporate resource access" passed clean
#: inside a summary. Attributing the advice to someone else does not stop it
#: being advice: the field boundary is about what the sentence does, not about
#: who is credited with doing it.
RECOMMENDATION_MARKERS = (
    "should",
    "must",
    "recommend",
    "recommends",
    "recommended",
    "advise",
    "advises",
    "advised",
    "urges",
    "guidance",
    "mitigations",
    "organisations are advised",
    "organizations are advised",
    "defenders are advised",
)

#: Sentences about the article rather than about the adversary. This class did
#: not exist until the house-style prompt was deployed: it appeared *with* v2
#: and was absent from v1. A block that asks for structure and concision can
#: push a model to fill the space with commentary on its source when the article
#: gives it nothing else, and "The article provides technical details of the
#: activity" occupies the place the bottom line is owed.
#: Narrowed after it fired on "The article states it or it does not", which is
#: attribution and not commentary. The harmful pattern is not naming the source,
#: it is describing what the source *offers a reader*: thoroughness, coverage,
#: guidance. Those say nothing about the adversary. Where a sentence merely
#: attributes a claim, `hedged_attribution` already has it covered, and two
#: rules firing on one phrase would double-count a single fault.
META_COMMENTARY = (
    "the article provides",
    "the article offers",
    "the article outlines",
    "the report provides",
    "the report offers",
    "the report outlines",
    "the advisory provides",
    "the advisory offers",
    "this article provides",
    "this report provides",
)

#: Openings that put the chronology where the bottom line belongs. The BLUF rule
#: is that the first sentence covers the paragraph, and a date covers nothing:
#: it is the least important thing in an assessment and it led both of the first
#: two summaries this system produced.
CHRONOLOGY_OPENERS = (
    "first appeared",
    "first emerged",
    "first observed",
    "first seen",
    "emerged in",
    "was discovered in",
    "was first",
    "has been active since",
    "has operated since",
    "dates back",
    "originated in",
)


def _finditer(text: str, phrase: str) -> list[tuple[int, int]]:
    """Word-boundary search, so `certain` does not match inside `uncertain`."""
    pattern = re.compile(rf"(?<!\w){re.escape(phrase)}(?!\w)", re.IGNORECASE)
    return [(m.start(), m.end()) for m in pattern.finditer(text)]


def _outermost(text: str, phrases: Sequence[str]) -> list[tuple[int, int]]:
    """Every place one of `phrases` occurs, counted once.

    Marker lists overlap on purpose: `advised` catches what `defenders are
    advised` would miss, and `etc` catches the writer who left the full stop
    off. Scanning them one by one then counts the overlap twice, so a single
    breach scores two. Worse, it degrades as the lists grow, because each
    phrasing added to catch something new also multiplies the phrasings already
    covered — a rule that gets louder every time it is improved.

    The longest match at a position wins and anything inside it is the same
    breach being named twice.
    """
    spans = sorted(
        {span for phrase in phrases for span in _finditer(text, phrase)},
        key=lambda span: (span[0], -span[1]),
    )
    outermost: list[tuple[int, int]] = []
    for start, end in spans:
        if outermost and start >= outermost[-1][0] and end <= outermost[-1][1]:
            continue
        outermost.append((start, end))
    return outermost


def split_sentences(text: str) -> list[tuple[str, int]]:
    """Sentences with their offsets, split on terminal punctuation.

    Naive on purpose, and its one known weakness is stated rather than papered
    over: an abbreviation ending in a full stop splits a sentence in two. That
    error makes a long sentence look like two short ones, so it can only ever
    under-report a length violation, never invent one. A checker whose errors
    all fall on the forgiving side is one whose complaints can be trusted.
    """
    sentences: list[tuple[str, int]] = []
    start = 0
    for match in re.finditer(r"[.!?](?:\s|$)", text):
        end = match.start() + 1
        chunk = text[start:end].strip()
        if chunk:
            sentences.append(
                (chunk, start + (len(text[start:end]) - len(text[start:end].lstrip())))
            )
        start = match.end()
    tail = text[start:].strip()
    if tail:
        sentences.append((tail, start))
    return sentences


def _word_count(sentence: str) -> int:
    return len(re.findall(r"[A-Za-z0-9][\w'-]*", sentence))


def check(text: str, *, advice_allowed: bool = True) -> list[Violation]:
    """Every mechanical violation in `text`, in the order they occur.

    `advice_allowed` is False for the fields that carry assessment rather than
    counsel, which is `key_judgement` and `summary_md`. Advice there is a field
    error: it duplicates `recommendations_md` and it sits outside the bottom
    line the paragraph opened with. In `recommendations_md` advice is the point,
    so the rule is off by default rather than on.
    """
    if not text or not text.strip():
        return []

    found: list[Violation] = []

    for phrase in FAKE_ANALYSIS:
        for start, end in _finditer(text, phrase):
            found.append(
                Violation(
                    "fake_analysis",
                    text[start:end],
                    start,
                    end,
                    "DI manual ch. 9: betrays sloppy thinking; say what the article establishes",
                )
            )

    for start, end in _outermost(text, OPEN_ENUMERATIONS):
        found.append(
            Violation(
                "open_enumeration",
                text[start:end],
                start,
                end,
                "close the list or stop it; the remaining instances are in the article",
            )
        )

    for phrase in VAGUE_QUANTIFIERS:
        for start, end in _finditer(text, phrase):
            found.append(
                Violation(
                    "vague_quantifier",
                    text[start:end],
                    start,
                    end,
                    "the specific value is already extracted with a span behind it",
                )
            )

    for word in ABSOLUTES:
        for start, end in _finditer(text, word):
            preceding = text[max(0, start - 20) : start].lower()
            limited = any(modifier in preceding for modifier in LIMITING_MODIFIERS)
            found.append(
                Violation(
                    "absolute",
                    text[start:end],
                    start,
                    end,
                    "an absolute under a limiting modifier is impossible"
                    if limited
                    else "use only where it is literally the whole thing or nothing",
                )
            )

    for phrase in HEDGED_ATTRIBUTION:
        for start, end in _finditer(text, phrase):
            found.append(
                Violation(
                    "hedged_attribution",
                    text[start:end],
                    start,
                    end,
                    "the observed/inferred fence already carries this; a hedge reopens it",
                )
            )

    for word, replacement in RESERVED_VERBS.items():
        for start, end in _finditer(text, word):
            found.append(Violation("reserved_verb", text[start:end], start, end, replacement))

    for start, end in _finditer(text, "—"):
        found.append(
            Violation("em_dash", text[start:end], start, end, "use a comma, full stop or semicolon")
        )

    for sentence, offset in split_sentences(text):
        words = _word_count(sentence)
        if words > MAX_SENTENCE_WORDS:
            found.append(
                Violation(
                    "sentence_length",
                    sentence,
                    offset,
                    offset + len(sentence),
                    f"{words} words against a ceiling of {MAX_SENTENCE_WORDS}; "
                    "one sentence, one claim",
                )
            )

        lowered = sentence.lower()
        for word in CONDITIONALS:
            if not _finditer(sentence, word):
                continue
            if any(_finditer(lowered, condition) for condition in LIMITING_CONDITIONS):
                continue
            position = _finditer(sentence, word)[0]
            found.append(
                Violation(
                    "bare_conditional",
                    word,
                    offset + position[0],
                    offset + position[1],
                    "a conditional with no limiting condition carries no analytic weight; "
                    "attach the condition or use the ICD 203 likelihood scale",
                )
            )

    for phrase in META_COMMENTARY:
        for start, end in _finditer(text, phrase):
            found.append(
                Violation(
                    "meta_commentary",
                    text[start:end],
                    start,
                    end,
                    "this describes the source, not the adversary; say what the article "
                    "establishes rather than that it establishes things",
                )
            )

    if not advice_allowed:
        # One recommendation is one violation; see `_outermost`. This is the
        # family where the double count was found, and it was found by the
        # measurement disagreeing with the text: *defenders are advised to
        # patch* scored two.
        for start, end in _outermost(text, RECOMMENDATION_MARKERS):
            found.append(
                Violation(
                    "advice_in_summary",
                    text[start:end],
                    start,
                    end,
                    "advice belongs in recommendations_md, and repeating it here "
                    "puts it outside the paragraph's own bottom line",
                )
            )

        sentences = split_sentences(text)
        if sentences:
            opening, offset = sentences[0]
            for phrase in CHRONOLOGY_OPENERS:
                hits = _finditer(opening, phrase)
                if not hits:
                    continue
                found.append(
                    Violation(
                        "chronology_first",
                        opening[hits[0][0] : hits[0][1]],
                        offset + hits[0][0],
                        offset + hits[0][1],
                        "the first sentence is the bottom line and must cover the paragraph; "
                        "when the operation began is the least important thing in it",
                    )
                )
                break

    return sorted(found, key=lambda violation: (violation.start, violation.rule))


def tally(violations: list[Violation]) -> dict[str, int]:
    """Violations per rule. What a before-and-after comparison is written in."""
    counts: dict[str, int] = {}
    for violation in violations:
        counts[violation.rule] = counts.get(violation.rule, 0) + 1
    return counts
