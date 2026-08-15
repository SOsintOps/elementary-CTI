# "There is nothing more deceptive than an obvious fact." — Sherlock Holmes
"""Technique mapping — the catalogue says what exists, the article says what happened.

A mapped TTP is a claim with two halves, and this module refuses to store one
without the other (roadmap criterion 4):

**The technique must be current.** `attack_catalog.py` is the authority, so a
proposed id is not checked for shape but resolved: an invented id, or one
deprecated with no successor, denotes nothing and the mapping goes. A revoked id
resolves through its chain and the *live* id is what gets stored — `T1150` from a
2019 write-up is a correct observation with an out-of-date name, and rejecting it
would lose the mapping while storing it verbatim would file today's article under
an id ATT&CK no longer publishes.

**The evidence must be in the body.** `AnchorIndex.find_quote` is the bridge: the
quote is anchored to a span, and the span is what is persisted, so an evidence
quote is never stored as a second claim to take on trust. This is where TTPs
differ from indicators — `iocs.py` can pre-scan the text for everything that
*could* be an indicator, but nothing regex-shaped says "this paragraph describes
phishing". The model does the reading; the anchor keeps it honest about where.

Two thresholds, both about not accepting evidence that proves nothing:

- **A quote must be long enough to cite.** `find_quote("a")` succeeds on nearly
  any article, so a floor is what makes `UNANCHORED_EVIDENCE` mean anything.
- **Ten mappings per article.** The cap is a criterion, not a preference: an
  article is not evidence for thirty techniques, and a model that lists thirty
  is pattern-matching its ATT&CK training rather than reading. `schemas.py`
  bounds the parse at the same number; this re-check exists because the cap is
  the criterion's, not the schema's, and must survive the schema being relaxed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pestilentia.ai.extraction.anchors import AnchorIndex
from pestilentia.ai.extraction.attack_catalog import AttackCatalog, Technique
from pestilentia.ai.schemas import MAX_TTPS, MapTtpOutput

# Measured on the quote with whitespace collapsed. A fragment shorter than this
# occurs by chance in a 30 KB article, so anchoring it says nothing about
# whether the model was reading the article or its own training.
_MIN_EVIDENCE_CHARS = 16


class RejectionReason(StrEnum):
    """Why a mapping the model proposed did not survive."""

    UNKNOWN_TECHNIQUE = "unknown_technique"  # no live technique bears that id
    WEAK_EVIDENCE = "weak_evidence"  # a fragment too short to be a citation
    UNANCHORED_EVIDENCE = "unanchored_evidence"  # the quote is not in the article
    DUPLICATE = "duplicate"  # the same live technique twice
    OVER_CAP = "over_cap"  # past the ten the criterion allows


@dataclass(frozen=True)
class MappedTechnique:
    """A technique the catalogue vouches for, evidenced by a span of the body.

    Maps one-to-one onto an `article_ttps` row (migration 0019). The identity
    and the naming are the catalogue's — the model supplies only the id it
    reached and the sentence it read; `confidence` is its own, kept as the
    number it gave because Phase 5 folds it into a composite score.
    """

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    evidence_span_start: int
    evidence_span_end: int
    confidence: float


@dataclass(frozen=True)
class Rejected:
    """A refusal, reported under the id the *model* wrote.

    Deliberately not the resolved id: this row exists so a run can be traced
    back to the raw output, and the raw output says `T1150`.
    """

    technique_id: str
    reason: RejectionReason


@dataclass(frozen=True)
class TtpReconciliation:
    """Both halves of the decision — what was kept and what was refused.

    As with indicators, the refusals are the half worth watching: a run whose
    model cites quotes that are not in the article is a run to look at, and
    that is invisible if the refusals are dropped on the floor.
    """

    kept: tuple[MappedTechnique, ...]
    rejected: tuple[Rejected, ...]


def _primary_tactic(technique: Technique) -> tuple[str, str]:
    """The first tactic the bundle declares, or empty when it declares none.

    `article_ttps` holds one row per technique, so multi-tactic techniques —
    Valid Accounts sits under four — have to pick one, and the bundle's own
    kill-chain order is the only non-arbitrary answer available. `group_ttps`
    already behaves this way: it writes a row per tactic against a unique
    `(group_id, technique_id)`, so the first is what survives.

    A technique with no kill-chain phases keeps empty tactic fields rather than
    being refused — missing bundle metadata is not the model's error.
    """
    return technique.tactics[0] if technique.tactics else ("", "")


def reconcile(
    body: str | AnchorIndex,
    output: MapTtpOutput,
    catalog: AttackCatalog,
) -> TtpReconciliation:
    """Keep the mappings the catalogue and the article both support.

    Checks run in the order that makes a refusal most informative: the cap
    first, since past ten nothing else about a mapping matters; then existence,
    then evidence, then duplication — so a second mapping of the same technique
    is only called a duplicate once we know it was otherwise sound.
    """
    index = body if isinstance(body, AnchorIndex) else AnchorIndex(body)

    kept: list[MappedTechnique] = []
    rejected: list[Rejected] = []
    seen: set[str] = set()

    for proposed in output.mappings:
        stated = proposed.technique_id.strip().upper()

        if len(kept) >= MAX_TTPS:
            rejected.append(Rejected(stated, RejectionReason.OVER_CAP))
            continue

        technique = catalog.resolve(stated)
        if technique is None:
            rejected.append(Rejected(stated, RejectionReason.UNKNOWN_TECHNIQUE))
            continue

        quote = " ".join(proposed.evidence_quote.split())
        if len(quote) < _MIN_EVIDENCE_CHARS:
            rejected.append(Rejected(stated, RejectionReason.WEAK_EVIDENCE))
            continue

        found = index.find_quote(quote)
        if found is None:
            rejected.append(Rejected(stated, RejectionReason.UNANCHORED_EVIDENCE))
            continue

        # Keyed on the resolved id: two write-ups can cite `T1150` and `T1647`
        # for one observation, and after resolution they are one mapping.
        if technique.technique_id in seen:
            rejected.append(Rejected(stated, RejectionReason.DUPLICATE))
            continue
        seen.add(technique.technique_id)

        tactic_id, tactic_name = _primary_tactic(technique)
        kept.append(
            MappedTechnique(
                technique_id=technique.technique_id,
                technique_name=technique.name,
                tactic_id=tactic_id,
                tactic_name=tactic_name,
                evidence_span_start=found.start,
                evidence_span_end=found.end,
                confidence=proposed.confidence,
            )
        )

    return TtpReconciliation(kept=tuple(kept), rejected=tuple(rejected))
