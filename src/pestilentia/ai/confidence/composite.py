# "I'm a consultant. The police don't hire me." — Sherlock, Elementary
"""The composite score, from signals measured outside the model (Phase 5).

**Confidence is not what the model says it is.** A model asked to rate its own
output returns high numbers uncorrelated with the truth, so the self-report is
the weakest of four voices and the other three are measurements: how much of
what the model proposed survived anchoring, what an independent judge made of
the state's claims, and how much of the schema the finding actually filled.

Pure functions, no I/O. What they produce is `score_raw` — the composite before
the two UNODC axes touch it. Those are a separate layer in `grading.py`, and
they are separate so that a retuned grade→factor map can be applied to stored
rows without recomputing any of this.

Three of the four components needed a definition the sources of record do not
give, and the definitions are here rather than implied by the code:

**Anchoring is measured per state, not per finding.** Read per finding it is
degenerate: the extraction states *reject* unanchored findings rather than
scoring them down, so every finding that exists is anchored and the ratio is
always 1.0. The signal that survives is how much of the state's proposal made
it through — 29 of 35 indicators on the acceptance article, six inventions —
and that number is a property of the state, shared by every finding it
produced.

**Critic agreement is coarser than it looks.** The judge audits claims, and
there is no one-to-one map from its claims to finding rows; building one would
be a second matching problem with its own errors. So the state's
`evidence_quality` becomes the critic component for every finding of that
state. Two indicators from one passage get the same critic mark even if one sat
in a quoted sentence and the other in a footnote.

**A missing component is not a zero.** Indicators carry no self-report because
the model is not asked for one, and a zero there would punish a category for a
question nobody put to it. Missing components take a neutral 0.5 at the moment
of the sum. The weights do not renormalise: a finding measured on three signals
should not be able to reach the same total as one measured on four.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from pestilentia.ai.schemas import EvidenceQuality

#: Roadmap criterion 1. The self-report is last by a factor of four against
#: anchoring for the reason in the module docstring.
WEIGHT_ANCHOR = 0.4
WEIGHT_CRITIC = 0.3
WEIGHT_SCHEMA = 0.2
WEIGHT_SELF = 0.1

#: What a component contributes when it does not exist for this kind of
#: finding. Neutral, not zero: see the module docstring.
NEUTRAL = 0.5

#: The judge's three-way verdict as a number. **Provisional**, and named in the
#: plan's step 9 as one of the things the corpus is meant to settle.
#:
#: `LOW` is 0.2 rather than 0.0 deliberately. Low evidence quality means the
#: state contains an unverified claim somewhere, not that this finding is
#: false, and the component is shared across the state's findings — a zero
#: would delete 30% of the score for every finding in a passage on the strength
#: of one bad claim elsewhere in it.
CRITIC_SCORES: dict[EvidenceQuality, float] = {
    EvidenceQuality.HIGH: 1.0,
    EvidenceQuality.MODERATE: 0.6,
    EvidenceQuality.LOW: 0.2,
}


@dataclass(frozen=True)
class Components:
    """The four measurements behind one finding's score.

    `None` means the measurement was not taken, and is persisted as null rather
    than as a number so a later recalibration can tell it from a poor score.

    `not_applicable` says *why* it was not taken, and the distinction turned out
    to matter more than it looked. Two different absences were being treated as
    one:

    - **Contingent.** The signal exists for this kind of finding and is missing
      here: a technique whose confidence came back null, a state the judge never
      reached. Neutral 0.5 is right, and the weight stays in the sum, because a
      finding measured on fewer signals than its peers should not score like one
      measured on all of them.
    - **Structural.** The signal does not exist for this kind at all. Indicators
      carry no self-report because the schema never asks the model for one.
      Substituting neutral there applies a fixed discount to an entire category
      for a question the design does not pose, which is not a measurement of
      anything. Measured on the corpus: it capped every indicator's raw score at
      0.95 and no indicator ever reached the 0.85 floor.

    So a structurally absent component is removed and the remaining weights are
    renormalised. The rule the phase plan set out, that three signals must not
    buy what four buy, is kept exactly where it was aimed: at contingent gaps.
    """

    anchor_ratio: float | None = None
    critic_agreement: float | None = None
    schema_completeness: float | None = None
    self_assessed: float | None = None
    #: Names of the components this kind of finding structurally does not have.
    not_applicable: frozenset[str] = frozenset()


def _count(value: Any) -> int | None:
    """A grounding entry's size, whether it was stored as a number or a list.

    The two extraction states do not agree on the shape, and this was found by
    running the gate over real rows rather than by reading the code: under
    `grounding`, `extract_ioc` writes `kept` as a count and `map_ttp` writes it
    as the list of mappings it kept. Both are reasonable and neither is going to
    be rewritten, because changing the stored shape would change the meaning of
    every run row already written. So the reader accommodates both and says so
    here, instead of the mismatch surfacing as a TypeError on whichever article
    happens to have techniques.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return None


def anchor_ratio(grounding: Mapping[str, Any] | None) -> float | None:
    """How much of what the state proposed survived anchoring.

    Reads the `grounding` block the machine already stores on the run row:
    what it kept against what it threw out. A state that proposed nothing
    returns None — there is no ratio to take, and a 0.0 would read as total
    fabrication when nothing was even attempted.
    """
    if not grounding:
        return None
    kept = _count(grounding.get("kept"))
    rejected = _count(grounding.get("rejected"))
    if kept is None or rejected is None:
        return None
    proposed = kept + rejected
    if proposed <= 0:
        return None
    return kept / proposed


def critic_agreement(quality: EvidenceQuality | str | None) -> float | None:
    """The independent judge's verdict on the state, as a number.

    Accepts the enum or the stored string, because the value arrives from a
    JSON column as often as from a model instance.
    """
    if quality is None:
        return None
    try:
        return CRITIC_SCORES[EvidenceQuality(quality)]
    except ValueError:
        return None


def schema_completeness(finding: BaseModel) -> float | None:
    """The fraction of the model's optional fields the finding actually filled.

    Optional means the schema gave it a default: those are the fields the model
    could have left alone, so filling them is the only part of the schema that
    carries information about effort. Required fields are not evidence — the
    validator would have refused the output without them.

    A schema with no optional fields at all returns None rather than 1.0. A
    perfect score for having no opportunity to fail is not a measurement, and
    it would quietly hand every technique mapping a free 0.2.
    """
    optional = [
        name for name, field in type(finding).model_fields.items() if not field.is_required()
    ]
    if not optional:
        return None
    filled = sum(_is_filled(getattr(finding, name, None)) for name in optional)
    return filled / len(optional)


def _is_filled(value: Any) -> bool:
    """Populated means it says something. Empty string, empty list, None do not.

    `False` and `0` do: a model that answered "no" answered.
    """
    if value is None:
        return False
    if isinstance(value, str | list | dict | tuple | set):
        return bool(value)
    return True


def composite(components: Components) -> float:
    """The weighted sum, on the scale the thresholds are written for.

    This is `score_raw`. The source and information grades are applied after it
    and elsewhere: mixing the evaluation of the source into the measurement of
    the model's behaviour is what UNODC's chapter 4 forbids, and keeping the
    layers apart is what lets either be retuned without the other.

    Components the kind structurally does not have are dropped and the rest
    renormalised, so the score of every kind spans the same 0 to 1 the roadmap's
    floors were written against. Components that are merely missing keep their
    weight and take the neutral value. See `Components` for why the two absences
    are not the same.
    """
    pairs = (
        ("anchor_ratio", components.anchor_ratio, WEIGHT_ANCHOR),
        ("critic_agreement", components.critic_agreement, WEIGHT_CRITIC),
        ("schema_completeness", components.schema_completeness, WEIGHT_SCHEMA),
        ("self_assessed", components.self_assessed, WEIGHT_SELF),
    )
    applicable = [item for item in pairs if item[0] not in components.not_applicable]
    total_weight = sum(weight for _, _, weight in applicable)
    if total_weight <= 0:
        # Every component declared inapplicable. Nothing was measured, and
        # neutral is the honest answer: not zero, which would read as a finding
        # proven bad, and not one, which would read as a finding proven good.
        return NEUTRAL
    return (
        sum((NEUTRAL if value is None else value) * weight for _, value, weight in applicable)
        / total_weight
    )
