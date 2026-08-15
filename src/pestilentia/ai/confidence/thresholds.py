# "The temptation to form premature theories is the bane of our profession."
"""The thresholds, and the decision they make (Phase 5, step 4).

Roadmap criterion 2: per-category floors apply **before** the overall gate, not
instead of it. A finding has to clear both. The category floor is where the
domain judgement lives, and the overall floor is the one an operator raises when
the whole pipeline is behaving worse than it should.

The values are configuration rather than code because they are meant to be
retuned, and they are a **closed set** rather than a rule engine because a gate
that can be explained is worth more than one that can be shaped. Five floors,
one lift, two grade maps: an analyst can hold all of it in mind at once, which
is the property that makes an automated decision arguable.

**The local lift raises the bar, it does not lower it.** ADR-006 section 4 and
roadmap criterion 2 both say "local-model runs lift every threshold by +0.10".
An earlier draft of the phase plan had it lifting the score instead, which runs
the opposite way: lifting thresholds makes a small local model harder to trust
automatically, lifting scores would make it easier. The sources decide.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pestilentia.ai.confidence.grading import GradedScore
from pestilentia.config import Settings, get_settings


class FindingKind(StrEnum):
    """What sort of finding is being gated. Persisted as `finding_kind`."""

    IOC = "ioc"
    TTP = "ttp"
    NARRATIVE = "narrative"
    SKETCH = "sketch"
    DIAMOND = "diamond"


class Decision(StrEnum):
    """Persisted as `decision`. Three outcomes, and every one gets a row."""

    #: Clears both floors and both axes could be judged: enriches directly.
    AUTO = "auto"
    #: Anything a person has to look at. The queue, not the bin.
    STAGED = "staged"
    #: Kept for a later policy that discards outright. Nothing sets it yet, and
    #: the plan says so rather than leaving an unused branch looking deliberate.
    REJECTED = "rejected"


@dataclass(frozen=True)
class GateDecision:
    """What the gate decided, and enough of the arithmetic to argue with it."""

    decision: Decision
    threshold_applied: float
    overall_applied: float
    reason: str

    @property
    def enriches(self) -> bool:
        return self.decision is Decision.AUTO


def category_floor(kind: FindingKind, settings: Settings | None = None) -> float:
    """The per-category floor before any lift.

    The Diamond Model takes the overall floor rather than one of its own: the
    roadmap names four categories and Diamond is not among them, and inventing
    a fifth number would be adding a policy the sources of record do not carry.
    """
    config = settings if settings is not None else get_settings()
    return {
        FindingKind.IOC: config.ai_gate_ioc_min,
        FindingKind.TTP: config.ai_gate_ttp_min,
        FindingKind.NARRATIVE: config.ai_gate_narrative_min,
        FindingKind.SKETCH: config.ai_gate_sketch_min,
        FindingKind.DIAMOND: config.ai_gate_overall_min,
    }[kind]


def thresholds_for(
    kind: FindingKind, *, local_run: bool = False, settings: Settings | None = None
) -> tuple[float, float]:
    """The category floor and the overall floor, with the local lift applied.

    Capped at 1.0. A lift that pushed a 0.95 threshold to 1.05 would make the
    category unreachable by arithmetic rather than by policy, and a gate nothing
    can pass is a gate that has stopped being a gate.
    """
    config = settings if settings is not None else get_settings()
    lift = config.ai_gate_local_lift if local_run else 0.0
    return (
        min(1.0, category_floor(kind, config) + lift),
        min(1.0, config.ai_gate_overall_min + lift),
    )


def decide(
    graded: GradedScore,
    kind: FindingKind,
    *,
    local_run: bool = False,
    settings: Settings | None = None,
) -> GateDecision:
    """Auto or staged, with the reason in words.

    **The floors are compared against `score_raw`, not against the total.**
    Decided 2026-08-15 on the corpus, and it amends how decision 1 of the phase
    plan is applied rather than reversing it. The roadmap's floors were written
    when the two axes did not exist, so they describe the composite alone;
    multiplying the composite by two factors each at most 1.0 and then holding
    the product to a floor set for the unmultiplied number closed whole
    categories by arithmetic. Measured: 0 of 406 indicators could pass.

    The reason it bites indicators and not techniques is worth keeping in view.
    The information axis is built on cross-feed corroboration, and indicators
    are almost never corroborated: 4 of 406, 1%. A technique is, constantly.
    So for indicators grade 3 is effectively universal, its factor is a constant
    multiplier on the whole category, and a constant multiplier against a fixed
    floor is just a different floor wearing an axis's clothes.

    The axes keep the two jobs that are actually theirs, which is closer to
    UNODC's own use of them than a discount was: **a veto**, since an
    ungradeable axis still stages whatever the number says, and **an
    explanation**, since both grades and both factors stay on the row. The
    total is still computed and persisted, so a later recalibration can switch
    the comparison back without re-running anything.

    Order matters and is the roadmap's: the unjudgeable check first, because it
    is a statement about whether the question was answerable at all and no
    number overrules it; then the category floor; then the overall floor.

    The reason is stored on the row rather than reconstructed later. A staged
    finding whose score sits above its category floor was staged for a reason
    that the number alone cannot explain, and a reviewer opening the queue
    deserves to be told which of the three tests it failed.
    """
    category, overall = thresholds_for(kind, local_run=local_run, settings=settings)
    score = graded.score_raw

    if graded.unjudgeable:
        axis = "source" if graded.source_factor is None else "information"
        if graded.source_factor is None and graded.info_factor is None:
            axis = "neither source nor information"
        return GateDecision(
            Decision.STAGED,
            category,
            overall,
            f"{axis} could not be graded, so the gate did not guess",
        )

    if score < category:
        return GateDecision(
            Decision.STAGED,
            category,
            overall,
            f"{score:.3f} is under the {kind.value} floor of {category:.2f}",
        )

    if score < overall:
        return GateDecision(
            Decision.STAGED,
            category,
            overall,
            f"{score:.3f} clears {kind.value} but not the overall {overall:.2f}",
        )

    return GateDecision(
        Decision.AUTO,
        category,
        overall,
        f"{score:.3f} clears both the {kind.value} floor and the overall gate",
    )


@dataclass(frozen=True)
class Reachability:
    """Whether a category can be cleared at all.

    It exists because it caught a real one. While the floors were compared
    against the axis-multiplied total, a floor combined with a factor stopped
    being a policy and became arithmetic: the IOC floor of 0.85 against the 0.75
    factor of an uncorroborated first report needed a composite of 1.133, and no
    composite exceeds 1.0. The category was shut, and it looked like judgement.

    Since the floors moved onto `score_raw` the axes no longer cap anything, so
    the ceiling is simply 1.0 and only a misconfigured floor can close a
    category. That is a smaller job than the one this was written for, and it is
    kept because the smaller job is still real: a floor of 0.95 with a local
    lift of 0.10 is a category nobody can enter.
    """

    kind: FindingKind
    floor: float
    ceiling: float = 1.0

    @property
    def reachable(self) -> bool:
        return self.floor <= self.ceiling


def reachability(
    *, local_run: bool = False, settings: Settings | None = None
) -> list[Reachability]:
    """Each category's floor against the best composite any finding can reach."""
    config = settings if settings is not None else get_settings()
    return [
        Reachability(kind, thresholds_for(kind, local_run=local_run, settings=config)[0])
        for kind in FindingKind
    ]


def unreachable(*, local_run: bool = False, settings: Settings | None = None) -> list[Reachability]:
    """Only the categories no finding can ever clear."""
    return [
        entry
        for entry in reachability(local_run=local_run, settings=settings)
        if not entry.reachable
    ]
