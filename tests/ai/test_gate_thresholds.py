# "The temptation to form premature theories is the bane of our profession."
"""The gate's floors and the decision they make.

Two properties carry most of the weight here. The category floor applies
*before* the overall one and not instead of it, which is roadmap criterion 2
read literally. And the local lift raises the bar rather than the score, which
is the correction the phase plan needed: the two readings move findings in
opposite directions, so a test that only checked "something changed" would
have passed on the wrong one.
"""

import pytest

from pestilentia.ai.confidence.grading import GradedScore, InfoGrade, SourceGrade
from pestilentia.ai.confidence.thresholds import (
    Decision,
    FindingKind,
    category_floor,
    decide,
    thresholds_for,
)
from pestilentia.config import Settings

CONFIG = Settings()


def _graded(total: float, *, unjudgeable: bool = False, missing: str = "source") -> GradedScore:
    return GradedScore(
        score_raw=total,
        source_grade=SourceGrade.CANNOT_BE_JUDGED if unjudgeable else SourceGrade.USUALLY_RELIABLE,
        source_factor=None if unjudgeable and missing in ("source", "both") else 0.9,
        info_grade=InfoGrade.CANNOT_BE_JUDGED if unjudgeable else InfoGrade.CONFIRMED,
        info_factor=None if unjudgeable and missing in ("information", "both") else 1.0,
        score_total=total,
        unjudgeable=unjudgeable,
    )


# --- the floors --------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (FindingKind.IOC, 0.85),
        (FindingKind.TTP, 0.70),
        (FindingKind.NARRATIVE, 0.90),
        (FindingKind.SKETCH, 0.75),
    ],
)
def test_the_roadmap_defaults_are_the_defaults(kind, expected):
    assert category_floor(kind, CONFIG) == expected


def test_the_diamond_borrows_the_overall_floor_rather_than_inventing_one():
    """The roadmap names four categories and Diamond is not among them.
    Inventing a fifth number would be adding a policy the sources do not hold."""
    assert category_floor(FindingKind.DIAMOND, CONFIG) == CONFIG.ai_gate_overall_min


def test_a_narrative_is_held_to_a_higher_bar_than_a_technique():
    """A wrong sentence in a report is read as an assessment; a wrong technique
    mapping is read as one mapping among ten."""
    assert category_floor(FindingKind.NARRATIVE, CONFIG) > category_floor(FindingKind.TTP, CONFIG)


# --- the local lift ----------------------------------------------------------


def test_a_local_run_lifts_the_thresholds_and_does_not_lift_the_score():
    """The correction the plan needed. Lifting thresholds makes a small local
    model harder to trust automatically; lifting the score would make it
    easier, and both are 'applying +0.10'."""
    cloud, cloud_overall = thresholds_for(FindingKind.IOC, local_run=False, settings=CONFIG)
    local, local_overall = thresholds_for(FindingKind.IOC, local_run=True, settings=CONFIG)

    assert local == pytest.approx(cloud + CONFIG.ai_gate_local_lift)
    assert local_overall == pytest.approx(cloud_overall + CONFIG.ai_gate_local_lift)
    assert local > cloud, "the bar rises, so the same score is trusted less"


def test_a_finding_that_passes_on_the_cloud_can_fail_the_same_run_locally():
    """Criterion 2, stated as the behaviour rather than as the arithmetic."""
    graded = _graded(0.88)

    assert decide(graded, FindingKind.IOC, settings=CONFIG).decision is Decision.AUTO
    assert (
        decide(graded, FindingKind.IOC, local_run=True, settings=CONFIG).decision is Decision.STAGED
    )


def test_the_lift_cannot_push_a_threshold_past_one():
    """A gate nothing can pass has stopped being a gate: it is a refusal with
    extra steps, and it would look like a scoring problem to whoever debugged
    it."""
    strict = Settings(ai_gate_narrative_min=0.95, ai_gate_local_lift=0.10)
    category, overall = thresholds_for(FindingKind.NARRATIVE, local_run=True, settings=strict)

    assert category == 1.0
    assert overall <= 1.0


# --- the decision ------------------------------------------------------------


def test_clearing_both_floors_enriches():
    decision = decide(_graded(0.92), FindingKind.IOC, settings=CONFIG)

    assert decision.decision is Decision.AUTO
    assert decision.enriches is True


def test_the_category_floor_bites_before_the_overall_one():
    """0.80 clears the overall 0.75 and misses the IOC 0.85. If the overall
    gate were applied first, or instead, this would enrich."""
    decision = decide(_graded(0.80), FindingKind.IOC, settings=CONFIG)

    assert decision.decision is Decision.STAGED
    assert "under the ioc floor" in decision.reason


def test_the_overall_floor_still_bites_when_the_category_one_is_lenient():
    """0.72 clears the TTP floor of 0.70 and misses the overall 0.75. Without
    the second test this would enrich on the strength of a lenient category."""
    decision = decide(_graded(0.72), FindingKind.TTP, settings=CONFIG)

    assert decision.decision is Decision.STAGED
    assert "not the overall" in decision.reason


@pytest.mark.parametrize("missing", ["source", "information", "both"])
def test_an_ungradeable_axis_stages_whatever_the_number_says(missing):
    """Criterion 1c. A perfect score on a source nobody has graded is still not
    enrichable, and no threshold overrules that."""
    decision = decide(
        _graded(1.0, unjudgeable=True, missing=missing), FindingKind.IOC, settings=CONFIG
    )

    assert decision.decision is Decision.STAGED
    assert "could not be graded" in decision.reason


def test_the_row_says_which_axis_could_not_be_judged():
    """A reviewer opening the queue is owed the reason, not just the verdict."""
    source_only = decide(
        _graded(1.0, unjudgeable=True, missing="source"), FindingKind.IOC, settings=CONFIG
    )
    both = decide(_graded(1.0, unjudgeable=True, missing="both"), FindingKind.IOC, settings=CONFIG)

    assert source_only.reason.startswith("source")
    assert "neither" in both.reason


def test_the_thresholds_that_were_applied_are_recorded_on_the_decision():
    """Persisted as `threshold_applied`, so a row can be re-judged later against
    the numbers it actually met rather than today's."""
    decision = decide(_graded(0.60), FindingKind.SKETCH, local_run=True, settings=CONFIG)

    assert decision.threshold_applied == pytest.approx(0.85)
    assert decision.overall_applied == pytest.approx(0.85)


def test_a_staged_finding_is_queued_and_not_discarded():
    """`rejected` exists in the vocabulary and nothing sets it. Staged means a
    person decides; it must never quietly mean the finding was dropped."""
    decision = decide(_graded(0.10), FindingKind.NARRATIVE, settings=CONFIG)

    assert decision.decision is Decision.STAGED
    assert decision.decision is not Decision.REJECTED


def test_moving_a_threshold_moves_findings_between_auto_and_staged():
    """Criterion 2's own wording, and the property that makes the gate
    recalibrable at all: no LLM call is involved in changing this answer."""
    graded = _graded(0.80)
    strict = Settings(ai_gate_ioc_min=0.85)
    lenient = Settings(ai_gate_ioc_min=0.75)

    assert decide(graded, FindingKind.IOC, settings=strict).decision is Decision.STAGED
    assert decide(graded, FindingKind.IOC, settings=lenient).decision is Decision.AUTO


# --- can a category be cleared at all? ---------------------------------------


def test_no_category_is_closed_by_arithmetic_under_the_default_floors():
    """This check caught a real one and is kept for the smaller job it still has.

    While the floors were compared against the axis-multiplied total, the IOC
    floor of 0.85 against the 0.75 factor of an uncorroborated first report
    needed a composite of 1.133, and none exceeds 1.0. Nought of 406 indicators
    could pass, and it looked like judgement. Since the floors moved onto
    `score_raw` the axes cap nothing, so only a misconfigured floor can shut a
    category.
    """
    from pestilentia.ai.confidence.thresholds import unreachable

    assert unreachable(settings=CONFIG) == []


def test_a_floor_a_lift_cannot_be_added_to_is_still_caught():
    """0.95 with a 0.10 local lift is a category nobody can enter. The cap in
    `thresholds_for` keeps it at 1.0, which a perfect composite can still meet,
    so the guard has to agree with the cap rather than with the raw sum."""
    from pestilentia.ai.confidence.thresholds import reachability

    strict = Settings(ai_gate_narrative_min=0.95, ai_gate_local_lift=0.10)
    entry = next(
        e for e in reachability(local_run=True, settings=strict) if e.kind is FindingKind.NARRATIVE
    )

    assert entry.floor == 1.0
    assert entry.reachable, "a perfect composite must still be able to meet a capped floor"


def test_the_ceiling_is_the_composite_scale_and_no_longer_the_axes():
    from pestilentia.ai.confidence.thresholds import reachability

    assert all(entry.ceiling == 1.0 for entry in reachability(settings=CONFIG))


# --- the floors act on the raw composite, not on the axis-multiplied total ---


def test_the_decision_reads_the_raw_composite_and_not_the_total():
    """Decided 2026-08-15 on the corpus. The roadmap's floors were written when
    the axes did not exist, so they describe the composite alone; holding the
    axis-multiplied product to them shut whole categories."""
    graded = GradedScore(
        score_raw=0.90,
        source_grade=SourceGrade.USUALLY_RELIABLE,
        source_factor=0.90,
        info_grade=InfoGrade.POSSIBLY_TRUE,
        info_factor=0.75,
        score_total=0.90 * 0.90 * 0.75,
        unjudgeable=False,
    )

    assert graded.score_total < 0.85 < graded.score_raw, "the two answers differ here"
    assert decide(graded, FindingKind.IOC, settings=CONFIG).decision is Decision.AUTO


def test_the_total_is_still_computed_so_the_comparison_can_be_switched_back():
    """The axes keep explaining even though they no longer discount, and a later
    recalibration must be able to move the comparison without re-running the
    pipeline."""
    graded = GradedScore(
        score_raw=0.90,
        source_grade=SourceGrade.USUALLY_RELIABLE,
        source_factor=0.90,
        info_grade=InfoGrade.POSSIBLY_TRUE,
        info_factor=0.75,
        score_total=0.6075,
        unjudgeable=False,
    )

    assert graded.score_total == pytest.approx(0.6075)
    assert graded.source_grade is SourceGrade.USUALLY_RELIABLE


def test_an_ungradeable_axis_still_vetoes_a_perfect_composite():
    """The axes lost the discount and kept the veto, which is the job UNODC
    actually gives them: the gate does not guess."""
    graded = GradedScore(
        score_raw=1.0,
        source_grade=SourceGrade.CANNOT_BE_JUDGED,
        source_factor=None,
        info_grade=InfoGrade.CONFIRMED,
        info_factor=1.0,
        score_total=1.0,
        unjudgeable=True,
    )

    assert decide(graded, FindingKind.IOC, settings=CONFIG).decision is Decision.STAGED
