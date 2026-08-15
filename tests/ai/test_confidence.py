# "There is nothing more deceptive than an obvious fact." — Sherlock Holmes
"""Phase 5 step 3: the composite, and the three definitions behind it.

The arithmetic is not what needs pinning down — the interpretations are. Each
of the three was a choice made in the plan, each could be read another way by
the next person to open the file, and each would change every score in the
database if it were changed quietly.
"""

import pytest

from pestilentia.ai.confidence import (
    NEUTRAL,
    WEIGHT_ANCHOR,
    WEIGHT_CRITIC,
    WEIGHT_SCHEMA,
    WEIGHT_SELF,
    Components,
    anchor_ratio,
    composite,
    critic_agreement,
    schema_completeness,
)
from pestilentia.ai.schemas import (
    AdversarySketchOutput,
    AttributionLevel,
    ConfidenceLevel,
    EvidenceQuality,
    ExtractedIoc,
    IocType,
    Likelihood,
    NamedActor,
    NarrativeOutput,
    TtpMapping,
)

# --- anchoring: survivors over proposals, per state --------------------------


def test_the_anchor_ratio_is_what_survived_of_what_was_proposed():
    """The acceptance article: 35 indicators proposed, 29 kept, six inventions."""
    grounding = {"kept": 29, "rejected": [{"value": f"x{n}"} for n in range(6)]}

    assert anchor_ratio(grounding) == pytest.approx(29 / 35)


def test_a_state_that_invented_nothing_scores_one():
    assert anchor_ratio({"kept": 12, "rejected": []}) == 1.0


def test_a_state_that_proposed_nothing_is_not_measured_at_all():
    """Zero of zero is not total fabrication, it is no attempt.

    Scoring it 0.0 would take 40% off the top of every finding of a state that
    simply had nothing to find, which on a corpus of short articles is most of
    them.
    """
    assert anchor_ratio({"kept": 0, "rejected": []}) is None


def test_a_state_where_everything_was_invented_scores_zero_and_is_measured():
    """The opposite case, and it must not collapse into the same None."""
    assert anchor_ratio({"kept": 0, "rejected": [{"value": "a"}, {"value": "b"}]}) == 0.0


@pytest.mark.parametrize("grounding", [None, {}, {"kept": 3}, {"rejected": []}])
def test_a_state_with_no_grounding_block_yields_nothing_rather_than_guessing(grounding):
    """Triage and narrative have no grounding check; a half-written block is a
    bug upstream. Neither is an occasion to invent a ratio."""
    assert anchor_ratio(grounding) is None


# --- critic agreement: the judge's verdict, per state ------------------------


@pytest.mark.parametrize(
    ("quality", "expected"),
    [(EvidenceQuality.HIGH, 1.0), (EvidenceQuality.MODERATE, 0.6), (EvidenceQuality.LOW, 0.2)],
)
def test_the_judges_verdict_becomes_a_number(quality, expected):
    assert critic_agreement(quality) == expected
    assert critic_agreement(quality.value) == expected, "the stored string works too"


def test_low_evidence_quality_is_punished_hard_but_not_absolutely():
    """A zero would delete 30% of the score for every finding in a passage on
    the strength of one unverified claim elsewhere in that passage. The
    component is shared across a state; the penalty has to be survivable."""
    assert 0 < critic_agreement(EvidenceQuality.LOW) < critic_agreement(EvidenceQuality.MODERATE)


@pytest.mark.parametrize("value", [None, "", "excellent"])
def test_no_verdict_is_not_a_bad_verdict(value):
    """The judge did not run, or the state predates it. Either way, unmeasured."""
    assert critic_agreement(value) is None


# --- schema completeness -----------------------------------------------------


def test_completeness_counts_the_optional_fields_the_model_bothered_to_fill():
    """`context` is the one optional field on an indicator."""
    bare = ExtractedIoc(ioc_type=IocType.IPV4, value="1.2.3.4", value_as_written="1.2.3[.]4")
    quoted = ExtractedIoc(
        ioc_type=IocType.IPV4,
        value="1.2.3.4",
        value_as_written="1.2.3[.]4",
        context="the beacon called home to 1.2.3[.]4",
    )

    assert schema_completeness(bare) == 0.0
    assert schema_completeness(quoted) == 1.0


def test_a_schema_with_nothing_optional_is_not_handed_a_free_full_mark():
    """Every field of a technique mapping is required, so there is nothing to
    measure. Returning 1.0 would give every TTP a free 0.2 for having had no
    opportunity to fail."""
    mapping = TtpMapping(technique_id="T1059", evidence_quote="ran powershell", confidence=0.8)

    assert schema_completeness(mapping) is None


def test_partial_completion_is_a_fraction_not_a_verdict():
    sketch = AdversarySketchOutput(
        attribution_level=AttributionLevel.TACTICAL,
        cluster_summary="a ransomware affiliate",
        named_actors=[NamedActor(name="Akira")],
        likelihood=Likelihood.LIKELY,
        confidence=ConfidenceLevel.MODERATE,
        shared_infrastructure_note="none observed",
        false_flag_note="no indication",
    )

    # attribution_level and named_actors are the optional pair; both are filled.
    assert schema_completeness(sketch) == 1.0

    thin = sketch.model_copy(update={"named_actors": []})
    assert schema_completeness(thin) == 0.5


def test_an_empty_string_is_not_an_answer():
    """`recommendations_md` defaults to empty, and staying empty is declining
    to answer, not answering."""
    narrative = NarrativeOutput(
        key_judgement="Akira is likely responsible.",
        confidence=ConfidenceLevel.MODERATE,
        summary_md="## Summary",
    )

    assert schema_completeness(narrative) == 0.0


# --- the composite -----------------------------------------------------------


def test_all_four_present_is_the_weighted_sum():
    score = composite(
        Components(
            anchor_ratio=1.0, critic_agreement=1.0, schema_completeness=1.0, self_assessed=1.0
        )
    )

    assert score == pytest.approx(1.0)
    assert pytest.approx(1.0) == WEIGHT_ANCHOR + WEIGHT_CRITIC + WEIGHT_SCHEMA + WEIGHT_SELF


def test_the_self_report_is_the_weakest_voice_by_design():
    """A model that rates itself well must not be able to buy much with it.

    Anchoring is a measurement of what the article supports; the self-report is
    the model's opinion of itself. Four to one is the roadmap's ratio, and the
    test is here so that a later tweak has to argue with it.
    """
    generous = composite(Components(anchor_ratio=0.0, self_assessed=1.0))
    honest = composite(Components(anchor_ratio=1.0, self_assessed=0.0))

    assert honest > generous
    assert pytest.approx(4 * WEIGHT_SELF) == WEIGHT_ANCHOR


def test_a_component_that_does_not_apply_is_neutral_not_zero():
    """An indicator carries no self-report. Scoring it zero would mark every
    indicator down for a question the prompt never asked."""
    absent = composite(Components(anchor_ratio=1.0, critic_agreement=1.0, schema_completeness=1.0))
    zeroed = composite(
        Components(
            anchor_ratio=1.0, critic_agreement=1.0, schema_completeness=1.0, self_assessed=0.0
        )
    )

    assert absent == pytest.approx(1.0 - WEIGHT_SELF + NEUTRAL * WEIGHT_SELF)
    assert absent > zeroed


def test_the_weights_do_not_renormalise_over_the_components_present():
    """A finding measured on three signals must not be able to reach the same
    total as one measured on four. Renormalising would let a missing component
    be free rather than neutral."""
    three = composite(Components(anchor_ratio=1.0, critic_agreement=1.0, schema_completeness=1.0))

    assert three < 1.0


def test_nothing_measured_at_all_lands_on_neutral():
    """Not zero. Zero would read as a finding proven bad, which is the opposite
    of a finding nobody could measure — and the gate stages what it cannot
    judge instead of rejecting it."""
    assert composite(Components()) == pytest.approx(NEUTRAL)


def test_the_two_extraction_states_disagree_on_the_shape_and_both_are_read():
    """Found by running the gate over real rows, not by reading the code.

    Under `grounding`, `extract_ioc` writes `kept` as a count and `map_ttp`
    writes it as the list of mappings it kept. Neither shape is going to be
    rewritten, because changing it would change the meaning of every run row
    already stored, so the reader accommodates both. Before this the mismatch
    surfaced as a TypeError on whichever article happened to have techniques.
    """
    counted = {"kept": 8, "rejected": [{"value": "a"}, {"value": "b"}]}
    listed = {"kept": [{"technique_id": "T1190"}] * 8, "rejected": [{"id": "a"}, {"id": "b"}]}

    assert anchor_ratio(counted) == anchor_ratio(listed) == pytest.approx(0.8)


def test_a_rejected_count_stored_as_a_number_reads_the_same_as_a_list():
    assert anchor_ratio({"kept": 9, "rejected": 1}) == pytest.approx(0.9)


def test_a_boolean_is_not_mistaken_for_a_count():
    """`True` is an int in Python, and reading it as one would turn a flag into
    a kept-count of 1."""
    assert anchor_ratio({"kept": True, "rejected": 0}) is None
