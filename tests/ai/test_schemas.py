"""The eight state schemas: what they accept, and what they must refuse.

These models are where a bad generation becomes a re-ask instead of a corrupt
row, so the refusals matter more than the happy paths.
"""

import pytest
from pydantic import ValidationError

from pestilentia.ai.schemas import (
    STATE_ORDER,
    STATE_SCHEMAS,
    AdversarySketchOutput,
    AttributionLevel,
    AuditedClaim,
    AuditLabel,
    ClassifyOutput,
    DiamondModelOutput,
    DiamondVertex,
    EvidenceLabel,
    EvidenceQuality,
    ExtractedIoc,
    ExtractIocOutput,
    MapTtpOutput,
    NarrativeOutput,
    TriageOutput,
    TtpMapping,
    VerifyOutput,
)


def test_every_state_has_a_schema_and_the_order_matches_the_adr():
    assert STATE_ORDER == (
        "triage",
        "classify",
        "extract_ioc",
        "map_ttp",
        "diamond_model",
        "narrative",
        "adversary_sketch",
        "verify",
    )
    assert set(STATE_SCHEMAS) == set(STATE_ORDER)


@pytest.mark.parametrize("state", STATE_ORDER)
def test_unknown_fields_are_refused_in_every_state(state):
    """A model inventing a field misread the task; dropping it silently would
    discard the signal and let the run look clean."""
    schema = STATE_SCHEMAS[state]
    with pytest.raises(ValidationError, match=r"[Ee]xtra"):
        schema.model_validate({"surprise": "value"})


# --- Triage / Classify -------------------------------------------------------


def test_triage_roundtrip():
    out = TriageOutput(relevant=False, reason="vendor marketing, no incident")
    assert out.relevant is False


def test_reason_is_bounded():
    with pytest.raises(ValidationError):
        TriageOutput(relevant=True, reason="x" * 5_000)


def test_classify_refuses_a_type_outside_the_fixed_set():
    with pytest.raises(ValidationError):
        ClassifyOutput(
            article_type="opinion_piece",
            confidence="high confidence",
            evidence_quote="…",
        )


def test_confidence_must_use_the_icd203_wording():
    with pytest.raises(ValidationError):
        ClassifyOutput(article_type="blog", confidence="pretty sure", evidence_quote="…")


# --- ExtractIOC --------------------------------------------------------------


def test_ioc_keeps_both_the_canonical_and_the_written_form():
    ioc = ExtractedIoc(ioc_type="ipv4", value="1.2.3.4", value_as_written="1.2.3[.]4")
    assert ioc.value != ioc.value_as_written


def test_ioc_schema_exposes_no_offset_field():
    """Offsets are computed by anchors.py against the body. A model asked for
    character positions returns confident arithmetic about text it cannot
    count, and a fabricated offset is indistinguishable from a real one."""
    fields = set(ExtractedIoc.model_fields)
    assert not fields & {"span_start", "span_end", "offset", "position", "index"}


def test_ioc_list_is_capped():
    many = [
        {"ioc_type": "md5", "value": f"{i:032x}", "value_as_written": f"{i:032x}"}
        for i in range(101)
    ]
    with pytest.raises(ValidationError):
        ExtractIocOutput(iocs=many)


def test_empty_ioc_list_is_valid():
    assert ExtractIocOutput().iocs == []


# --- MapTTP ------------------------------------------------------------------


def test_ttp_confidence_is_a_unit_interval():
    TtpMapping(technique_id="T1486", evidence_quote="files were encrypted", confidence=0.8)
    for bad in (-0.1, 1.1):
        with pytest.raises(ValidationError):
            TtpMapping(technique_id="T1486", evidence_quote="q", confidence=bad)


def test_ttp_evidence_quote_cannot_be_empty():
    """A mapping without a quote cannot be checked against the body, which
    makes it an assertion rather than evidence."""
    with pytest.raises(ValidationError):
        TtpMapping(technique_id="T1486", evidence_quote="", confidence=0.5)


def test_an_eleventh_mapping_is_not_a_failed_answer():
    """The criterion's ten is enforced in `ttps.reconcile`, not here.

    The acceptance run showed why: a model returning eleven had three good
    answers thrown away and re-asked at full price, when keeping the best ten
    and recording the eleventh as `over_cap` says more and costs nothing.
    """
    mappings = [
        {"technique_id": "T1486", "evidence_quote": "q", "confidence": 0.5} for _ in range(11)
    ]

    assert len(MapTtpOutput(mappings=mappings).mappings) == 11


def test_the_schema_still_guards_against_a_runaway():
    mappings = [
        {"technique_id": "T1486", "evidence_quote": "q", "confidence": 0.5} for _ in range(51)
    ]
    with pytest.raises(ValidationError):
        MapTtpOutput(mappings=mappings)


# --- DiamondModel ------------------------------------------------------------


def test_absent_vertex_is_none_not_prose():
    out = DiamondModelOutput(
        infrastructure=DiamondVertex(
            summary="C2 on a bulletproof host",
            label=EvidenceLabel.OBSERVED,
            evidence_quote="hosted at …",
        )
    )
    assert out.adversary is None
    assert out.vertices_supported == 1


def test_every_vertex_carries_its_own_label():
    """The label is per-vertex so one cannot lean on another's evidence."""
    with pytest.raises(ValidationError):
        DiamondVertex(summary="…")


# --- Narrative / AdversarySketch --------------------------------------------


def test_narrative_leads_with_a_judgement():
    out = NarrativeOutput(
        key_judgement="We assess that the intrusion began with a phished credential.",
        confidence="moderate confidence",
        summary_md="## Summary\n…",
    )
    assert out.recommendations_md == ""


def test_sketch_defaults_to_tactical_attribution():
    out = AdversarySketchOutput(
        cluster_summary="Four samples share a packer.",
        likelihood="likely",
        confidence="moderate confidence",
        shared_infrastructure_note="Operator vs affiliate not separable from this article.",
        false_flag_note="Considered; no imitation markers present.",
    )
    assert out.attribution_level is AttributionLevel.TACTICAL


@pytest.mark.parametrize("missing", ["shared_infrastructure_note", "false_flag_note"])
def test_sketch_requires_both_caveats(missing):
    """In ransomware reporting the operator/affiliate/broker split and the
    false-flag question are the normal case, not an edge case."""
    payload = {
        "cluster_summary": "…",
        "likelihood": "likely",
        "confidence": "low confidence",
        "shared_infrastructure_note": "…",
        "false_flag_note": "…",
    }
    del payload[missing]
    with pytest.raises(ValidationError):
        AdversarySketchOutput.model_validate(payload)


def test_sketch_exposes_no_group_id():
    """The LLM never picks a Group.id (ADR-006 §3); resolution is Phase 5's."""
    assert not set(AdversarySketchOutput.model_fields) & {"group_id", "group", "actor_id"}


def test_likelihood_and_confidence_are_separate_fields():
    """Kept apart so the two ICD 203 scales cannot be mixed into one phrase."""
    assert {"likelihood", "confidence"} <= set(AdversarySketchOutput.model_fields)


# --- Verify ------------------------------------------------------------------


def _claims(*labels):
    return [AuditedClaim(claim=f"claim {i}", label=lab) for i, lab in enumerate(labels)]


def test_evidence_quality_is_computed_not_supplied():
    """The audit is where we catch the model being wrong; letting it grade
    itself would add a field it can be wrong in, in exactly that place."""
    assert "evidence_quality" not in VerifyOutput.model_fields
    with pytest.raises(ValidationError):
        VerifyOutput.model_validate({"claims": [], "evidence_quality": "high"})


def test_one_unverified_claim_sinks_the_rating():
    out = VerifyOutput(claims=_claims(*([AuditLabel.OBSERVED] * 20), AuditLabel.UNVERIFIED))
    assert out.evidence_quality is EvidenceQuality.LOW


# --- repeats do not count -----------------------------------------------------
#
# Measured on the 2026-08-12 acceptance run: the independent judge returned 23
# claims of which 15 were distinct, because the three generative states restate
# the same facts and the judge audits them state by state.


def _same(text, label, times=1):
    return [AuditedClaim(claim=text, label=label) for _ in range(times)]


def test_a_repeated_claim_does_not_raise_the_rating():
    """Five copies of one observed claim beside one inferred claim would be 83%
    observed by count, and is 50% by assertion."""
    diluted = VerifyOutput(
        claims=_same("The estate was encrypted.", AuditLabel.OBSERVED, 5)
        + _same("Access was likely bought.", AuditLabel.INFERRED)
    )

    assert len(diluted.claims) == 6, "the audit trail keeps every claim it was given"
    assert len(diluted.distinct_labels) == 2
    assert diluted.evidence_quality is EvidenceQuality.MODERATE


def test_the_worst_label_wins_among_repeats():
    """Otherwise a repeat could launder an unverified claim into a majority of
    observed ones — the same hole, reopened from the other side."""
    conflicted = VerifyOutput(
        claims=_same("The actor was named.", AuditLabel.OBSERVED, 8)
        + _same("The actor was named.", AuditLabel.UNVERIFIED)
    )

    assert conflicted.distinct_labels == {"the actor was named": AuditLabel.UNVERIFIED}
    assert conflicted.evidence_quality is EvidenceQuality.LOW


@pytest.mark.parametrize(
    "variant",
    ["The estate was encrypted.", "the estate was encrypted", "  The   estate was encrypted!  "],
)
def test_case_spacing_and_a_full_stop_do_not_make_a_new_claim(variant):
    out = VerifyOutput(
        claims=_same("The estate was encrypted.", AuditLabel.OBSERVED)
        + _same(variant, AuditLabel.OBSERVED)
    )

    assert len(out.distinct_labels) == 1


def test_genuinely_distinct_claims_are_untouched():
    out = VerifyOutput(claims=_claims(*([AuditLabel.OBSERVED] * 9), AuditLabel.INFERRED))

    assert len(out.distinct_labels) == 10
    assert out.evidence_quality is EvidenceQuality.HIGH


def test_quality_thresholds():
    high = VerifyOutput(claims=_claims(*([AuditLabel.OBSERVED] * 9), AuditLabel.INFERRED))
    assert high.evidence_quality is EvidenceQuality.HIGH

    moderate = VerifyOutput(claims=_claims(*([AuditLabel.OBSERVED] * 3), AuditLabel.INFERRED))
    assert moderate.evidence_quality is EvidenceQuality.MODERATE

    low = VerifyOutput(claims=_claims(AuditLabel.OBSERVED, *([AuditLabel.INFERRED] * 3)))
    assert low.evidence_quality is EvidenceQuality.LOW


def test_no_claims_is_not_high_quality():
    """An empty audit has verified nothing; it must not read as a pass."""
    assert VerifyOutput().evidence_quality is EvidenceQuality.LOW


def test_computed_quality_survives_serialisation():
    out = VerifyOutput(claims=_claims(AuditLabel.OBSERVED, AuditLabel.UNVERIFIED))
    assert out.model_dump()["evidence_quality"] == "low"
