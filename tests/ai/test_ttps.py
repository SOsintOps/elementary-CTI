# "Data! Data! Data! I can't make bricks without clay." — Sherlock Holmes
"""Technique mapping: what the catalogue vouches for, and what the body proves.

The two load-bearing tests are `test_a_technique_the_catalogue_refuses_is_dropped`
and `test_an_evidence_quote_absent_from_the_body_is_dropped`. Everything else is
here so those two refusals can be enforced without throwing away sound mappings —
a revoked id and a quote wrapped across a line break are both correct answers.
"""

import pytest

from pestilentia.ai.extraction.attack_catalog import AttackCatalog
from pestilentia.ai.extraction.ttps import (
    MAX_TTPS,
    RejectionReason,
    reconcile,
)
from pestilentia.ai.schemas import MapTtpOutput, TtpMapping

# Line breaks are the article's own: a model quoting across one writes a single
# line, which is exactly what `find_quote` has to tolerate.
BODY = (
    "Elementary Ransomware Group - incident notes\n\n"
    "Initial access came through valid VPN credentials purchased from a broker.\n"
    "Once inside, the operators encrypted files across the estate and dropped a\n"
    "ransom note in every share. Exfiltration preceded encryption by two days.\n"
)

ENCRYPTION_QUOTE = "the operators encrypted files across the estate"
ACCESS_QUOTE = "valid VPN credentials purchased from a broker"


def _pattern(stix_id, attack_id, name, *, tactics=(), revoked=False, deprecated=False):
    obj = {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": slug} for slug in tactics
        ],
    }
    if revoked:
        obj["revoked"] = True
    if deprecated:
        obj["x_mitre_deprecated"] = True
    return obj


def _revoked_by(source, target):
    return {
        "type": "relationship",
        "relationship_type": "revoked-by",
        "source_ref": source,
        "target_ref": target,
    }


@pytest.fixture
def catalog():
    objects = [
        _pattern("ap--live1", "T1486", "Data Encrypted for Impact", tactics=["impact"]),
        # Four tactics, as Valid Accounts really has: the row can hold one.
        _pattern(
            "ap--live2",
            "T1078",
            "Valid Accounts",
            tactics=["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
        ),
        # Live, with no kill-chain phases the map recognises.
        _pattern("ap--live3", "T1000", "Unphased Technique"),
        # Chain: T1150 -> T1547.011 -> T1647, both intermediates revoked.
        _pattern("ap--live4", "T1647", "Plist File Modification", tactics=["defense-evasion"]),
        _pattern("ap--rev1", "T1150", "Plist Modification", revoked=True),
        _pattern("ap--rev2", "T1547.011", "Plist Modification", revoked=True),
        # Deprecated with no successor — the real bundle has twelve.
        _pattern("ap--dep1", "T1064", "Scripting", deprecated=True),
        _revoked_by("ap--rev1", "ap--rev2"),
        _revoked_by("ap--rev2", "ap--live4"),
    ]
    # Filler, so the cap can be reached with distinct techniques.
    objects += [
        _pattern(f"ap--fill{n}", f"T20{n:02d}", f"Filler {n}", tactics=["impact"])
        for n in range(1, 13)
    ]
    return AttackCatalog.from_bundle({"objects": objects})


def _model(*mappings):
    return MapTtpOutput(
        mappings=[
            TtpMapping(technique_id=technique_id, evidence_quote=quote, confidence=confidence)
            for technique_id, quote, confidence in mappings
        ]
    )


# --- what survives -----------------------------------------------------------


def test_a_sound_mapping_is_kept_with_the_catalogue_naming(catalog):
    result = reconcile(BODY, _model(("T1486", ENCRYPTION_QUOTE, 0.9)), catalog)

    assert result.rejected == ()
    (kept,) = result.kept
    assert kept.technique_id == "T1486"
    assert kept.technique_name == "Data Encrypted for Impact"
    assert (kept.tactic_id, kept.tactic_name) == ("TA0040", "Impact")


def test_the_stored_span_slices_back_to_the_article(catalog):
    """The span is the evidence; if it does not cut the body, nothing does."""
    result = reconcile(BODY, _model(("T1486", ENCRYPTION_QUOTE, 0.7)), catalog)

    (kept,) = result.kept
    assert BODY[kept.evidence_span_start : kept.evidence_span_end] == ENCRYPTION_QUOTE


def test_the_models_confidence_is_carried_through_untouched(catalog):
    """Phase 5 folds this into a composite score, so it must not be rounded."""
    result = reconcile(BODY, _model(("T1486", ENCRYPTION_QUOTE, 0.37)), catalog)

    assert result.kept[0].confidence == 0.37


def test_a_quote_wrapped_across_a_line_break_anchors(catalog):
    """The article goes to a new line where the model writes a space."""
    quote = "dropped a ransom note in every share"
    assert quote not in BODY, "the point of the test is that a plain search fails"

    result = reconcile(BODY, _model(("T1486", quote, 0.5)), catalog)

    assert len(result.kept) == 1


def test_model_formatting_of_the_id_is_not_a_wrong_answer(catalog):
    result = reconcile(BODY, _model((" t1486 ", ENCRYPTION_QUOTE, 0.5)), catalog)

    assert result.kept[0].technique_id == "T1486"


def test_a_revoked_id_is_stored_under_its_live_successor(catalog):
    """`T1150` in a 2019 write-up is a correct observation with a stale name."""
    result = reconcile(BODY, _model(("T1150", ENCRYPTION_QUOTE, 0.6)), catalog)

    (kept,) = result.kept
    assert kept.technique_id == "T1647"
    assert kept.technique_name == "Plist File Modification"


def test_a_multi_tactic_technique_takes_the_first_the_bundle_declares(catalog):
    result = reconcile(BODY, _model(("T1078", ACCESS_QUOTE, 0.8)), catalog)

    assert (result.kept[0].tactic_id, result.kept[0].tactic_name) == ("TA0005", "Defense Evasion")


def test_a_technique_without_kill_chain_phases_is_still_kept(catalog):
    """Missing bundle metadata is not the model's error."""
    result = reconcile(BODY, _model(("T1000", ENCRYPTION_QUOTE, 0.5)), catalog)

    (kept,) = result.kept
    assert kept.technique_id == "T1000"
    assert (kept.tactic_id, kept.tactic_name) == ("", "")


def test_nothing_proposed_is_nothing_kept(catalog):
    result = reconcile(BODY, MapTtpOutput(), catalog)

    assert result.kept == () and result.rejected == ()


# --- what is refused ---------------------------------------------------------


@pytest.mark.parametrize("technique_id", ["T9999", "T1064", "not-a-technique"])
def test_a_technique_the_catalogue_refuses_is_dropped(catalog, technique_id):
    """An invented id, and a deprecated one with no successor, denote nothing."""
    result = reconcile(BODY, _model((technique_id, ENCRYPTION_QUOTE, 0.9)), catalog)

    assert result.kept == ()
    assert result.rejected[0].reason is RejectionReason.UNKNOWN_TECHNIQUE


def test_an_evidence_quote_absent_from_the_body_is_dropped(catalog):
    """A plausible sentence the article never contains is a fabricated citation."""
    invented = "the operators deployed a custom loader over SMB"

    result = reconcile(BODY, _model(("T1486", invented, 0.95)), catalog)

    assert result.kept == ()
    assert result.rejected[0].reason is RejectionReason.UNANCHORED_EVIDENCE


def test_a_fragment_too_short_to_cite_is_not_evidence(catalog):
    """`encrypted` is in the body and proves nothing by being there."""
    assert "encrypted" in BODY

    result = reconcile(BODY, _model(("T1486", "encrypted", 0.9)), catalog)

    assert result.kept == ()
    assert result.rejected[0].reason is RejectionReason.WEAK_EVIDENCE


def test_two_ids_resolving_to_one_technique_are_one_mapping(catalog):
    """`T1150` and `T1647` are the same technique once the chain is followed."""
    result = reconcile(
        BODY,
        _model(("T1647", ENCRYPTION_QUOTE, 0.8), ("T1150", ACCESS_QUOTE, 0.6)),
        catalog,
    )

    assert [kept.technique_id for kept in result.kept] == ["T1647"]
    assert result.rejected[0].reason is RejectionReason.DUPLICATE


def test_a_refusal_names_the_id_the_model_wrote(catalog):
    """The row exists to be traced back to the raw output, which says T1150."""
    result = reconcile(
        BODY,
        _model(("T1647", ENCRYPTION_QUOTE, 0.8), ("T1150", ACCESS_QUOTE, 0.6)),
        catalog,
    )

    assert result.rejected[0].technique_id == "T1150"


def test_the_cap_holds_when_the_schema_is_bypassed(catalog):
    """The ten is the criterion's, not the schema's.

    `MapTtpOutput` already refuses an eleventh at parse time (covered in
    test_schemas), so this constructs the output unvalidated: the cap has to
    survive a caller that hands `reconcile` a list from somewhere else.
    """
    proposed = MapTtpOutput.model_construct(
        mappings=[
            TtpMapping(technique_id=f"T20{n:02d}", evidence_quote=ENCRYPTION_QUOTE, confidence=0.5)
            for n in range(1, 13)
        ]
    )

    result = reconcile(BODY, proposed, catalog)

    assert len(result.kept) == MAX_TTPS
    assert [rejected.technique_id for rejected in result.rejected] == ["T2011", "T2012"]
    assert {rejected.reason for rejected in result.rejected} == {RejectionReason.OVER_CAP}


def test_a_sound_mapping_survives_beside_a_refused_one(catalog):
    """One bad mapping must not take the article's real evidence with it."""
    result = reconcile(
        BODY,
        _model(("T9999", ENCRYPTION_QUOTE, 0.9), ("T1078", ACCESS_QUOTE, 0.8)),
        catalog,
    )

    assert [kept.technique_id for kept in result.kept] == ["T1078"]
    assert len(result.rejected) == 1
