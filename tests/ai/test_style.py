# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""The house-style checker, tested against the prose that provoked it.

The two fixtures below are verbatim output from this pipeline, not invented
examples. That matters: a rule written against a made-up sentence tends to
catch the made-up sentence and nothing else, and the point of the checker is to
catch what the system actually produces.

Sources for every rule are in `docs/intelligence-writing-style.md`.
"""

import pytest

from pestilentia.ai.style import (
    MAX_SENTENCE_WORDS,
    Violation,
    check,
    split_sentences,
    tally,
)

# Article 5, the CISA Gunra advisory, narrative_v1, 2026-08-12. Verbatim.
GUNRA_V1 = (
    "The Gunra ransomware variant first appeared in 2025 and expanded to RaaS operations in "
    "2026, with affiliates using a double-extortion model to target organizations across "
    "multiple sectors, including government, critical infrastructure, healthcare, financial "
    "services, and more. The ransomware is based on the Conti ransomware source code and uses "
    "a combination of ChaCha20 and RSA-4096 encryption algorithms. Gunra actors have been "
    "observed exploiting vulnerabilities in FortiGate firewall and SSL-VPN appliances to gain "
    "initial access to victim networks, and using various techniques such as account "
    "manipulation, external remote services, and credential dumping to move laterally and "
    "maintain persistence."
)

# Article 81, DeadLock, narrative_v1, 2026-08-12. Verbatim.
DEADLOCK_V1 = (
    "The DeadLock ransomware operation, which emerged in mid-2025, uses double-extortion "
    "tactics and has affected 80 organizations in Europe across various sectors. The operation "
    "utilizes a decentralized infrastructure including the Polygon blockchain, Session network, "
    "and Wasabi cloud service. The ransomware employs a unique encryption scheme, avoiding "
    "certain countries, and demands payment in Bitcoin or Monero. Microsoft recommends "
    "strengthening endpoint defenses and restricting unauthorized file changes to defend "
    "against DeadLock ransomware attacks."
)


def _rules(text: str, **kwargs) -> set[str]:
    return {violation.rule for violation in check(text, **kwargs)}


# --- the two real failures, caught whole -------------------------------------


def test_the_gunra_summary_fails_on_every_count_it_was_read_as_failing():
    """Four defects were identified by hand before the checker existed. If the
    checker finds fewer, it is the checker that is wrong."""
    rules = _rules(GUNRA_V1)

    assert "open_enumeration" in rules, "'and more' closes nothing"
    assert "vague_quantifier" in rules, "'various techniques', 'multiple sectors'"
    assert "sentence_length" in rules, "the opening sentence runs to 78 words"


def test_the_deadlock_summary_fails_on_its_own_four():
    rules = _rules(DEADLOCK_V1, advice_allowed=False)

    assert "absolute" in rules, "'a unique encryption scheme'"
    assert "vague_quantifier" in rules, "'various sectors', 'certain countries'"
    assert "advice_in_summary" in rules, "'Microsoft recommends strengthening...'"


def test_the_offending_words_are_named_not_merely_counted():
    """A count tells you the prompt is wrong; the words tell you how."""
    offenders = {violation.text.lower() for violation in check(GUNRA_V1)}

    assert "and more" in offenders
    assert "various" in offenders


def test_a_violation_points_back_at_its_own_position():
    violation = next(v for v in check(GUNRA_V1) if v.rule == "open_enumeration")

    assert GUNRA_V1[violation.start : violation.end].lower() == "and more"


# --- sentence length ---------------------------------------------------------


def test_a_sentence_within_the_ceiling_passes():
    text = "Gunra affiliates exploited FortiGate SSL-VPN appliances to gain initial access."

    assert check(text) == []


def test_the_ceiling_is_the_ceiling_and_not_a_suggestion():
    long = "word " * (MAX_SENTENCE_WORDS + 1)
    short = "word " * (MAX_SENTENCE_WORDS - 1)

    assert any(v.rule == "sentence_length" for v in check(long.strip() + "."))
    assert not any(v.rule == "sentence_length" for v in check(short.strip() + "."))


def test_an_abbreviation_can_only_make_the_checker_forgiving():
    """The splitter breaks on any full stop, so `U.S.` splits a sentence in two.

    That error makes one long sentence look like two short ones, so it can only
    ever miss a violation, never invent one. A checker whose errors all fall on
    the forgiving side is one whose complaints can be trusted.
    """
    sentences = split_sentences("The U.S. agency published it. A second sentence follows.")

    assert len(sentences) > 2, "the known weakness is present, and it under-reports"


# --- the rules that carry a source -------------------------------------------


@pytest.mark.parametrize(
    "phrase",
    [
        "It remains to be seen whether the operation returns.",
        "Only the future will tell.",
        "It is too early to tell.",
    ],
)
def test_fake_analysis_is_refused_by_name(phrase):
    """The DI manual's own list, and it calls them what they are."""
    assert any(v.rule == "fake_analysis" for v in check(phrase))


def test_a_conditional_without_its_condition_is_flagged():
    """'Conditionals carry little analytic weight without the anchor of a
    limiting condition' (DI manual ch. 9)."""
    assert any(
        v.rule == "bare_conditional" for v in check("Affiliates may pivot to other devices.")
    )


def test_a_conditional_with_its_condition_is_left_alone():
    anchored = "Affiliates may pivot to other edge devices if the FortiGate exposure closes."

    assert not any(v.rule == "bare_conditional" for v in check(anchored))


def test_the_icd_203_scale_is_not_mistaken_for_a_bare_conditional():
    """A likelihood statement is the sanctioned alternative, not a violation."""
    assert check("Gunra affiliates will very likely retain FortiGate access.") == []


def test_an_absolute_under_a_limiting_modifier_says_so_in_the_note():
    violation = next(v for v in check("a somewhat unique scheme") if v.rule == "absolute")

    assert "impossible" in violation.note


def test_hedged_attribution_is_refused_because_the_fence_already_carries_it():
    assert any(v.rule == "hedged_attribution" for v in check("Available evidence indicates it."))


def test_a_reserved_verb_is_told_what_to_use_instead():
    violation = next(
        v for v in check("The outage exacerbated the intrusion.") if v.rule == "reserved_verb"
    )

    assert "worsen" in violation.note


def test_an_em_dash_is_a_violation_like_any_other():
    assert any(v.rule == "em_dash" for v in check("The operator — an affiliate — encrypted."))


# --- what belongs in which field ---------------------------------------------


def test_advice_is_a_violation_in_an_assessment_and_the_point_in_recommendations():
    advice = "Organisations should patch the FortiGate appliance."

    assert any(v.rule == "advice_in_summary" for v in check(advice, advice_allowed=False))
    assert not any(v.rule == "advice_in_summary" for v in check(advice))


# --- the shape of the answer -------------------------------------------------


def test_violations_come_back_in_reading_order():
    violations = check(GUNRA_V1)

    assert violations == sorted(violations, key=lambda v: (v.start, v.rule))


def test_the_tally_is_what_a_before_and_after_is_written_in():
    counts = tally(check(DEADLOCK_V1, advice_allowed=False))

    assert counts["absolute"] >= 1
    assert sum(counts.values()) == len(check(DEADLOCK_V1, advice_allowed=False))


@pytest.mark.parametrize("empty", ["", "   ", "\n"])
def test_nothing_to_check_is_not_a_violation(empty):
    assert check(empty) == []


def test_clean_prose_written_to_the_guide_passes_everything():
    """The standard the prompt block is aiming at, written by hand to prove the
    checker can be satisfied. A checker nothing can pass measures nothing."""
    clean = (
        "Gunra affiliates very likely retain access to unpatched FortiGate SSL-VPN "
        "appliances. The operators licensed a Conti-derived encryptor to affiliates in 2026 "
        "and run a double-extortion leak site. Affiliates gained initial access through "
        "FortiGate and SSL-VPN appliances, then used account manipulation, external remote "
        "services and credential dumping to move laterally. The advisory names government, "
        "critical infrastructure, healthcare and financial services as affected sectors. It "
        "does not establish dwell time or the affiliate count."
    )

    assert check(clean, advice_allowed=False) == []


def test_a_violation_prints_itself_usefully():
    violation = Violation("absolute", "unique", 4, 10, "whole thing or nothing")

    assert "absolute" in str(violation) and "unique" in str(violation)


# --- the three copies of the rules must not drift apart ----------------------


def test_the_prompt_block_carries_every_rule_the_checker_enforces():
    """Three places hold these rules: the guide, the prompt block, the checker.

    The guide is prose and cannot be asserted on. The other two can, and they
    are the pair that matters: a rule the checker punishes but the prompt never
    mentions is a trap, not a standard.
    """
    from pestilentia.ai.prompts.base import HOUSE_STYLE

    block = HOUSE_STYLE.lower()
    for phrase in ("and more", "etc.", "various", "certain", "unique"):
        assert phrase in block, f"{phrase!r} is punished but never asked for"
    for phrase in ("it remains to be seen", "it is too early to tell"):
        assert phrase in block
    for word in ("could", "may", "might", "exacerbate", "decimate"):
        assert word in block
    for phrase in ("advis", "the article", "first appeared"):
        assert phrase in block, f"{phrase!r} names a rule the checker enforces"
    assert "35" in HOUSE_STYLE or "thirty-five" in block, "the sentence ceiling"
    assert "em dash" in block


def test_the_prose_states_actually_carry_the_block():
    """A block nothing imports is a document, not a rule."""
    from pestilentia.ai.prompts import PROMPTS
    from pestilentia.ai.prompts.base import HOUSE_STYLE

    for state in ("narrative", "adversary_sketch"):
        assert HOUSE_STYLE in PROMPTS[state].system, f"{state} was left on the old prose"


def test_the_states_that_emit_no_prose_are_left_alone():
    """Triage returns a verdict and a reason; loading it with paragraph
    structure rules would spend tokens on prose it does not write."""
    from pestilentia.ai.prompts import PROMPTS
    from pestilentia.ai.prompts.base import HOUSE_STYLE

    assert HOUSE_STYLE not in PROMPTS["triage"].system
    assert HOUSE_STYLE not in PROMPTS["extract_ioc"].system


def test_the_prompt_block_is_itself_written_to_the_style_it_teaches():
    """A style block containing an em dash would be teaching one thing and
    doing another, and the model reads the doing."""
    from pestilentia.ai.prompts.base import HOUSE_STYLE

    instructive_examples = ("and more", "etc.", "various", "unique", "exacerbate")
    violations = [
        v
        for v in check(HOUSE_STYLE)
        if v.text.lower() not in instructive_examples and v.rule != "sentence_length"
    ]

    assert [v for v in violations if v.rule == "em_dash"] == []


# --- the three defects the first restyled batch left standing ----------------


def test_attributing_advice_to_someone_else_does_not_stop_it_being_advice():
    """Real miss: "The Ukrainian cyber agency advises restricting corporate
    resource access" sat inside a summary and passed clean, because `advise`
    was not in the marker list. The field boundary is about what the sentence
    does, not about who is credited with doing it."""
    text = "The Ukrainian cyber agency advises restricting corporate resource access."

    assert any(v.rule == "advice_in_summary" for v in check(text, advice_allowed=False))
    assert not any(v.rule == "advice_in_summary" for v in check(text))


def test_a_sentence_about_the_article_is_not_a_sentence_about_the_adversary():
    """A class of defect that appeared *with* the house-style prompt and was
    absent before it. Asking for structure and concision can push a model to
    fill the space with commentary on its source when the article gives it
    nothing else, and it occupies the place the bottom line is owed."""
    text = "The article provides technical details of the activity and mitigation guidance."

    assert any(v.rule == "meta_commentary" for v in check(text))


def test_a_summary_that_opens_on_a_date_breaks_the_umbrella_rule():
    """Both of the first two summaries this system wrote opened on chronology,
    and the prompt block saying otherwise did not stop it. A date covers
    nothing, which is what the first sentence of a paragraph has to do."""
    chronological = "The Gunra ransomware variant first appeared in 2025 and expanded in 2026."
    bottom_line = (
        "Gunra affiliates very likely retain access to unpatched FortiGate appliances. "
        "The operation first appeared in 2025."
    )

    assert any(v.rule == "chronology_first" for v in check(chronological, advice_allowed=False))
    assert not any(v.rule == "chronology_first" for v in check(bottom_line, advice_allowed=False))


def test_a_date_later_in_the_paragraph_is_where_a_date_belongs():
    """The rule is about position, not about dates. Ordering from most to least
    important puts the origin story last, and last is allowed."""
    text = (
        "DeadLock stores its configuration on the Polygon blockchain, which survives a "
        "takedown of conventional infrastructure. The operation emerged in mid-2025."
    )

    assert not any(v.rule == "chronology_first" for v in check(text, advice_allowed=False))


def test_the_chronology_rule_does_not_fire_on_recommendations():
    """A recommendation is not a paragraph with a bottom line to cover, and the
    rule would be noise there."""
    text = "First observed exploitation of the FortiGate flaw should drive patch priority."

    assert not any(v.rule == "chronology_first" for v in check(text))


def test_one_recommendation_counts_once_however_many_markers_match_it():
    """The markers overlap by design; the count must not.

    `advised` exists to catch what `defenders are advised` would miss, and a
    naive pass then scores the same sentence twice. Left alone it gets worse
    with every marker added, because each new phrasing also multiplies the
    phrasings already covered.
    """
    violations = [v for v in check("Defenders are advised to patch.", advice_allowed=False)]

    assert [v.rule for v in violations] == ["advice_in_summary"]
    assert violations[0].text == "Defenders are advised", "the longest match, once"


def test_two_separate_recommendations_still_count_twice():
    text = "Defenders are advised to patch. The vendor recommends an update."

    assert len([v for v in check(text, advice_allowed=False) if v.rule == "advice_in_summary"]) == 2


def test_an_unclosed_list_counts_once_whether_or_not_the_full_stop_is_there():
    """`etc` exists for the writer who leaves the full stop off, and it then
    matches inside `etc.` too. Same defect as the advice markers, other family."""
    violations = [v for v in check("They used various tools, etc.") if v.rule == "open_enumeration"]

    assert [v.text for v in violations] == ["etc."]
