# "You see, but you do not observe." — Sherlock Holmes
"""The report's shape, which the sources fix and this module has to hold.

What is tested here is the form, not the words: the order of the parts, what
appears above the first heading, what is refused when a part is missing. The
words are the states' problem and `test_style`'s.
"""

import pytest

from pestilentia.ai.enrichment.identity import IdentityCatalog
from pestilentia.ai.report import build

NARRATIVE = {
    "key_judgement": "Access was bought from a broker.",
    "confidence": "moderate confidence",
    "summary_md": "A logistics operator was encrypted after VPN access.",
    "recommendations_md": "Rotate the VPN credentials.",
}

SKETCH = {
    "cluster_summary": "Buys access, encrypts quickly.",
    "named_actors": [{"name": "Gunra"}, {"name": "Amadey"}, {"name": "Storm-2372"}],
    "likelihood": "likely",
    "false_flag_note": "Nothing in the article suggests deception.",
    "shared_infrastructure_note": "Affiliate and operator are not separable here.",
}

BUNDLE = {
    "objects": [
        {"type": "intrusion-set", "name": "Gunra", "aliases": ["Gunra", "GUNRA GANG"]},
        {"type": "malware", "name": "Amadey"},
    ]
}


@pytest.fixture
def catalog():
    return IdentityCatalog.from_bundle(BUNDLE)


def _report(**kwargs):
    return build(article_title="A logistics operator encrypted", narrative=NARRATIVE, **kwargs)


def test_the_bottom_line_sits_above_every_heading():
    """The sources are explicit that a BLUF states the conclusion rather than
    describing what follows, so nothing may come between it and the top."""
    text = _report(sketch=SKETCH).to_markdown()
    bottom = text.index("**Bottom line.**")

    assert bottom < text.index("## "), "a heading before the bottom line buries it"
    assert "Access was bought from a broker." in text


def test_the_parts_appear_in_the_order_the_form_fixes():
    """Known, then concluded, then what is missing, and only then what to do.

    The order is a judgement about the reader and not a layout preference: a
    recommendation read without the gaps beside it is read as more certain than
    it is.
    """
    text = _report(sketch=SKETCH, source_name="Example Research").to_markdown()
    order = [
        text.index("## What the reporting establishes"),
        text.index("## The adversary"),
        text.index("## Gaps and deception"),
        text.index("## Recommended action"),
        text.index("## Source"),
    ]

    assert order == sorted(order)


def test_a_borrowed_title_is_declared_rather_than_worn():
    """No state produces a title of the report's own. Presenting the
    publisher's as ours is the quiet misattribution this pipeline exists to
    prevent, so it is labelled until we write our own."""
    report = _report(sketch=SKETCH)

    assert not report.title_is_ours
    assert "as published by the source" in report.to_markdown()


def test_an_empty_part_leaves_no_empty_heading():
    """A heading with nothing under it reads as an omission by the analyst
    rather than as an absence in the reporting."""
    text = build(article_title="T", narrative=NARRATIVE, sketch={}).to_markdown()

    assert "## Gaps and deception" not in text
    assert "## What the reporting establishes" in text


def test_a_named_actor_carries_whoever_vouches_for_the_name(catalog):
    """Where the identity work becomes something a reader sees."""
    text = _report(sketch=SKETCH, catalog=catalog).to_markdown()

    assert "**Gunra**" in text
    assert "GUNRA GANG" in text
    assert "mitre-attack" in text


def test_a_name_that_is_malware_is_not_offered_as_an_adversary(catalog):
    text = _report(sketch=SKETCH, catalog=catalog).to_markdown()

    assert "Amadey — malware, not an actor" in text


def test_a_cluster_number_is_reported_as_unnamed_rather_than_as_a_name(catalog):
    text = _report(sketch=SKETCH, catalog=catalog).to_markdown()

    assert "Storm-2372 — a cluster Microsoft has not named" in text


def test_a_name_no_catalogue_knows_says_so(catalog):
    """The reader's next decision depends on whether nothing was found or
    nothing was looked for, and those must not read alike."""
    sketch = {**SKETCH, "named_actors": [{"name": "Toy Ghouls"}]}

    assert "recognised by no catalogue" in _report(sketch=sketch, catalog=catalog).to_markdown()


def test_the_local_database_answers_before_any_outside_catalogue():
    """A name this deployment already tracks has been reasoned about here, and
    an outside catalogue must not quietly rename it."""
    local = IdentityCatalog.from_group_names([("warlock", [])])
    outside = IdentityCatalog.from_bundle(
        {"objects": [{"type": "intrusion-set", "name": "Something Else", "aliases": ["Warlock"]}]}
    )
    merged = IdentityCatalog.merged(local, outside)

    assert merged.resolve("Warlock").canonical == "warlock"
    assert merged.resolve("Warlock").authority == "this database"


def test_the_report_level_is_its_own_and_not_the_attribution_depth():
    """`attribution_level` carries the same three words for a different
    question: how deep the attribution reached, not who the report is for. The
    values coincide and the meanings do not."""
    report = build(article_title="T", narrative=NARRATIVE, sketch=SKETCH, level="tactical")

    assert report.level == "tactical"
    assert "attribution_level" not in report.to_markdown()
