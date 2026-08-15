# "You have been in Afghanistan, I perceive." — Sherlock Holmes
"""Indicator extraction: what the article contains, and what the model may keep.

The load-bearing test here is `test_a_model_only_indicator_is_dropped`. Every
other case in this file exists to make sure that rule can be enforced without
throwing away real indicators — a pre-pass that misses `1.2.3[.]4` would reject
it later and call the refusal a success.
"""

import pytest

from pestilentia.ai.extraction.iocs import (
    IocType,
    RejectionReason,
    reconcile,
    scan,
)
from pestilentia.ai.schemas import ExtractedIoc, ExtractIocOutput

# A genuine address (the genesis block's) and a genuine bech32 test vector:
# checksums have to pass on real data, not on strings shaped like addresses.
GENESIS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


def _found(body):
    return {(candidate.ioc_type, candidate.value) for candidate in scan(body)}


def _model(*iocs):
    return ExtractIocOutput(
        iocs=[
            ExtractedIoc(
                ioc_type=ioc_type,
                value=value,
                value_as_written=written or value,
                context=context,
            )
            for ioc_type, value, written, context in iocs
        ]
    )


# --- the admissible set ------------------------------------------------------


def test_the_pre_pass_finds_defanged_indicators():
    """If the pre-pass misses these, the anchor step never gets the chance."""
    body = "C2 at 203.0.113[.]7, panel on hxxps://evil[.]com/gate.php, mail support[at]evil[.]com"

    assert (IocType.IPV4, "203.0.113.7") in _found(body)
    assert (IocType.URL, "https://evil.com/gate.php") in _found(body)
    assert (IocType.EMAIL, "support@evil.com") in _found(body)
    assert (IocType.DOMAIN, "evil.com") in _found(body)


def test_an_indicator_at_the_end_of_a_sentence_is_still_found():
    """The commonest position of all, and the first guard refused it.

    `(?![\\d.])` treated the full stop as part of the token, so the pre-pass
    silently missed every address a sentence ended on — and what the pre-pass
    misses is lost for good. The runner's integration test found it; reading
    the pattern had not.
    """
    assert (IocType.IPV4, "203.0.113.7") in _found("The note pointed at 203.0.113[.]7.")
    assert (IocType.DOMAIN, "evil.com") in _found("The panel was on evil[.]com.")


@pytest.mark.parametrize(
    "body",
    [
        "the agent reports version 1.2.3.4.5 on start",
        "built on 10.0.19041.1 exactly",
    ],
)
def test_a_dotted_version_number_is_not_an_address(body):
    """Which is what the trailing guard was there for; it just over-reached."""
    assert not [found for found in _found(body) if found[0] is IocType.IPV4]


def test_a_longer_domain_is_not_the_shorter_one():
    found = _found("hosted on example.com.br only")

    assert (IocType.DOMAIN, "example.com.br") in found
    assert (IocType.DOMAIN, "example.com") not in found


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        (IocType.MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        (IocType.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (
            IocType.SHA256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ],
)
def test_hashes_are_typed_by_length(ioc_type, value):
    assert (ioc_type, value) in _found(f"Sample: {value.upper()} was submitted.")


def test_a_url_keeps_the_case_of_its_path():
    """Paths are case-sensitive; lowercasing one would produce a URL that is
    not the one in the article."""
    body = "Staged at hxxps://Evil[.]com/Gate/Payload.BIN?id=A1"

    assert (IocType.URL, "https://Evil.com/Gate/Payload.BIN?id=A1") in _found(body)


def test_a_build_number_is_not_an_address():
    """`10.0.19041.1` reads as an IPv4 to a naive pattern."""
    assert not [c for c in scan("Windows 10.0.19041.1 hosts") if c.ioc_type is IocType.IPV4]


def test_an_out_of_range_address_is_refused():
    assert not [c for c in scan("version 999.888.777.666 shipped") if c.ioc_type is IocType.IPV4]


def test_an_ipv6_address_is_canonicalised():
    assert (IocType.IPV6, "2001:db8::1") in _found("beacon to 2001:0db8:0000::1 nightly")


def test_a_timestamp_is_not_an_ipv6_address():
    """The pattern matches `12:30:45`; only the validator knows better."""
    assert not [c for c in scan("logged at 12:30:45 UTC") if c.ioc_type is IocType.IPV6]


def test_a_filename_is_not_a_domain():
    body = "Dropped invoice.pdf, then ran setup.exe and loader.dll"

    assert not [c for c in scan(body) if c.ioc_type is IocType.DOMAIN]


def test_an_extension_that_is_also_a_tld_stays_admissible():
    """`.zip` and `.sh` are delegated TLDs. Refusing them here would lose real
    domains for good; the model settles the ambiguity."""
    assert (IocType.DOMAIN, "payload.zip") in _found("hosted at payload.zip today")


def test_bitcoin_addresses_are_checksum_verified():
    body = f"Pay {GENESIS} or {BECH32} within 72 hours."
    found = _found(body)

    assert (IocType.BTC_ADDRESS, GENESIS) in found
    assert (IocType.BTC_ADDRESS, BECH32) in found


def test_a_string_shaped_like_an_address_is_refused():
    """One character off is a different address, and there is no such address."""
    body = f"Pay {GENESIS[:-1]}b within 72 hours."

    assert not [c for c in scan(body) if c.ioc_type is IocType.BTC_ADDRESS]


def test_a_hash_starting_with_a_digit_is_not_a_bitcoin_address():
    """`[13][a-z0-9]{25,34}` matches an MD5 that happens to start with a 1."""
    body = "MD5: 1a2b3c4d5e6f708192a3b4c5d6e7f809"

    assert not [c for c in scan(body) if c.ioc_type is IocType.BTC_ADDRESS]


def test_a_repeated_indicator_is_one_candidate():
    body = "evil.com resolved; evil.com again; evil.com once more."

    assert len([c for c in scan(body) if c.value == "evil.com"]) == 1


def test_a_url_also_yields_its_domain():
    """Deliberate overlap: the model keeps whichever it is reasoning about."""
    found = _found("payload from https://evil.com/a.bin")

    assert (IocType.URL, "https://evil.com/a.bin") in found
    assert (IocType.DOMAIN, "evil.com") in found


# --- the intersection --------------------------------------------------------


def test_a_model_only_indicator_is_dropped():
    """The rule the whole module exists for: plausible is not present."""
    body = "The dropper contacted 203.0.113.7 over port 443."
    result = reconcile(body, _model((IocType.IPV4, "198.51.100.9", "", "C2 server")))

    assert result.kept == ()
    assert [r.reason for r in result.rejected] == [RejectionReason.MODEL_ONLY]
    assert result.rejected[0].value == "198.51.100.9"


def test_an_indicator_present_in_the_article_is_kept_with_its_span():
    body = "The dropper contacted 203.0.113[.]7 over port 443."
    result = reconcile(body, _model((IocType.IPV4, "203.0.113.7", "203.0.113[.]7", "")))

    (kept,) = result.kept
    assert kept.value == "203.0.113.7"
    assert kept.value_defanged == "203.0.113[.]7"
    assert body[kept.span_start : kept.span_end] == "203.0.113[.]7"
    assert result.rejected == ()


def test_the_model_selects_and_does_not_add():
    """Three indicators in the text, one selected: the pre-pass is the ceiling,
    not the output."""
    body = "IOCs: 203.0.113.7, evil.com, and d41d8cd98f00b204e9800998ecf8427e"
    result = reconcile(body, _model((IocType.DOMAIN, "evil.com", "", "")))

    assert [kept.value for kept in result.kept] == ["evil.com"]


def test_the_pattern_decides_the_type_not_the_model():
    """A string's shape is not a matter of opinion."""
    body = "payload from https://evil.com/a.bin"
    result = reconcile(body, _model((IocType.DOMAIN, "https://evil.com/a.bin", "", "")))

    (kept,) = result.kept
    assert kept.ioc_type is IocType.URL


def test_the_same_indicator_twice_is_kept_once():
    body = "The dropper contacted 203.0.113.7 over port 443."
    result = reconcile(
        body,
        _model(
            (IocType.IPV4, "203.0.113.7", "", "first mention"),
            (IocType.IPV4, "203.0.113.7", "", "second mention"),
        ),
    )

    assert len(result.kept) == 1
    assert [r.reason for r in result.rejected] == [RejectionReason.DUPLICATE]


def test_an_ipv6_written_uncompressed_still_matches():
    """The model echoes the article's spelling; `ipaddress` canonicalises ours."""
    body = "beacon to 2001:0db8:0000::1 nightly"
    result = reconcile(body, _model((IocType.IPV6, "2001:0db8:0000::1", "", "")))

    (kept,) = result.kept
    assert kept.value == "2001:db8::1"


# --- context -----------------------------------------------------------------


def test_a_context_found_in_the_article_is_kept():
    body = "The dropper contacted 203.0.113.7 over port 443."
    result = reconcile(
        body, _model((IocType.IPV4, "203.0.113.7", "", "The dropper contacted 203.0.113.7"))
    )

    (kept,) = result.kept
    assert kept.context == "The dropper contacted 203.0.113.7"


def test_an_invented_context_falls_back_to_the_surrounding_text():
    """A context we cannot find is a second claim, not evidence."""
    body = "The dropper contacted 203.0.113.7 over port 443."
    result = reconcile(
        body, _model((IocType.IPV4, "203.0.113.7", "", "exfiltrated 4 TB to this host"))
    )

    (kept,) = result.kept
    assert kept.context == body
    assert "exfiltrated" not in kept.context


def test_context_falls_back_when_the_model_offers_none():
    body = "Beacons went to 203.0.113.7 every ninety seconds."
    result = reconcile(body, _model((IocType.IPV4, "203.0.113.7", "", "")))

    (kept,) = result.kept
    assert "203.0.113.7" in kept.context
