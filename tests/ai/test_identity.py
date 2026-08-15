# "I never guess. It is a shocking habit." — Sherlock Holmes
"""The offline resolver, tested on the names the corpus actually produced.

Every fixture below is a real name from a real sketch, and the two failures the
module exists to avoid were both found by measuring rather than by imagining:
one threshold merged two adversaries, and the same threshold failed to join one
adversary to itself.
"""

import pytest

from pestilentia.ai.enrichment.identity import (
    IdentityCatalog,
    NameKind,
    designator_authority,
    naming_scheme,
)

BUNDLE = {
    "objects": [
        {
            "type": "intrusion-set",
            "name": "Sandworm Team",
            "aliases": ["Sandworm Team", "ELECTRUM", "Telebots", "IRON VIKING", "APT44"],
        },
        {
            "type": "intrusion-set",
            "name": "VOID MANTICORE",
            "aliases": ["VOID MANTICORE", "COBALT MYSTIQUE", "Handala Hack", "Karma"],
        },
        {
            "type": "intrusion-set",
            "name": "Winter Vivern",
            "aliases": ["Winter Vivern", "UAC-0114"],
        },
        {"type": "intrusion-set", "name": "APT29", "aliases": ["APT29", "Midnight Blizzard"]},
        {
            "type": "intrusion-set",
            "name": "Lazarus Group",
            "aliases": ["Lazarus Group", "HIDDEN COBRA"],
        },
        {
            "type": "intrusion-set",
            "name": "Revoked Set",
            "aliases": ["Revoked Set"],
            "revoked": True,
        },
        {"type": "malware", "name": "Amadey"},
        {"type": "tool", "name": "PsExec"},
    ]
}


@pytest.fixture
def catalog():
    return IdentityCatalog.from_bundle(BUNDLE)


# --- the two trap cases, both measured on the corpus --------------------------


def test_two_designators_one_digit_apart_are_two_adversaries(catalog):
    """The trap fuzzy matching walks into.

    `UAC-0145` sits within the project's usual 85 threshold of `UAC-0114`, and
    `UAC-0114` is Winter Vivern. For a designator the digits are the identity,
    so tolerating a wrong one merges two actors — the single mistake here that
    nothing downstream can see.
    """
    resolution = catalog.resolve("UAC-0145")

    assert resolution.kind is NameKind.CLUSTER_DESIGNATOR
    assert not resolution.is_alias_of("UAC-0114")
    assert catalog.resolve("UAC-0114").kind is NameKind.KNOWN_ACTOR, "this one is named"


@pytest.mark.parametrize(
    ("written", "canonical"),
    [("Sandworm", "Sandworm Team"), ("Lazarus", "Lazarus Group")],
)
def test_a_dropped_generic_word_is_not_a_different_actor(catalog, written, canonical):
    """The opposite trap, and the reason no single threshold fixes both.

    The extra word costs more similarity than a wrong digit does, so a threshold
    loose enough to join these is loose enough to merge the pair above.
    """
    assert catalog.resolve(written).canonical == canonical


def test_the_alias_the_faulty_gate_guessed_is_one_an_authority_states(catalog):
    """The proposal that started this: `Handala Hack Team` against `karma`.

    It was right, and it was still a defect, because it was asserted with
    nothing behind it. A lucky guess and a checked fact are written the same way
    in the database, which is the whole reason this module exists.
    """
    resolution = catalog.resolve("Handala Hack Team")

    assert resolution.is_alias_of("Karma")
    assert resolution.authority == "mitre-attack"
    assert "VOID MANTICORE" in resolution.evidence


# --- what a name is, when it is not an actor ---------------------------------


def test_a_name_the_bundle_holds_as_malware_is_not_an_actor(catalog):
    """Reports name an intrusion after its malware, and the sketch follows."""
    resolution = catalog.resolve("Amadey")

    assert resolution.kind is NameKind.MALWARE
    assert not resolution.resolved, "classified is not the same as identified"


def test_a_tool_is_told_apart_from_the_hands_that_ran_it(catalog):
    assert catalog.resolve("PsExec").kind is NameKind.TOOL


@pytest.mark.parametrize(
    ("designator", "authority"),
    [
        ("Storm-2372", "Microsoft"),
        ("UAT-11795", "Cisco Talos"),
        ("UNC2165", "Mandiant"),
        ("TA505", "Proofpoint"),
    ],
)
def test_a_cluster_number_names_the_authority_that_coined_it(designator, authority):
    """Knowing whose scheme it is turns a dead end into an open question."""
    assert designator_authority(designator) == authority


def test_a_designator_an_authority_has_adopted_is_read_as_the_name_it_is(catalog):
    """`APT29` is shaped like a designator and is what its actor is called.

    Order decides this: classifying by shape before looking it up would discard
    the answer while holding it.
    """
    resolution = catalog.resolve("APT29")

    assert resolution.kind is NameKind.KNOWN_ACTOR
    assert resolution.is_alias_of("Midnight Blizzard")


def test_a_name_nothing_on_disk_knows_says_so_rather_than_reaching(catalog):
    """`MOIS` is a ministry, and no amount of local data makes it an actor.

    Unknown is the answer that earns the cost of looking further afield, so it
    has to be given honestly rather than approximated to the nearest match.
    """
    resolution = catalog.resolve("MOIS")

    assert resolution.kind is NameKind.UNKNOWN
    assert resolution.canonical == ""


def test_a_revoked_set_is_not_an_authority_for_anything(catalog):
    assert catalog.resolve("Revoked Set").kind is NameKind.UNKNOWN


def test_an_empty_name_resolves_to_nothing_rather_than_raising(catalog):
    assert catalog.resolve("   ").kind is NameKind.UNKNOWN


# --- the module makes no promises it cannot keep -----------------------------


def test_resolution_is_never_an_alias_of_something_it_did_not_resolve(catalog):
    """A classification is not an identity, and must not be readable as one."""
    assert not catalog.resolve("Amadey").is_alias_of("Sandworm Team")
    assert not catalog.resolve("Storm-2372").is_alias_of("Sandworm Team")


# --- whose alphabet the name is written in -----------------------------------


@pytest.mark.parametrize(
    ("name", "vendor", "encodes"),
    [
        ("Fox Tempest", "Microsoft", "financially motivated"),
        ("Lunar Spider", "CrowdStrike", "financially motivated"),
        ("Volt Typhoon", "Microsoft", "China"),
        ("Vanguard Panda", "CrowdStrike", "China"),
        ("GOLD PRELUDE", "Secureworks", "financially motivated"),
        ("Earth Dahu", "Trend Micro", "unstated"),
    ],
)
def test_a_name_carries_the_house_that_coined_it(name, vendor, encodes):
    """Two parallel alphabets over one axis, measured on the bundle.

    The only family pairs that ever share an actor are one animal and one
    weather — Bear+Blizzard, Panda+Typhoon, Spider+Tempest — because each house
    gives an actor exactly one name. That is why a name is never an identity.
    """
    scheme = naming_scheme(name)

    assert scheme is not None
    assert (scheme.vendor, scheme.encodes) == (vendor, encodes)


def test_a_recognised_alphabet_is_a_classification_and_not_an_identification(catalog):
    """`Fox Tempest` is in no catalogue here. Knowing Microsoft named it, and
    what their word means, is most of what a reader wanted — and it is still not
    an answer to who it is."""
    resolution = catalog.resolve("Fox Tempest")

    assert resolution.kind is NameKind.VENDOR_NAMED
    assert resolution.authority == "Microsoft"
    assert not resolution.resolved, "named by a house is not the same as identified"
    assert resolution.canonical == ""


def test_a_catalogued_actor_is_identified_rather_than_merely_placed(catalog):
    """Order again: the catalogue answers before the alphabet does, or an actor
    we hold would be reported as a stranger with a nice hat."""
    assert catalog.resolve("Sandworm").kind is NameKind.KNOWN_ACTOR


def test_a_single_word_name_belongs_to_no_alphabet():
    assert naming_scheme("Gunra") is None


@pytest.mark.parametrize(
    ("name", "encodes"),
    [
        ("Amethyst Rain", "Lebanon"),
        ("Canvas Cyclone", "Vietnam"),
        ("Blue Tsunami", "private sector offensive actor"),
        ("Zigzag Hail", "South Korea"),
    ],
)
def test_the_families_that_were_got_wrong_from_memory(name, encodes):
    """Four entries written from recollection, three of them wrong.

    `rain` was read as South Korea and is Lebanon; `cyclone` as the
    offensive-industry category and is Vietnam; that category is `tsunami`,
    which had been left out altogether. All three were among the entries not
    derived from the bundle, and the ones that were derived all held. Kept as a
    test because the lesson is not about weather words: a table half measured
    and half remembered looks uniform from the outside.
    """
    scheme = naming_scheme(name)

    assert scheme is not None
    assert scheme.encodes == encodes


def test_a_typographic_dash_is_not_a_different_company(catalog):
    """`I-SOON` arrived from an article written with U+2011 and missed the
    catalogue over one invisible character. Which dash was typed is not
    identity, exactly as which quotation mark was typed is not."""
    # The odd character is the point of the test, so it stays as typed.
    with_nbhyphen = "Sandworm‑Team"  # noqa: RUF001

    assert catalog.resolve(with_nbhyphen).canonical == "Sandworm Team"


def test_squashing_separators_cannot_merge_two_designators(catalog):
    """The tolerance is safe here rather than dangerous: what tells UAC-0145
    from UAC-0114 apart was never the hyphen."""
    assert catalog.resolve("UAC-0145").kind is NameKind.CLUSTER_DESIGNATOR
    assert catalog.resolve("UAC0114").canonical == "Winter Vivern"


# --- the curated feeds, and where an answer came from ------------------------

GALAXY = {
    "values": [
        {
            "value": "Bearlyfy",
            "meta": {"synonyms": ["Labubu"], "country": "UA"},
        },
        {
            "value": "Earth Lusca",
            "meta": {"synonyms": ["CHROMIUM", "TAG-22", "FISHMONGER"], "country": "CN"},
        },
    ]
}

MICROSOFT = [
    {
        "Threat actor name": "Forest Blizzard",
        "Origin/Threat": "Russia",
        "Other names": "STRONTIUM, FANCY BEAR, APT28",
    }
]


def test_the_galaxy_knows_two_names_are_one_actor_when_nothing_else_does():
    """The measurement that earned MISP its place in the stack.

    `Labubu` and `Bearlyfy` were two separate unknowns in this corpus. They are
    one actor, and no other source on disk says so.
    """
    catalog = IdentityCatalog.from_misp_galaxy(GALAXY)

    assert catalog.resolve("Labubu").canonical == "Bearlyfy"
    assert catalog.resolve("Labubu").is_alias_of("Bearlyfy")
    assert catalog.resolve("FishMonger").canonical == "Earth Lusca"


def test_an_answer_says_which_house_gave_it():
    """Provenance is not decoration: an alias nobody can trace cannot be revoked
    later, because nothing tells it apart from one that was checked."""
    catalog = IdentityCatalog.from_misp_galaxy(GALAXY)

    assert catalog.resolve("Labubu").authority == "misp-galaxy"
    assert IdentityCatalog.from_microsoft_mapping(MICROSOFT).resolve("STRONTIUM").authority == (
        "microsoft"
    )


def test_a_retired_name_still_reaches_the_actor_it_became():
    """Microsoft's scheme changed in 2023, so an older report and a newer one
    name the same actor with no word in common."""
    catalog = IdentityCatalog.from_microsoft_mapping(MICROSOFT)

    assert catalog.resolve("STRONTIUM").canonical == "Forest Blizzard"


def test_merging_lets_the_first_source_asked_answer(catalog):
    """Where two houses disagree about which names belong together, precedence
    decides and the disagreement is not averaged away: an average of two
    opinions about identity is a third opinion nobody holds."""
    galaxy = IdentityCatalog.from_misp_galaxy(
        {"values": [{"value": "Something Else", "meta": {"synonyms": ["Sandworm"]}}]}
    )

    assert IdentityCatalog.merged(catalog, galaxy).resolve("Sandworm").canonical == "Sandworm Team"
    assert IdentityCatalog.merged(galaxy, catalog).resolve("Sandworm").canonical == "Something Else"
