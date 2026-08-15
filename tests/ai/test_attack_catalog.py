"""ATT&CK catalogue: what it vouches for, and what it must refuse.

The fixture is synthetic so the suite needs no network and no 35 MB bundle,
but its shape is copied from the real enterprise-attack data verified on
2026-08-12 — including the revocation chain, which is the case a single-hop
lookup gets wrong.
"""

import json

import pytest

from pestilentia.ai.extraction.attack_catalog import AttackCatalog


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
def bundle():
    return {
        "objects": [
            _pattern("ap--live1", "T1486", "Data Encrypted for Impact", tactics=["impact"]),
            _pattern(
                "ap--live2",
                "T1647",
                "Plist File Modification",
                tactics=["defense-evasion", "persistence"],
            ),
            # Chain: T1150 -> T1547.011 -> T1647, both intermediates revoked.
            _pattern("ap--rev1", "T1150", "Plist Modification", revoked=True),
            _pattern("ap--rev2", "T1547.011", "Plist Modification", revoked=True),
            # Deprecated with no successor — the real bundle has twelve.
            _pattern("ap--dep1", "T1064", "Scripting", deprecated=True),
            # A revoked-by between non-techniques must be ignored, not crash.
            {"type": "intrusion-set", "id": "is--a", "name": "GroupA"},
            {"type": "intrusion-set", "id": "is--b", "name": "GroupB"},
            _revoked_by("ap--rev1", "ap--rev2"),
            _revoked_by("ap--rev2", "ap--live2"),
            _revoked_by("is--a", "is--b"),
        ]
    }


@pytest.fixture
def catalog(bundle):
    return AttackCatalog.from_bundle(bundle)


def test_live_technique_resolves_to_itself(catalog):
    hit = catalog.resolve("T1486")
    assert hit is not None
    assert hit.technique_id == "T1486"
    assert hit.name == "Data Encrypted for Impact"
    assert ("TA0040", "Impact") in hit.tactics


def test_revocation_chain_lands_on_the_live_technique(catalog):
    """T1150 -> T1547.011 -> T1647: a single hop would return a revoked id."""
    hit = catalog.resolve("T1150")
    assert hit is not None and hit.technique_id == "T1647"
    assert catalog.resolve("T1547.011").technique_id == "T1647"


def test_deprecated_without_successor_is_refused(catalog):
    assert catalog.resolve("T1064") is None


def test_invented_technique_is_refused(catalog):
    assert catalog.resolve("T9999") is None
    assert catalog.resolve("not-a-technique") is None


@pytest.mark.parametrize("value", [None, "", "   "])
def test_empty_input_is_refused(catalog, value):
    assert catalog.resolve(value) is None


@pytest.mark.parametrize("value", ["t1486", " T1486 ", "t1486\n"])
def test_lookup_tolerates_model_formatting(catalog, value):
    """Models emit lowercase and stray whitespace; that is not a wrong answer."""
    assert catalog.resolve(value).technique_id == "T1486"


def test_revoked_entries_are_not_offered_as_live(catalog):
    assert "T1486" in catalog
    assert len(catalog) == 2, "only live techniques are catalogued"


def test_cycle_fails_closed_instead_of_hanging():
    cyclic = {
        "objects": [
            _pattern("ap--x", "T1000", "X", revoked=True),
            _pattern("ap--y", "T2000", "Y", revoked=True),
            _revoked_by("ap--x", "ap--y"),
            _revoked_by("ap--y", "ap--x"),
        ]
    }
    assert AttackCatalog.from_bundle(cyclic).resolve("T1000") is None


def test_missing_bundle_raises_instead_of_vouching_for_nothing(tmp_path):
    """An empty catalogue would reject every mapping and read as a model
    failure; the caller must be told the bundle is absent."""
    with pytest.raises(FileNotFoundError, match="not cached"):
        AttackCatalog.load(tmp_path / "absent.json")


def test_load_reads_a_cached_bundle(tmp_path, bundle):
    path = tmp_path / "enterprise-attack.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert AttackCatalog.load(path).resolve("T1150").technique_id == "T1647"
