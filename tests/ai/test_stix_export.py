"""W17: STIX 2.1 export for adversary profiles.

Filed behind Phase 4 in the plan because indicators need extraction that does
not exist. Groups, techniques and tooling are already a valid STIX story, so
that much ships now.
"""

import json

from pestilentia.ai.reports.stix import TLP_MARKINGS, bundle_to_json, group_to_bundle


class _TTP:
    def __init__(self, tid, name):
        self.technique_id = tid
        self.technique_name = name


class _Tool:
    def __init__(self, name):
        self.tool_name = name


class _Group:
    def __init__(self, name, description=None, aliases=None, ttps=(), tools=()):
        self.group_name = name
        self.description = description
        self.aliases = aliases
        self.ttps = list(ttps)
        self.tools = list(tools)


def _by_type(bundle, t):
    return [o for o in bundle["objects"] if o["type"] == t]


def test_group_becomes_an_intrusion_set_not_a_threat_actor():
    """We track behaviour and tooling, not evidence about the humans."""
    b = group_to_bundle(_Group("lockbit", description="A RaaS crew"))
    assert b["type"] == "bundle"
    sets = _by_type(b, "intrusion-set")
    assert len(sets) == 1 and sets[0]["name"] == "lockbit"
    assert _by_type(b, "threat-actor") == []


def test_ids_are_deterministic_so_re_export_updates_rather_than_duplicates():
    a = group_to_bundle(_Group("akira", ttps=[_TTP("T1486", "Data Encrypted for Impact")]))
    b = group_to_bundle(_Group("akira", ttps=[_TTP("T1486", "Data Encrypted for Impact")]))
    assert [o["id"] for o in a["objects"]] == [o["id"] for o in b["objects"]]
    # Only the envelope id is random.
    assert a["id"] != b["id"]


def test_techniques_and_tools_are_linked_by_uses_relationships():
    b = group_to_bundle(
        _Group(
            "qilin", ttps=[_TTP("T1490", "Inhibit System Recovery")], tools=[_Tool("Cobalt Strike")]
        )
    )
    assert len(_by_type(b, "attack-pattern")) == 1
    assert len(_by_type(b, "tool")) == 1
    rels = _by_type(b, "relationship")
    assert len(rels) == 2
    assert {r["relationship_type"] for r in rels} == {"uses"}
    intrusion = _by_type(b, "intrusion-set")[0]["id"]
    assert all(r["source_ref"] == intrusion for r in rels)


def test_sub_technique_ids_map_to_the_right_attack_url():
    b = group_to_bundle(_Group("x", ttps=[_TTP("T1059.001", "PowerShell")]))
    ref = _by_type(b, "attack-pattern")[0]["external_references"][0]
    assert ref["external_id"] == "T1059.001"
    assert ref["url"].endswith("/techniques/T1059/001/")


def test_null_properties_are_omitted_because_stix_forbids_them():
    b = group_to_bundle(_Group("bare"))
    obj = _by_type(b, "intrusion-set")[0]
    assert "description" not in obj
    assert "aliases" not in obj
    assert all(v is not None for o in b["objects"] for v in o.values())


def test_legacy_scalar_aliases_do_not_iterate_character_by_character():
    b = group_to_bundle(_Group("x", aliases=json.dumps("SoloAlias")))
    assert _by_type(b, "intrusion-set")[0]["aliases"] == ["SoloAlias"]


def test_repeated_technique_appears_once_in_the_bundle():
    b = group_to_bundle(_Group("x", ttps=[_TTP("T1486", "Impact"), _TTP("T1486", "Impact")]))
    assert len(_by_type(b, "attack-pattern")) == 1


def test_tlp_marking_is_the_specification_assigned_id():
    b = group_to_bundle(_Group("x"), tlp="green")
    assert _by_type(b, "intrusion-set")[0]["object_marking_refs"] == [TLP_MARKINGS["green"]]
    # An unknown level fails closed to CLEAR rather than emitting nothing.
    b2 = group_to_bundle(_Group("x"), tlp="nonsense")
    assert _by_type(b2, "intrusion-set")[0]["object_marking_refs"] == [TLP_MARKINGS["clear"]]


def test_bundle_serialises_to_json():
    json.loads(bundle_to_json(group_to_bundle(_Group("x"))))
