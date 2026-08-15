"""A1: the contract fingerprint — the deterministic heart of the sentinel.

Everything here is offline. The property that matters most: the fingerprint
depends on *structure only*, never on values, key order, or which record was
sampled — otherwise the weekly check would cry wolf and be ignored by week 3.
"""

from __future__ import annotations

import pestilentia.contracts as contracts
from pestilentia.contracts import check_sample, diff_structures, fingerprint, save_baseline

RECORD = {"name": "akira", "victims": 42, "active": True, "tags": ["ransomware"], "notes": None}


def test_values_do_not_matter():
    other = {"name": "lockbit", "victims": 7, "active": False, "tags": ["raas"], "notes": None}
    assert fingerprint(RECORD) == fingerprint(other)


def test_key_order_does_not_matter():
    reordered = dict(reversed(list(RECORD.items())))
    assert fingerprint(RECORD) == fingerprint(reordered)


def test_a_renamed_field_changes_the_fingerprint():
    renamed = {**RECORD}
    renamed["victim_count"] = renamed.pop("victims")
    assert fingerprint(RECORD) != fingerprint(renamed)


def test_a_type_change_changes_the_fingerprint():
    retyped = {**RECORD, "victims": "42"}  # int -> str: the classic silent break
    assert fingerprint(RECORD) != fingerprint(retyped)


def test_a_list_is_represented_by_all_its_elements_merged():
    assert fingerprint({"tags": ["a", "b", "c"]}) == fingerprint({"tags": ["z"]})
    assert fingerprint({"tags": ["a", 1]}) == {"tags": [contracts.VARIES]}


def test_depth_is_capped():
    bomb: dict = {"x": None}
    node = bomb
    for _ in range(50):
        node["x"] = {"x": None}
        node = node["x"]
    assert fingerprint(bomb)  # must terminate, not recurse to death


def test_diff_names_the_removed_field():
    slimmer = {k: v for k, v in RECORD.items() if k != "victims"}
    problems = diff_structures(fingerprint(RECORD), fingerprint(slimmer))
    assert problems == ["$.victims: field removed"]


def test_diff_names_the_type_change():
    retyped = {**RECORD, "victims": "42"}
    problems = diff_structures(fingerprint(RECORD), fingerprint(retyped))
    assert problems == ["$.victims: type changed 'number' -> 'str'"]


def test_a_new_field_is_reported_but_named_as_new():
    grown = {**RECORD, "sector": "healthcare"}
    problems = diff_structures(fingerprint(RECORD), fingerprint(grown))
    assert problems == ["$.sector: new field (type 'str')"]


def test_nullable_fields_do_not_flap():
    """The record sampled this week has notes=None, last week's had a string.
    That is the same contract, not drift."""
    with_value = {**RECORD, "notes": "hit via Citrix"}
    assert diff_structures(fingerprint(RECORD), fingerprint(with_value)) == []
    assert diff_structures(fingerprint(with_value), fingerprint(RECORD)) == []


def test_an_empty_list_this_week_is_not_drift():
    """No recent cyberattacks in the window ⇒ empty sample list. The shape is
    unproven, not changed."""
    assert diff_structures(fingerprint({"items": [RECORD]}), fingerprint({"items": []})) == []


def test_the_empty_string_does_not_flap_against_an_object():
    """The real 2026-08-09 drift. ransomware.live serves `infostealer` as a
    nine-key object for victims it has data on and as "" for the rest, both
    inside one page — so which victim lands at index 0 decides the
    fingerprint. Whichever week captured the baseline, the other week must not
    read as drift."""
    absent = {**RECORD, "infostealer": ""}
    present = {**RECORD, "infostealer": {"users": 3, "employees": 0, "update": "2026-08-12"}}
    assert diff_structures(fingerprint(absent), fingerprint(present)) == []
    assert diff_structures(fingerprint(present), fingerprint(absent)) == []


def test_an_empty_object_does_not_flap_either():
    """`infostealer_stats` is {} on every record today. The week it fills in,
    that is an unpopulated field arriving — not a contract that changed."""
    empty = {**RECORD, "stats": {}}
    filled = {**RECORD, "stats": {"redline": 2}}
    assert diff_structures(fingerprint(empty), fingerprint(filled)) == []
    assert diff_structures(fingerprint(filled), fingerprint(empty)) == []


def test_empty_is_recorded_as_its_own_token_not_as_a_type():
    """`""` must not fingerprint as `str`: that is the claim that caused the
    flap. It also must not be conflated with a genuinely absent value."""
    assert fingerprint({"a": "", "b": [], "c": {}}) == {
        "a": contracts.EMPTY,
        "b": contracts.EMPTY,
        "c": contracts.EMPTY,
    }
    assert contracts.EMPTY != contracts.NULL


def test_zero_and_false_are_values_not_emptiness():
    """Falsy is not empty. There is no such thing as an empty int, so a field
    that turns from int to str is drift even when the sample happened to
    hold 0 — the tolerance must not widen into a silencer."""
    assert fingerprint({"n": 0}) == {"n": "number"}
    assert fingerprint({"n": False}) == {"n": "bool"}
    assert diff_structures(fingerprint({"n": 0}), fingerprint({"n": "0"})) == [
        "$.n: type changed 'number' -> 'str'"
    ]


def test_a_whole_number_and_a_fractional_one_are_the_same_json_type():
    """ransomwhe.re serves amountUSD as a float 21,787 times and as an int 15
    times — the whole-dollar amounts, which JSON writes without a decimal
    point. Python's parser invents that split; JSON has one number type. The
    field the sentinel's own drill named as its silent failure mode must not
    be the one it stops watching."""
    page = [{"amountUSD": 3298.82}, {"amountUSD": 194850}]
    assert fingerprint(page) == [{"amountUSD": contracts.NUMBER}]
    assert diff_structures(fingerprint([{"amountUSD": 1}]), fingerprint([{"amountUSD": 1.5}])) == []
    assert diff_structures(
        fingerprint([{"amountUSD": 1.5}]), fingerprint([{"amountUSD": "1.5"}])
    ) == ["$[0].amountUSD: type changed 'number' -> 'str'"]


def test_a_bool_is_not_a_number_despite_python():
    """isinstance(True, int) is True, so the numeric test must come second or
    every boolean field silently becomes numeric."""
    assert fingerprint({"flag": True}) == {"flag": "bool"}
    assert diff_structures(fingerprint({"flag": True}), fingerprint({"flag": 1})) == [
        "$.flag: type changed 'bool' -> 'number'"
    ]


def test_a_type_change_between_two_non_empty_values_is_still_drift():
    """The point of the sentinel, restated after widening the tolerance."""
    populated = {**RECORD, "infostealer": {"users": 3}}
    renamed_shape = {**RECORD, "infostealer": ["users"]}
    assert diff_structures(fingerprint(populated), fingerprint(renamed_shape)) == [
        "$.infostealer: type changed {'users': 'number'} -> ['str']"
    ]


def test_a_field_typed_two_ways_upstream_is_marked_unverifiable():
    """The second real drift. recentcyberattacks returns `claim_gang` as False
    on the victims with no claim and as a gang name on the rest, interleaved in
    one page. Neither is the contract; the honest fingerprint says so."""
    page = [
        {"victim": "acme", "claim_gang": False},
        {"victim": "globex", "claim_gang": "qilin"},
    ]
    assert fingerprint(page) == [{"victim": "str", "claim_gang": contracts.VARIES}]


def test_varies_does_not_flap_whichever_records_the_page_holds():
    """The property the whole change exists for: what a page contains may
    shift, what the fingerprint says must not."""
    mixed = fingerprint([{"claim": False}, {"claim": "qilin"}])
    all_bool = fingerprint([{"claim": False}, {"claim": False}])
    all_str = fingerprint([{"claim": "qilin"}, {"claim": "akira"}])
    for observed in (all_bool, all_str, mixed):
        assert diff_structures(mixed, observed) == []
        assert diff_structures(observed, mixed) == []


def test_a_consistent_field_stays_checked_even_when_its_value_is_falsy():
    """The line the tolerance must not cross. `employees` is 0 on every record
    and `has_infostealer_info` is False on 38% of them — both are consistently
    typed, so both keep their contract."""
    page = [
        {"employees": 0, "has_infostealer_info": False},
        {"employees": 0, "has_infostealer_info": True},
    ]
    assert fingerprint(page) == [{"employees": "number", "has_infostealer_info": "bool"}]
    retyped = fingerprint([{"employees": "0", "has_infostealer_info": False}])
    assert diff_structures(fingerprint(page), retyped) == [
        "$[0].employees: type changed 'number' -> 'str'"
    ]


def test_merging_prefers_the_record_that_saw_something():
    """A page where the first victim has no infostealer data and the second
    does must yield the shape, not the absence."""
    page = [{"infostealer": ""}, {"infostealer": {"users": 3}}]
    assert fingerprint(page) == [{"infostealer": {"users": "number"}}]


def test_a_key_present_in_only_some_records_is_still_part_of_the_contract():
    merged = fingerprint([{"a": "x"}, {"a": "y", "b": 1}])
    assert merged == [{"a": "str", "b": "number"}]


def test_merge_is_order_independent():
    """Whatever order the server returns its rows in, the contract is one."""
    records = [{"claim": False}, {"claim": "qilin"}, {"claim": ""}]
    assert fingerprint(records) == fingerprint(list(reversed(records)))


def test_a_conflict_survives_later_agreement():
    """Once two shapes have been seen, a third record agreeing with one of them
    does not restore a contract that upstream does not honour."""
    assert contracts.merge_fingerprints(contracts.VARIES, "str") == contracts.VARIES
    assert contracts.merge_fingerprints("str", contracts.VARIES) == contracts.VARIES


def test_a_dict_keyed_by_data_is_recorded_as_a_map():
    """`infostealer_stats` counts sightings per infostealer family, so its keys
    are family names — six distinct key sets across one live page. Pinning them
    would report the next new family as drift."""
    page = [
        {"stats": {"Lumma": 3, "Vidar": 1}},
        {"stats": {"RedLine": 2}},
    ]
    assert fingerprint(page) == [{"stats": {contracts.MAP_KEY: "number"}}]


def test_a_new_key_in_a_map_is_not_drift_but_a_retyped_value_is():
    """The whole point of the distinction: names unconstrained, types checked."""
    baseline = fingerprint([{"stats": {"Lumma": 3}}, {"stats": {"Vidar": 1}}])
    grown = fingerprint([{"stats": {"Lumma": 3, "Remus": 1}}, {"stats": {"Acreed": 2}}])
    assert diff_structures(baseline, grown) == []

    retyped = fingerprint([{"stats": {"Lumma": "3"}}, {"stats": {"Vidar": "1"}}])
    assert diff_structures(baseline, retyped) == ["$[0].stats.*: type changed 'number' -> 'str'"]


def test_a_record_with_an_optional_field_is_not_mistaken_for_a_map():
    """Records have differing keys too when a field is optional. What separates
    them from maps is that their values are a mix of types."""
    page = [{"name": "akira", "victims": 3}, {"name": "qilin"}]
    assert fingerprint(page) == [{"name": "str", "victims": "number"}]


def test_a_map_stays_a_map_once_seen():
    """A later record that conflicts does not restore the field names."""
    merged = contracts.merge_fingerprints({contracts.MAP_KEY: "number"}, {"Lumma": "str"})
    assert merged == {contracts.MAP_KEY: contracts.VARIES}


def test_a_legacy_baseline_with_an_empty_list_still_reads_as_unobserved():
    """Baselines committed before EMPTY existed hold `[]` for a field that is
    now fingerprinted as "empty". A checkout that has not re-baselined yet must
    read that as "never observed", not go red on its first run."""
    assert diff_structures({"tools": []}, fingerprint({"tools": ["mimikatz"]})) == []


def test_check_sample_roundtrip_against_a_saved_baseline(tmp_path, monkeypatch):
    monkeypatch.setattr(contracts, "BASELINE_DIR", tmp_path)
    save_baseline("demo", fingerprint(RECORD))

    ok = check_sample("demo", {**RECORD, "victims": 999})
    assert ok.ok and ok.status == "alive+match"

    drifted = check_sample("demo", {**RECORD, "victims": "999"})
    assert not drifted.ok and drifted.status == "drift"
    assert drifted.problems == ["$.victims: type changed 'number' -> 'str'"]


def test_a_missing_baseline_is_its_own_status_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(contracts, "BASELINE_DIR", tmp_path)
    result = check_sample("never-captured", RECORD)
    assert not result.ok
    assert result.status == "no-baseline"
    assert "--update" in result.problems[0]


def test_a_429_is_retried_once_then_classified_as_rate_limited(httpx_mock):
    """A3b, found in the drill: back-to-back probes drew a 429, and the
    detector reported it as 'unreachable' — which reads as an outage and would
    have sent the analyst chasing the wrong failure. A 429 is its own thing."""
    import httpx
    from scripts.api_sentinel import RateLimitedError, _fetch_json

    url = "https://api.example/x"
    httpx_mock.add_response(url=url, status_code=429, headers={"Retry-After": "0"})
    httpx_mock.add_response(url=url, status_code=429, headers={"Retry-After": "0"})
    with httpx.Client() as client:
        try:
            _fetch_json(client, url)
            raise AssertionError("expected RateLimitedError")
        except RateLimitedError:
            pass


def test_a_429_that_clears_on_retry_succeeds(httpx_mock):
    import httpx
    from scripts.api_sentinel import _fetch_json

    url = "https://api.example/y"
    httpx_mock.add_response(url=url, status_code=429, headers={"Retry-After": "0"})
    httpx_mock.add_response(url=url, status_code=200, json={"ok": True})
    with httpx.Client() as client:
        assert _fetch_json(client, url) == {"ok": True}
