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


def test_lists_are_represented_by_their_first_element():
    assert fingerprint({"tags": ["a", "b", "c"]}) == fingerprint({"tags": ["z"]})


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
    assert problems == ["$.victims: type changed 'int' -> 'str'"]


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


def test_check_sample_roundtrip_against_a_saved_baseline(tmp_path, monkeypatch):
    monkeypatch.setattr(contracts, "BASELINE_DIR", tmp_path)
    save_baseline("demo", fingerprint(RECORD))

    ok = check_sample("demo", {**RECORD, "victims": 999})
    assert ok.ok and ok.status == "alive+match"

    drifted = check_sample("demo", {**RECORD, "victims": "999"})
    assert not drifted.ok and drifted.status == "drift"
    assert drifted.problems == ["$.victims: type changed 'int' -> 'str'"]


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
