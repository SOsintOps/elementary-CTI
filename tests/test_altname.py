"""Tests for altname merge into group aliases."""

import json

from pestilentia.pipeline.ingest import _merge_altname


def test_merge_altname_into_empty():
    result = _merge_altname(None, "BlackCat")
    assert json.loads(result) == ["BlackCat"]


def test_merge_altname_into_existing():
    existing = json.dumps(["ALPHV", "GOLD BLAZER"])
    result = _merge_altname(existing, "BlackCat")
    assert json.loads(result) == ["ALPHV", "GOLD BLAZER", "BlackCat"]


def test_merge_altname_no_duplicate_case_insensitive():
    existing = json.dumps(["BlackCat", "ALPHV"])
    result = _merge_altname(existing, "blackcat")
    assert json.loads(result) == ["BlackCat", "ALPHV"]


def test_merge_altname_empty_string_noop():
    existing = json.dumps(["ALPHV"])
    result = _merge_altname(existing, "")
    assert result == existing


def test_merge_altname_none_aliases_none_altname():
    result = _merge_altname(None, "")
    assert result is None


def test_merge_altname_corrupted_json():
    result = _merge_altname("not-json", "NewAlias")
    assert json.loads(result) == ["NewAlias"]
