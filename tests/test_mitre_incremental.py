"""Tests for MITRE ATT&CK incremental enrichment."""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import httpx

from pestilentia.clients.mitre_attack import (
    _filter_modified_since,
    _find_unenriched_groups,
    _read_etag_file,
    _write_etag_file,
    check_bundle_freshness,
)

# --- Bundle freshness ---


def test_check_bundle_freshness_unchanged(httpx_mock):
    httpx_mock.add_response(
        url="https://example.com/bundle.json",
        method="HEAD",
        headers={"etag": '"abc123"'},
    )

    changed, etag = check_bundle_freshness(
        url="https://example.com/bundle.json",
        stored_etag='"abc123"',
    )
    assert changed is False
    assert etag == '"abc123"'


def test_check_bundle_freshness_changed(httpx_mock):
    httpx_mock.add_response(
        url="https://example.com/bundle.json",
        method="HEAD",
        headers={"etag": '"def456"'},
    )

    changed, etag = check_bundle_freshness(
        url="https://example.com/bundle.json",
        stored_etag='"abc123"',
    )
    assert changed is True
    assert etag == '"def456"'


def test_check_bundle_freshness_no_stored_etag(httpx_mock):
    httpx_mock.add_response(
        url="https://example.com/bundle.json",
        method="HEAD",
        headers={"etag": '"first"'},
    )

    changed, etag = check_bundle_freshness(
        url="https://example.com/bundle.json",
        stored_etag="",
    )
    assert changed is True
    assert etag == '"first"'


def test_check_bundle_freshness_network_error(httpx_mock):
    # the retry helper attempts the HEAD 3 times before giving up
    for _ in range(3):
        httpx_mock.add_exception(
            httpx.ConnectError("timeout"),
            url="https://example.com/bundle.json",
            method="HEAD",
        )

    changed, etag = check_bundle_freshness(
        url="https://example.com/bundle.json",
        stored_etag='"old"',
    )
    assert changed is True  # assume changed on error
    assert etag == ""


# --- ETag file ---


def test_etag_file_roundtrip(tmp_path):
    from pestilentia.clients import mitre_attack

    original_cache = mitre_attack.CACHE_PATH
    mitre_attack.CACHE_PATH = tmp_path / "data" / "enterprise-attack.json"
    try:
        _write_etag_file('"test-etag-value"')
        assert _read_etag_file() == '"test-etag-value"'
    finally:
        mitre_attack.CACHE_PATH = original_cache


def test_etag_file_missing(tmp_path):
    from pestilentia.clients import mitre_attack

    original_cache = mitre_attack.CACHE_PATH
    mitre_attack.CACHE_PATH = tmp_path / "nonexistent" / "bundle.json"
    try:
        assert _read_etag_file() == ""
    finally:
        mitre_attack.CACHE_PATH = original_cache


# --- Filter modified since ---


def test_filter_modified_since_keeps_recent():
    mitre_groups = [
        {"stix_id": "intrusion-set--1", "name": "GroupA"},
        {"stix_id": "intrusion-set--2", "name": "GroupB"},
    ]
    bundle = {
        "objects": [
            {"id": "intrusion-set--1", "type": "intrusion-set", "modified": "2026-04-01T00:00:00Z"},
            {"id": "intrusion-set--2", "type": "intrusion-set", "modified": "2026-01-01T00:00:00Z"},
        ],
    }
    since = datetime(2026, 3, 1, tzinfo=UTC)

    filtered = _filter_modified_since(mitre_groups, bundle, since)
    assert len(filtered) == 1
    assert filtered[0]["name"] == "GroupA"


def test_filter_modified_since_keeps_all_when_no_modified():
    mitre_groups = [{"stix_id": "intrusion-set--1", "name": "GroupA"}]
    bundle = {"objects": [{"id": "intrusion-set--1", "type": "intrusion-set"}]}
    since = datetime(2026, 3, 1, tzinfo=UTC)

    filtered = _filter_modified_since(mitre_groups, bundle, since)
    assert len(filtered) == 1


def test_filter_modified_since_handles_naive_since():
    # PostgreSQL returns naive datetimes; comparison with tz-aware STIX dates
    # must not raise (regression for BL-04).
    mitre_groups = [
        {"stix_id": "intrusion-set--1", "name": "GroupA"},
        {"stix_id": "intrusion-set--2", "name": "GroupB"},
    ]
    bundle = {
        "objects": [
            {"id": "intrusion-set--1", "type": "intrusion-set", "modified": "2026-04-01T00:00:00Z"},
            {"id": "intrusion-set--2", "type": "intrusion-set", "modified": "2026-01-01T00:00:00Z"},
        ],
    }
    since = datetime(2026, 3, 1)  # naive, as read from a PostgreSQL DateTime column

    filtered = _filter_modified_since(mitre_groups, bundle, since)
    assert [g["name"] for g in filtered] == ["GroupA"]


# --- Find unenriched groups ---


def test_find_unenriched_groups():
    session = MagicMock()

    # Simulate: group_id=1 has TTPs, group_id=2 does not
    session.query.return_value.distinct.return_value.all.return_value = [(1,)]

    group1 = MagicMock()
    group1.id = 1
    group2 = MagicMock()
    group2.id = 2

    session.query.return_value.all.return_value = [group1, group2]

    # Patch to handle the two different query calls
    call_count = 0

    def side_effect(*args):
        nonlocal call_count
        call_count += 1
        result = MagicMock()
        if call_count == 1:
            # GroupTTP query
            result.distinct.return_value.all.return_value = [(1,)]
        else:
            # Group query
            result.all.return_value = [group1, group2]
        return result

    session.query.side_effect = side_effect

    unenriched = _find_unenriched_groups(session)
    assert len(unenriched) == 1
    assert unenriched[0].id == 2
