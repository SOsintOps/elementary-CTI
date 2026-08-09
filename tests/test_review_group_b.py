"""Regression tests for review findings "Group B": ME-02, HI-03, ME-03, HI-09."""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.clients import mitre_attack
from pestilentia.clients.deepdarkcti import _safe_add_comm
from pestilentia.clients.mitre_attack import _merge_aliases, _safe_add, download_stix_bundle
from pestilentia.clients.ransomwhere import _safe_add_tx
from pestilentia.matching import (
    TARGET_HWM_CATEGORY,
    VICTIM_HWM_CATEGORY,
    fuzzy_match_watchlist,
)
from pestilentia.models import Alert, Group, GroupTool, InfoUpdate, Victim, Watchlist
from pestilentia.models.base import Base


def _setup_db() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


# --- ME-02: _safe_add must close the savepoint on non-IntegrityError ---


class _SavepointStub:
    def __init__(self):
        self.committed = False
        self.rolled_back = False

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class _SessionStub:
    def __init__(self, exc: Exception):
        self._exc = exc
        self.sp = _SavepointStub()

    def begin_nested(self):
        return self.sp

    def add(self, obj):
        raise self._exc


@pytest.mark.parametrize("safe_add", [_safe_add, _safe_add_tx, _safe_add_comm])
def test_safe_add_rolls_back_savepoint_on_unexpected_error(safe_add):
    session = _SessionStub(RuntimeError("connection lost"))
    with pytest.raises(RuntimeError, match="connection lost"):
        safe_add(session, object())
    assert session.sp.rolled_back
    assert not session.sp.committed


def test_safe_add_failure_does_not_poison_outer_transaction():
    factory = _setup_db()
    with factory() as session:
        group = Group(group_name="testgroup")
        session.add(group)
        session.flush()

        # Unbindable parameter -> non-IntegrityError raised at savepoint flush
        bad = GroupTool(group_id=group.id, category="x", tool_name=object())
        with pytest.raises(Exception) as excinfo:
            _safe_add(session, bad)
        assert "IntegrityError" not in type(excinfo.value).__name__

        # The outer transaction must still be usable after the failure
        good = GroupTool(group_id=group.id, category="x", tool_name="cobalt strike")
        assert _safe_add(session, good) is True
        session.commit()
        assert session.query(GroupTool).count() == 1


# --- HI-03: download_stix_bundle must bypass the cache on force=True ---


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload
        self.content = json.dumps(payload).encode()

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_download_stix_bundle_uses_cache_by_default(tmp_path, monkeypatch):
    cache = tmp_path / "bundle.json"
    cache.write_text(json.dumps({"objects": ["cached"]}))
    monkeypatch.setattr(mitre_attack, "CACHE_PATH", cache)

    def _no_network(*a, **kw):
        raise AssertionError("network hit despite warm cache")

    monkeypatch.setattr(mitre_attack, "get_with_retry", _no_network)
    assert download_stix_bundle()["objects"] == ["cached"]


def test_download_stix_bundle_force_bypasses_cache(tmp_path, monkeypatch):
    cache = tmp_path / "bundle.json"
    cache.write_text(json.dumps({"objects": ["stale"]}))
    monkeypatch.setattr(mitre_attack, "CACHE_PATH", cache)
    monkeypatch.setattr(
        mitre_attack,
        "get_with_retry",
        lambda *a, **kw: _FakeResponse({"objects": ["fresh"]}),
    )

    assert download_stix_bundle(force=True)["objects"] == ["fresh"]
    # Cache refreshed for subsequent cached reads
    assert json.loads(cache.read_text())["objects"] == ["fresh"]


# --- ME-03: MITRE aliases merge with ingested ones instead of overwriting ---


def test_merge_aliases_preserves_ingested_aliases():
    pg = Group(group_name="alphv", aliases=json.dumps(["BlackCat"]))
    merged = _merge_aliases(pg, ["ALPHV", "Noberus"])
    assert "BlackCat" in merged
    assert "Noberus" in merged


def test_merge_aliases_excludes_own_name_case_insensitively():
    pg = Group(group_name="alphv", aliases=None)
    merged = _merge_aliases(pg, ["ALPHV", "BlackCat"])
    assert merged == ["BlackCat"]


def test_merge_aliases_dedups_case_insensitively_first_form_wins():
    pg = Group(group_name="lockbit", aliases=json.dumps(["ABCD Gang"]))
    merged = _merge_aliases(pg, ["abcd gang", "Bitwise Spider"])
    assert merged == ["ABCD Gang", "Bitwise Spider"]


def test_merge_aliases_tolerates_legacy_scalar_json():
    pg = Group(group_name="conti", aliases=json.dumps("Wizard Spider"))
    merged = _merge_aliases(pg, ["GOLD ULRICK"])
    assert merged == ["GOLD ULRICK", "Wizard Spider"]


# --- HI-09: fuzzy watchlist scan is incremental via high-water marks ---


def _hwm(session: Session, category: str) -> int:
    row = session.query(InfoUpdate).filter_by(category=category).first()
    return row.number if row else 0


def test_fuzzy_scan_records_high_water_marks():
    factory = _setup_db()
    with factory() as session:
        wl = Watchlist(name="Microsoft Corporation", active=True)
        v = Victim(victim_name="Microsoft Corp", attackdate=datetime(2024, 1, 1, tzinfo=UTC))
        session.add_all([wl, v])
        session.commit()

        alerts = fuzzy_match_watchlist(session, set(), threshold=80)
        assert len(alerts) == 1
        assert _hwm(session, VICTIM_HWM_CATEGORY) == v.id
        assert _hwm(session, TARGET_HWM_CATEGORY) == wl.id


def test_fuzzy_scan_skips_already_scanned_victims_for_seen_targets():
    factory = _setup_db()
    with factory() as session:
        wl = Watchlist(name="Microsoft Corporation", active=True)
        v = Victim(victim_name="Microsoft Corp", attackdate=datetime(2024, 1, 1, tzinfo=UTC))
        session.add_all([wl, v])
        session.commit()

        fuzzy_match_watchlist(session, set(), threshold=80)
        # Drop the alert: a full rescan would recreate it, an incremental one won't
        session.query(Alert).delete()
        session.commit()

        alerts = fuzzy_match_watchlist(session, set(), threshold=80)
        assert alerts == []


def test_fuzzy_scan_matches_new_victims_for_seen_targets():
    factory = _setup_db()
    with factory() as session:
        wl = Watchlist(name="Microsoft Corporation", active=True)
        v1 = Victim(victim_name="Microsoft Corp", attackdate=datetime(2024, 1, 1, tzinfo=UTC))
        session.add_all([wl, v1])
        session.commit()

        first = fuzzy_match_watchlist(session, set(), threshold=80)
        assert len(first) == 1

        v2 = Victim(victim_name="Microsoft Corporation Ltd")
        session.add(v2)
        session.commit()

        existing = set(session.query(Alert.watchlist_id, Alert.victim_id).all())
        second = fuzzy_match_watchlist(session, existing, threshold=80)
        assert [(a.watchlist_id, a.victim_id) for a in second] == [(wl.id, v2.id)]
        assert _hwm(session, VICTIM_HWM_CATEGORY) == v2.id


def test_fuzzy_scan_new_target_gets_full_scan_over_old_victims():
    factory = _setup_db()
    with factory() as session:
        wl1 = Watchlist(name="Microsoft Corporation", active=True)
        v = Victim(victim_name="Acme Industries", attackdate=datetime(2024, 1, 1, tzinfo=UTC))
        session.add_all([wl1, v])
        session.commit()

        fuzzy_match_watchlist(session, set(), threshold=80)  # advances both HWMs

        wl2 = Watchlist(name="Acme Industries Inc", active=True)
        session.add(wl2)
        session.commit()

        existing = set(session.query(Alert.watchlist_id, Alert.victim_id).all())
        alerts = fuzzy_match_watchlist(session, existing, threshold=80)
        assert [(a.watchlist_id, a.victim_id) for a in alerts] == [(wl2.id, v.id)]
        assert _hwm(session, TARGET_HWM_CATEGORY) == wl2.id
