"""Regression tests for review findings "Group C": ME-01/07/09, LO-01/05/06."""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.clients.base import SourceError
from pestilentia.clients.deepdarkcti import parse_ransomware_table
from pestilentia.clients.mitre_attack import extract_country, validate_bundle
from pestilentia.models import Alert, Victim, Watchlist
from pestilentia.models.base import Base
from pestilentia.notifications.dispatcher import _build_event, dispatch_alerts
from pestilentia.web.app import _parse_aliases


def _setup_db() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


# --- ME-07: malformed STIX bundle fails loudly ---


def test_validate_bundle_accepts_well_formed():
    bundle = {"objects": []}
    assert validate_bundle(bundle) is bundle


@pytest.mark.parametrize("bad", [None, [], "etag-body", {"type": "bundle"}])
def test_validate_bundle_rejects_malformed(bad):
    with pytest.raises(SourceError, match="Invalid STIX bundle"):
        validate_bundle(bad)


# --- ME-01: orphaned alerts are skipped, not dispatched as "unknown" ---


def test_build_event_returns_none_for_deleted_watchlist():
    factory = _setup_db()
    with factory() as session:
        v = Victim(victim_name="Acme Corp")
        session.add(v)
        session.flush()
        alert = Alert(watchlist_id=99999, victim_id=v.id, match_field="name")
        session.add(alert)
        session.commit()

        assert _build_event(alert, session) is None


def test_build_event_returns_none_for_deleted_victim():
    factory = _setup_db()
    with factory() as session:
        wl = Watchlist(name="Acme", active=True)
        session.add(wl)
        session.flush()
        alert = Alert(watchlist_id=wl.id, victim_id=99999, match_field="name")
        session.add(alert)
        session.commit()

        assert _build_event(alert, session) is None


@pytest.mark.anyio
async def test_dispatch_alerts_skips_orphans_entirely():
    factory = _setup_db()
    with factory() as session:
        alert = Alert(watchlist_id=99999, victim_id=99999, match_field="name")
        session.add(alert)
        session.commit()

        sent = await dispatch_alerts(session, [alert.id])
        assert sent == 0


# --- LO-01: aliases JSON scalar doesn't iterate char-by-char ---


def test_parse_aliases_wraps_scalar_in_list():
    assert _parse_aliases(json.dumps("BlackCat")) == ["BlackCat"]


def test_parse_aliases_list_passthrough():
    assert _parse_aliases(json.dumps(["A", "B"])) == ["A", "B"]


def test_parse_aliases_invalid_json_returns_empty():
    assert _parse_aliases("{not json") == []


# --- LO-05: country attribution found beyond the first paragraph ---


def test_extract_country_in_second_paragraph():
    desc = (
        "APT-X is a financially motivated threat group active since 2019.\n"
        "Security researchers assess the group operates out of Russia."
    )
    assert extract_country(desc) == "RU"


# --- LO-06: back-to-back markdown tables don't leak headers as data ---


def test_parse_ransomware_table_consecutive_tables():
    md = (
        "| Name | Status |\n"
        "|---|---|\n"
        "| LockBit | ONLINE |\n"
        "| Group | Status |\n"
        "|---|---|\n"
        "| Conti | OFFLINE |\n"
    )
    rows = parse_ransomware_table(md)
    assert [r["name"] for r in rows] == ["LockBit", "Conti"]


# --- ME-09 lives in tests/test_web.py-style app context; tested via helper ---


def test_count_sources_excludes_disabled_enrichments():
    from pestilentia.models import InfoUpdate
    from pestilentia.web.app import _count_sources

    factory = _setup_db()
    with factory() as session:
        # Enrichment has run at least once...
        session.add(InfoUpdate(category="mitre_enrichment", last_update_json=datetime.now(UTC)))
        session.commit()
        # ...and is enabled by default (no toggle row) -> counted
        assert _count_sources(session) == 1

        # Toggled off -> no longer counted
        session.add(InfoUpdate(category="mitre_enabled", number=0))
        session.commit()
        assert _count_sources(session) == 0

        # Never-run enrichments are not counted even if enabled
        session.add(InfoUpdate(category="ransomwhere_enabled", number=1))
        session.commit()
        assert _count_sources(session) == 0
