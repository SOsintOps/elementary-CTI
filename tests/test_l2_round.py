"""Regression tests for the L2 migration round: tz-aware datetimes,
Cyberattack uniqueness, Alert FK CASCADE, Group.is_hacktivist."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.classify import is_hacktivist_description
from pestilentia.models import Alert, Cyberattack, Group, Victim, Watchlist
from pestilentia.models.base import Base


def _setup_db(enforce_fk: bool = False) -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    if enforce_fk:

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


# --- classify (ME-11/NI-04) ---


@pytest.mark.parametrize(
    ("desc", "expected"),
    [
        ("This is NOT a ransomware group, it is a hacktivist crew", True),
        ("A Data Broker selling stolen records", True),
        ("Classic double-extortion ransomware gang", False),
        (None, False),
        ("", False),
    ],
)
def test_is_hacktivist_description(desc, expected):
    assert is_hacktivist_description(desc) is expected


def test_group_is_hacktivist_defaults_false():
    factory = _setup_db()
    with factory() as session:
        session.add(Group(group_name="plaingroup"))
        session.commit()
        g = session.query(Group).one()
        assert g.is_hacktivist is False


# --- Cyberattack unique constraint (BL-07) ---


def test_cyberattack_duplicate_rejected():
    factory = _setup_db()
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    with factory() as session:
        session.add(Cyberattack(victim_name="Acme", attack_date=ts))
        session.commit()
        session.add(Cyberattack(victim_name="Acme", attack_date=ts))
        with pytest.raises(IntegrityError):
            session.commit()


def test_cyberattack_null_keys_still_allowed():
    factory = _setup_db()
    with factory() as session:
        session.add_all(
            [
                Cyberattack(victim_name="Acme", attack_date=None),
                Cyberattack(victim_name="Acme", attack_date=None),
            ]
        )
        session.commit()
        assert session.query(Cyberattack).count() == 2


# --- Alert FK CASCADE (ME-01 follow-up) ---


def test_deleting_watchlist_cascades_alerts():
    factory = _setup_db(enforce_fk=True)
    with factory() as session:
        wl = Watchlist(name="Acme", active=True)
        v = Victim(victim_name="Acme Corp")
        session.add_all([wl, v])
        session.flush()
        session.add(Alert(watchlist_id=wl.id, victim_id=v.id, match_field="name"))
        session.commit()

        session.execute(text("DELETE FROM watchlist WHERE id = :wid"), {"wid": wl.id})
        session.commit()
        assert session.query(Alert).count() == 0


def test_deleting_victim_cascades_alerts():
    factory = _setup_db(enforce_fk=True)
    with factory() as session:
        wl = Watchlist(name="Acme", active=True)
        v = Victim(victim_name="Acme Corp")
        session.add_all([wl, v])
        session.flush()
        session.add(Alert(watchlist_id=wl.id, victim_id=v.id, match_field="name"))
        session.commit()

        session.execute(text("DELETE FROM victims WHERE id = :vid"), {"vid": v.id})
        session.commit()
        assert session.query(Alert).count() == 0
