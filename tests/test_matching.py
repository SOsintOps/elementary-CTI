from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.matching import fuzzy_match_watchlist
from pestilentia.models import Victim, Watchlist
from pestilentia.models.base import Base


def _setup_db() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_fuzzy_name_match():
    factory = _setup_db()
    with factory() as session:
        session.add(Watchlist(name="Microsoft Corporation", active=True))
        session.add(
            Victim(
                victim_name="Microsoft Corp",
                domain="microsoft.com",
                attackdate=datetime(2024, 1, 1, tzinfo=UTC),
            )
        )
        session.commit()

        existing = set()
        alerts = fuzzy_match_watchlist(session, existing, threshold=80)
        assert len(alerts) == 1
        assert alerts[0].match_field.startswith("fuzzy_name:")


def test_fuzzy_domain_match():
    factory = _setup_db()
    with factory() as session:
        session.add(Watchlist(name="Amazon", domain="amaz0n.com", active=True))
        session.add(
            Victim(
                victim_name="Amazon Inc",
                domain="amazon.com",
                attackdate=datetime(2024, 1, 1, tzinfo=UTC),
            )
        )
        session.commit()

        existing = set()
        alerts = fuzzy_match_watchlist(session, existing, threshold=80)
        assert len(alerts) == 1
        assert alerts[0].match_field.startswith("fuzzy_domain:")


def test_fuzzy_no_match_below_threshold():
    factory = _setup_db()
    with factory() as session:
        session.add(Watchlist(name="Apple Inc", active=True))
        session.add(
            Victim(
                victim_name="Totally Different Company",
                domain="different.com",
                attackdate=datetime(2024, 1, 1, tzinfo=UTC),
            )
        )
        session.commit()

        existing = set()
        alerts = fuzzy_match_watchlist(session, existing, threshold=85)
        assert len(alerts) == 0


def test_fuzzy_skips_existing_pairs():
    factory = _setup_db()
    with factory() as session:
        wl = Watchlist(name="Microsoft Corporation", active=True)
        session.add(wl)
        v = Victim(
            victim_name="Microsoft Corp",
            domain="microsoft.com",
            attackdate=datetime(2024, 1, 1, tzinfo=UTC),
        )
        session.add(v)
        session.commit()

        existing = {(wl.id, v.id)}
        alerts = fuzzy_match_watchlist(session, existing, threshold=80)
        assert len(alerts) == 0


def test_fuzzy_keyword_match():
    factory = _setup_db()
    with factory() as session:
        session.add(Watchlist(name="Target Co", keywords="energy,utilities", active=True))
        session.add(
            Victim(
                victim_name="National Energy Corp",
                domain="energy.com",
                attackdate=datetime(2024, 1, 1, tzinfo=UTC),
            )
        )
        session.commit()

        existing = set()
        alerts = fuzzy_match_watchlist(session, existing, threshold=80)
        assert len(alerts) == 1
        assert alerts[0].match_field.startswith("fuzzy_keyword:")


def test_fuzzy_inactive_watchlist_ignored():
    factory = _setup_db()
    with factory() as session:
        session.add(Watchlist(name="Microsoft Corporation", active=False))
        session.add(
            Victim(
                victim_name="Microsoft Corp",
                domain="microsoft.com",
                attackdate=datetime(2024, 1, 1, tzinfo=UTC),
            )
        )
        session.commit()

        existing = set()
        alerts = fuzzy_match_watchlist(session, existing, threshold=80)
        assert len(alerts) == 0
