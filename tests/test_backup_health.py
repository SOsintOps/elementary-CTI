# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""The off-device backup reports itself, and is judged on its age.

Written after three consecutive nightly pushes failed without leaving a trace
anywhere a person looks: the script's only witness was the user journal, which
this host does not retain, and the oneshot unit's failed state was erased by the
next reboot. The two halves under test are the two halves of that hole.

`record_backup_push` covers the push that fails and says so. `check_backup_push`
covers the harder case the recorder cannot: a push that never runs at all, where
nothing writes a row and therefore nothing looks wrong.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.models.base import Base
from pestilentia.models.tables import SourceHealth
from pestilentia.pipeline.health import (
    BACKUP_PUSH_SOURCE,
    check_backup_push,
    record_backup_push,
)


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        yield db


def _row(session) -> SourceHealth:
    return session.query(SourceHealth).filter_by(source_name=BACKUP_PUSH_SOURCE).one()


def test_a_successful_push_is_recorded_with_its_size(session):
    record_backup_push(session, ok=True, detail="pushed x.dump", dump_bytes=11_228_896)
    row = _row(session)
    assert row.status == "ok"
    assert row.last_ok is not None
    assert row.row_count == 11_228_896
    assert row.error_message is None


def test_a_failed_push_is_recorded_with_the_reason_and_does_not_touch_last_ok(session):
    record_backup_push(session, ok=True, detail="pushed x.dump")
    good = _row(session).last_ok

    record_backup_push(session, ok=False, detail="could not read Username for 'https://github.com'")
    row = _row(session)
    assert row.status == "down"
    assert "could not read Username" in row.error_message
    # The last *successful* push is a fact about the past and a failure does not
    # revise it. Overwriting it here would erase the only number that answers
    # "how far back does the off-device copy go".
    assert row.last_ok == good


def test_a_backup_that_never_ran_is_down_and_says_so(session):
    """The case that hid for three days: no row at all reads as no problem."""
    result = check_backup_push(session)
    assert result["status"] == "down"
    assert result["age_days"] is None
    assert "has ever been recorded" in _row(session).error_message


@pytest.mark.parametrize(
    ("days_ago", "expected"),
    [
        (0.5, "ok"),
        (1.9, "ok"),
        (2.5, "degraded"),
        (3.9, "degraded"),
        (4.5, "down"),
        (30.0, "down"),
    ],
)
def test_the_verdict_follows_the_age_of_the_last_success(session, days_ago, expected):
    record_backup_push(session, ok=True, detail="pushed")
    row = _row(session)
    row.last_ok = datetime.now(UTC) - timedelta(days=days_ago)

    assert check_backup_push(session)["status"] == expected


def test_ageing_reports_the_gap_in_days_rather_than_a_bare_verdict(session):
    record_backup_push(session, ok=True, detail="pushed")
    _row(session).last_ok = datetime.now(UTC) - timedelta(days=3)

    check_backup_push(session)
    assert "3.0 days ago" in _row(session).error_message


def test_a_reported_success_clears_an_ageing_complaint(session):
    """A push that works again must not leave the old alarm standing."""
    record_backup_push(session, ok=True, detail="pushed")
    _row(session).last_ok = datetime.now(UTC) - timedelta(days=5)
    assert check_backup_push(session)["status"] == "down"

    record_backup_push(session, ok=True, detail="pushed again")
    assert check_backup_push(session)["status"] == "ok"
    assert _row(session).error_message is None


def test_a_naive_timestamp_is_read_as_utc_rather_than_crashing(session):
    """SQLite hands back naive datetimes; PostgreSQL does not.

    The comparison against `now` would raise on the development database and
    work in production, which is the shape of bug that ships.
    """
    record_backup_push(session, ok=True, detail="pushed")
    _row(session).last_ok = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=3)

    assert check_backup_push(session)["status"] == "degraded"


def test_the_backup_row_reaches_the_page_an_operator_reads(monkeypatch, authenticate):
    """The whole point: a failed backup must be visible without opening a shell.

    Recording the outcome in `source_health` achieves nothing if the pipeline
    page does not list that source, and the template's key list is hand-written,
    so a row can exist and still show nowhere.
    """
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    import pestilentia.config as config
    import pestilentia.web.app as web
    from pestilentia.config import Settings
    from pestilentia.web.app import app

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        record_backup_push(db, ok=False, detail="ssh: Permission denied (publickey)")
        db.commit()

    monkeypatch.setattr(config, "_settings", Settings(secret_key="x" * 64))
    monkeypatch.setattr(web, "_session_factory", factory)
    client = TestClient(app)
    authenticate(client, factory)

    body = client.get("/pipeline").text
    assert "Off-device DB backup" in body
    assert "Permission denied" in body
