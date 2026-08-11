"""W4: victims-per-month timeline — SQL aggregation, zero-filling, ordering.

The aggregation happens in the database so the payload is one point per month
rather than one per victim. These tests pin the contract that the chart relies
on: contiguous months, oldest first, gaps as explicit zeros.
"""

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import pestilentia.config as config
import pestilentia.web.app as web
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import Victim
from pestilentia.web.app import _group_sparks, _kpi_trend, _victim_timeline, app


def _setup() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _add(session: Session, when: datetime, name: str) -> None:
    session.add(Victim(victim_name=name, attackdate=when))


def test_empty_db_still_returns_a_contiguous_series():
    factory = _setup()
    with factory() as session:
        series = _victim_timeline(session, months=6)
    assert len(series) == 6
    assert all(point["count"] == 0 for point in series)


def test_series_is_oldest_first_and_contiguous():
    factory = _setup()
    with factory() as session:
        series = _victim_timeline(session, months=12)
    months = [p["month"] for p in series]
    assert months == sorted(months), "series must run oldest -> newest"
    assert len(months) == len(set(months)), "no duplicate buckets"
    # Every step is exactly one calendar month.
    for earlier, later in pairwise(months):
        y1, m1 = (int(x) for x in earlier.split("-"))
        y2, m2 = (int(x) for x in later.split("-"))
        assert (y2 - y1) * 12 + (m2 - m1) == 1, f"gap between {earlier} and {later}"


def test_counts_land_in_the_right_month():
    factory = _setup()
    now = datetime.now(UTC)
    with factory() as session:
        _add(session, now, "a")
        _add(session, now, "b")
        session.commit()
        series = _victim_timeline(session, months=3)

    current = f"{now.year:04d}-{now.month:02d}"
    by_month = {p["month"]: p["count"] for p in series}
    assert by_month[current] == 2
    assert sum(by_month.values()) == 2


def test_empty_months_are_zero_filled_not_dropped():
    """A line that skips empty months implies a continuity that isn't there."""
    factory = _setup()
    now = datetime.now(UTC)
    old = (now.replace(day=1) - timedelta(days=62)).replace(day=15)
    with factory() as session:
        _add(session, now, "recent")
        _add(session, old, "old")
        session.commit()
        series = _victim_timeline(session, months=6)

    assert len(series) == 6
    assert sum(p["count"] for p in series) == 2
    assert any(p["count"] == 0 for p in series), "gaps must be explicit zeros"


def test_victims_without_a_date_are_excluded():
    factory = _setup()
    with factory() as session:
        session.add(Victim(victim_name="undated", attackdate=None))
        session.commit()
        series = _victim_timeline(session, months=3)
    assert sum(p["count"] for p in series) == 0


def test_window_size_is_respected():
    factory = _setup()
    with factory() as session:
        assert len(_victim_timeline(session, months=1)) == 1
        assert len(_victim_timeline(session, months=24)) == 24


# --- W7: KPI trend (delta vs the preceding window + 12-month spark) ---


def test_kpi_trend_no_baseline_yields_no_percentage():
    """A zero previous window has no percentage — inventing one fabricates a trend."""
    factory = _setup()
    now = datetime.now(UTC)
    with factory() as session:
        _add(session, now, "only-recent")
        session.commit()
        trend = _kpi_trend(session, Victim.id, Victim.attackdate, window_days=30)
    assert trend["current"] == 1
    assert trend["previous"] == 0
    assert trend["delta_pct"] is None


def test_kpi_trend_computes_percentage_against_previous_window():
    factory = _setup()
    now = datetime.now(UTC)
    with factory() as session:
        for i in range(3):
            _add(session, now - timedelta(days=1 + i), f"cur{i}")
        for i in range(2):
            _add(session, now - timedelta(days=40 + i), f"prev{i}")
        session.commit()
        trend = _kpi_trend(session, Victim.id, Victim.attackdate, window_days=30)
    assert trend["current"] == 3
    assert trend["previous"] == 2
    assert trend["delta_pct"] == 50


def test_kpi_trend_windows_do_not_overlap():
    """A row exactly on the boundary must be counted once, not twice."""
    factory = _setup()
    now = datetime.now(UTC)
    with factory() as session:
        _add(session, now - timedelta(days=15), "inside")
        _add(session, now - timedelta(days=45), "previous")
        session.commit()
        trend = _kpi_trend(session, Victim.id, Victim.attackdate, window_days=30)
    assert trend["current"] == 1
    assert trend["previous"] == 1


def test_kpi_trend_spark_is_twelve_months():
    factory = _setup()
    with factory() as session:
        trend = _kpi_trend(session, Victim.id, Victim.attackdate)
    assert len(trend["spark"]) == 12
    assert all(isinstance(v, int) for v in trend["spark"])


# --- W5: per-group activity sparkline ---


def test_group_sparks_batches_all_requested_groups():
    """Every requested group gets a full-length series, silent ones included."""
    from pestilentia.models.tables import Group

    factory = _setup()
    now = datetime.now(UTC)
    with factory() as session:
        loud = Group(group_name="loud")
        quiet = Group(group_name="quiet")
        session.add_all([loud, quiet])
        session.flush()
        session.add(Victim(victim_name="v1", attackdate=now, group_id=loud.id))
        session.commit()
        sparks = _group_sparks(session, [loud.id, quiet.id], months=12)

    assert set(sparks) == {loud.id, quiet.id}
    assert len(sparks[loud.id]) == 12
    assert len(sparks[quiet.id]) == 12
    assert sum(sparks[loud.id]) == 1
    # A dormant group is a flat line, not a missing series — that is the signal.
    assert sum(sparks[quiet.id]) == 0


def test_group_sparks_empty_input_is_a_no_op():
    factory = _setup()
    with factory() as session:
        assert _group_sparks(session, []) == {}


# --- W6: range selector endpoint contract ---


def test_timeline_endpoint_honours_the_requested_window(authenticate):
    """The selector re-queries the server, so the window must be real."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    config._settings = Settings(secret_key="x" * 64)
    factory = sessionmaker(bind=engine)
    web._session_factory = factory
    try:
        client = TestClient(app)
        authenticate(client, factory)
        for months in (3, 12, 24, 60):
            payload = client.get(f"/api/v1/stats/timeline?months={months}").json()
            assert payload["months"] == months
            assert len(payload["series"]) == months
        # Out-of-range values are rejected, not silently clamped.
        assert client.get("/api/v1/stats/timeline?months=0").status_code == 422
        assert client.get("/api/v1/stats/timeline?months=999").status_code == 422
    finally:
        web._session_factory = None
        config._settings = None


# --- W11: alert triage (derived severity, no stored column) ---


class _FakeAlert:
    def __init__(self, seen, match_field, created_at):
        self.seen = seen
        self.match_field = match_field
        self.created_at = created_at


def test_unread_alerts_come_first_and_strongest_match_leads():
    """Domain is documentary; keyword is fuzzy and may be coincidental."""
    from pestilentia.web.app import _triage_alerts

    now = datetime.now(UTC)
    alerts = [
        _FakeAlert(False, "keyword", now),
        _FakeAlert(False, "domain", now - timedelta(days=3)),
        _FakeAlert(False, "name", now),
        _FakeAlert(True, "domain", now),
    ]
    t = _triage_alerts(alerts)
    assert [a.match_field for a in t["unread"]] == ["domain", "name", "keyword"]
    assert len(t["unread"]) == 3


def test_read_alerts_split_by_recency():
    from pestilentia.web.app import _triage_alerts

    now = datetime.now(UTC)
    alerts = [
        _FakeAlert(True, "name", now - timedelta(days=2)),
        _FakeAlert(True, "name", now - timedelta(days=40)),
    ]
    t = _triage_alerts(alerts, recent_days=7)
    assert len(t["recent"]) == 1
    assert len(t["older"]) == 1


def test_triage_handles_naive_timestamps():
    """SQLite can hand back naive datetimes; comparing them would raise."""
    from pestilentia.web.app import _triage_alerts

    naive = datetime.now(UTC).replace(tzinfo=None)
    t = _triage_alerts([_FakeAlert(True, "name", naive)])
    assert len(t["recent"]) + len(t["older"]) == 1


def test_empty_alert_list_yields_empty_tiers():
    from pestilentia.web.app import _triage_alerts

    t = _triage_alerts([])
    assert t["unread"] == [] and t["recent"] == [] and t["older"] == []
