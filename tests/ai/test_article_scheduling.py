"""Phase 2: the article ingest cycle wired into the scheduler.

Guards the two things that silently break the wiring: the stats key clash
between `ingest_feed`'s "skipped" and `_run_enrichment`'s "did not run"
sentinel, and the enabled/due gates that must keep the cycle off the network.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from pestilentia.ai import sources as ai_sources
from pestilentia.ai.sources import ARTICLES_CATEGORY, run_article_ingest
from pestilentia.ai.sources.seeds import SEED_SOURCES
from pestilentia.models.base import Base
from pestilentia.models.tables import ArticleSource, InfoUpdate
from pestilentia.pipeline import scheduler


def _setup() -> sessionmaker[Session]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_aggregate_renames_skipped_to_known():
    """A successful cycle must not report a truthy top-level "skipped".

    `_run_enrichment` reads that key as "the enrichment did not run"; leaving
    `ingest_feed`'s per-feed "skipped" (= already-known articles) at the top
    level would log every real cycle as skipped.
    """
    agg = ai_sources._aggregate(
        [
            {"source": "a", "entries": 10, "added": 2, "skipped": 8, "near_dup": 0, "errors": 0},
            {"source": "b", "entries": 5, "added": 0, "skipped": 4, "near_dup": 1, "errors": 0},
        ]
    )
    assert agg["known"] == 12
    assert agg["added"] == 2
    assert agg["near_dup"] == 1
    assert agg["feeds"] == 2
    assert agg["feeds_failed"] == 0
    assert not agg.get("skipped")


def test_aggregate_counts_failed_feeds():
    agg = ai_sources._aggregate(
        [
            {"source": "a", "entries": 3, "added": 3, "skipped": 0, "near_dup": 0, "errors": 0},
            {"source": "b", "error": True},
        ]
    )
    assert agg["feeds"] == 2
    assert agg["feeds_failed"] == 1
    assert agg["added"] == 3


def test_run_article_ingest_seeds_then_is_idempotent(monkeypatch):
    """First run seeds the curated sources; the second adds none."""
    monkeypatch.setattr(ai_sources, "ingest_all", lambda session: [])
    monkeypatch.setattr(
        ai_sources,
        "enrich_articles_fulltext",
        lambda session, limit=50: {"processed": 0, "ok": 0, "failed": 0},
    )
    factory = _setup()
    with factory() as session:
        first = run_article_ingest(session)
        assert first["sources_seeded"] == len(SEED_SOURCES)
        assert session.query(ArticleSource).count() == len(SEED_SOURCES)

        second = run_article_ingest(session)
        assert second["sources_seeded"] == 0
        assert session.query(ArticleSource).count() == len(SEED_SOURCES)


def test_run_article_ingest_stamps_last_enrichment(monkeypatch):
    monkeypatch.setattr(ai_sources, "ingest_all", lambda session: [])
    monkeypatch.setattr(
        ai_sources,
        "enrich_articles_fulltext",
        lambda session, limit=50: {"processed": 0, "ok": 0, "failed": 0},
    )
    factory = _setup()
    with factory() as session:
        run_article_ingest(session)
        row = session.query(InfoUpdate).filter_by(category=ARTICLES_CATEGORY).first()
        assert row is not None and row.last_update_json is not None


def test_run_article_ingest_reports_fulltext(monkeypatch):
    monkeypatch.setattr(ai_sources, "ingest_all", lambda session: [])
    monkeypatch.setattr(
        ai_sources,
        "enrich_articles_fulltext",
        lambda session, limit=50: {"processed": 4, "ok": 3, "failed": 1},
    )
    factory = _setup()
    with factory() as session:
        stats = run_article_ingest(session)
    assert stats["fulltext_processed"] == 4
    assert stats["fulltext_ok"] == 3
    assert stats["fulltext_failed"] == 1


@pytest.mark.anyio
async def test_enrichment_skipped_when_not_due(monkeypatch):
    """A recent InfoUpdate row must keep the cycle away from the network."""
    factory = _setup()
    with factory() as session:
        session.add(
            InfoUpdate(
                category=ARTICLES_CATEGORY,
                last_update_json=datetime.now(UTC) - timedelta(minutes=5),
            )
        )
        session.commit()

    called = False

    def _boom(session):  # pragma: no cover - must not run
        nonlocal called
        called = True
        return {}

    await scheduler._run_enrichment(factory, "Articles", ARTICLES_CATEGORY, _boom, 4 * 3600)
    assert called is False


@pytest.mark.anyio
async def test_enrichment_runs_when_due():
    factory = _setup()
    with factory() as session:
        session.add(
            InfoUpdate(
                category=ARTICLES_CATEGORY,
                last_update_json=datetime.now(UTC) - timedelta(hours=9),
            )
        )
        session.commit()

    seen = {}

    def _fake(session):
        seen["ran"] = True
        return {"feeds": 1, "added": 2, "known": 0}

    await scheduler._run_enrichment(factory, "Articles", ARTICLES_CATEGORY, _fake, 4 * 3600)
    assert seen.get("ran") is True


def test_articles_enrichment_toggle_defaults_on_and_can_be_disabled():
    """Missing row = enabled; number=0 disables, matching the other sources."""
    factory = _setup()
    with factory() as session:
        assert scheduler._is_enrichment_enabled(session, "articles") is True
        session.add(InfoUpdate(category="articles_enabled", number=0))
        session.commit()
        assert scheduler._is_enrichment_enabled(session, "articles") is False

        session.query(InfoUpdate).filter_by(category="articles_enabled").update({"number": 1})
        session.commit()
        assert scheduler._is_enrichment_enabled(session, "articles") is True


# --- W14: second feed wave ---


def test_seed_sources_are_unique_by_name_and_url():
    """A duplicate would be silently skipped by the name check and never poll."""
    names = [s["name"] for s in SEED_SOURCES]
    urls = [s["url"] for s in SEED_SOURCES]
    assert len(names) == len(set(names))
    assert len(urls) == len(set(urls))


def test_every_seed_has_a_sane_trust_weight_and_cadence():
    for spec in SEED_SOURCES:
        assert 0.0 < spec["trust_weight"] <= 1.0, spec["name"]
        assert spec["cadence_hours"] >= 1, spec["name"]
        assert spec["url"].startswith("https://"), spec["name"]


def test_user_agent_identifies_the_client_and_a_contact():
    """A bare token gets a crawler blocked; upstreams need someone to reach."""
    from pestilentia.clients.http import USER_AGENT

    assert USER_AGENT.startswith("elementary-cti/")
    assert "github.com/SOsintOps/elementary-CTI" in USER_AGENT


def test_article_interval_defaults_to_every_cycle():
    """0 = run on every outer loop.

    The due-gate is evaluated once per scheduler cycle, so an interval equal to
    the loop period makes a run that is minutes short of due wait a whole extra
    period — cadence drifts to 4-8h against a documented 4h.
    """
    from pestilentia.config import Settings
    from pestilentia.pipeline.scheduler import DEFAULT_ARTICLE_INTERVAL_SECONDS

    assert DEFAULT_ARTICLE_INTERVAL_SECONDS == 0
    assert Settings().article_ingest_hours == 0


def test_zero_interval_is_always_due():
    factory = _setup()
    with factory() as session:
        session.add(InfoUpdate(category=ARTICLES_CATEGORY, last_update_json=datetime.now(UTC)))
        session.commit()
        assert scheduler._enrichment_due(session, ARTICLES_CATEGORY, 0) is True
