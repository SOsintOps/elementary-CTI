# "I'm a consultant. The police don't hire me." — Sherlock, Elementary
"""Article-source ingestion entry point (Phase 2).

`run_article_ingest` is the single production caller for the Phase 2 pieces:
it seeds the curated sources, polls every enabled feed and then fills in the
full text of whatever is still summary-only. The scheduler drives it through
`_run_enrichment`, which is why the return value is one flat stats dict.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from pestilentia.ai.sources.fulltext import enrich_articles_fulltext
from pestilentia.ai.sources.rss import ingest_all
from pestilentia.ai.sources.seeds import seed_article_sources
from pestilentia.models.tables import InfoUpdate

log = logging.getLogger(__name__)

ARTICLES_CATEGORY = "ai_articles_enrichment"

DEFAULT_FULLTEXT_LIMIT = 50


def _set_last_enrichment(session: Session, ts: datetime) -> None:
    row = session.query(InfoUpdate).filter_by(category=ARTICLES_CATEGORY).first()
    if row:
        row.last_update_json = ts
    else:
        session.add(InfoUpdate(category=ARTICLES_CATEGORY, last_update_json=ts))


def _aggregate(per_feed: list[dict]) -> dict:
    """Flatten per-feed stats into one dict.

    `ingest_feed` reports already-known articles under "skipped"; that key is
    deliberately renamed to "known" here, because `_run_enrichment` reads a
    truthy top-level "skipped" as "the enrichment did not run" and would log
    every successful cycle as skipped.
    """
    agg = {
        "feeds": len(per_feed),
        "feeds_failed": 0,
        "entries": 0,
        "added": 0,
        "known": 0,
        "near_dup": 0,
        "entry_errors": 0,
        "not_modified": 0,
    }
    for feed in per_feed:
        if feed.get("error"):
            agg["feeds_failed"] += 1
            continue
        agg["entries"] += feed.get("entries", 0)
        agg["added"] += feed.get("added", 0)
        agg["known"] += feed.get("skipped", 0)
        agg["near_dup"] += feed.get("near_dup", 0)
        agg["entry_errors"] += feed.get("errors", 0)
        if feed.get("not_modified"):
            agg["not_modified"] += 1
    return agg


def run_article_ingest(session: Session, fulltext_limit: int = DEFAULT_FULLTEXT_LIMIT) -> dict:
    """Seed sources, poll every enabled feed, then fill in missing full text.

    Commits between phases so a later failure cannot roll back articles that
    were already fetched successfully.
    """
    seeded = seed_article_sources(session)
    if seeded:
        session.commit()  # ingest_all queries the rows we just added
        log.info("Seeded %d article sources", seeded)

    per_feed = ingest_all(session)
    session.commit()

    stats = _aggregate(per_feed)
    stats["sources_seeded"] = seeded

    fulltext = enrich_articles_fulltext(session, limit=fulltext_limit)
    stats["fulltext_processed"] = fulltext["processed"]
    stats["fulltext_ok"] = fulltext["ok"]
    stats["fulltext_failed"] = fulltext["failed"]

    _set_last_enrichment(session, datetime.now(UTC))
    session.commit()

    log.info(
        "Article ingest: %d/%d feeds ok, %d entries, +%d new, %d known, "
        "%d near-dup, full text %d/%d",
        stats["feeds"] - stats["feeds_failed"],
        stats["feeds"],
        stats["entries"],
        stats["added"],
        stats["known"],
        stats["near_dup"],
        stats["fulltext_ok"],
        stats["fulltext_processed"],
    )
    return stats
