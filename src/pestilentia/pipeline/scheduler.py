# "I am better with you, Watson. I'm sharper, I'm more focused." — Sherlock Holmes, Elementary
import asyncio
import contextlib
import logging
import signal
import time
from datetime import UTC, datetime

from sqlalchemy.orm import Session, sessionmaker

from pestilentia.ai.sources import ARTICLES_CATEGORY, run_article_ingest
from pestilentia.clients.base import BaseSource
from pestilentia.clients.deepdarkcti import DEEPDARK_CATEGORY, enrich_deepdarkcti
from pestilentia.clients.mitre_attack import MITRE_ENRICHMENT_CATEGORY, enrich_groups_incremental
from pestilentia.clients.ransomwhere import RANSOMWHERE_CATEGORY, enrich_ransomwhere
from pestilentia.clients.registry import SOURCES
from pestilentia.models.tables import InfoUpdate
from pestilentia.pipeline.backfill import is_backfill_done, run_backfill
from pestilentia.pipeline.health import run_health_checks
from pestilentia.pipeline.ingest import ingest_source

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 2 * 60 * 60  # 2 hours
DEFAULT_MITRE_INTERVAL_SECONDS = 7 * 24 * 60 * 60  # 1 week
# Article ingest rides the outer cycle: the loop body runs once per
# `interval_seconds`, so a shorter value here cannot produce a shorter cadence.
# 0 means "every outer cycle". A non-zero value equal to the loop period is
# worse than useless: the due-gate is checked once per loop, so a run that is
# a minute short of due waits a whole extra period (observed 4-8h in prod
# against a documented 4h).
DEFAULT_ARTICLE_INTERVAL_SECONDS = 0


def _is_enrichment_enabled(session: Session, name: str) -> bool:
    """Check if enrichment source is enabled (default: True)."""
    row = session.query(InfoUpdate).filter_by(category=f"{name}_enabled").first()
    if not row:
        return True
    return bool(row.number)


# "Eliminate the impossible; whatever remains must be truth." — Sherlock
async def _run_cycle(session_factory: sessionmaker[Session], source_name: str) -> None:
    source_cls = SOURCES.get(source_name)
    if not source_cls:
        logger.error("Unknown source: %s", source_name)
        return

    source: BaseSource = source_cls()
    try:
        with session_factory() as session:
            if not is_backfill_done(session, source_name):
                logger.info("Starting backfill for %s", source_name)
                await run_backfill(session, source)
                logger.info("Backfill finished for %s, switching to incremental", source_name)
            else:
                result = await ingest_source(session, source)
                logger.info(
                    "Incremental update %s: +%d victims, +%d attacks",
                    source_name,
                    result.victims_added,
                    result.cyberattacks_added,
                )
    finally:
        await source.close()


def _mitre_enrichment_due(session: Session, interval_seconds: int) -> bool:
    """Check if enough time has passed since last MITRE enrichment."""
    row = session.query(InfoUpdate).filter_by(category=MITRE_ENRICHMENT_CATEGORY).first()
    if not row or not row.last_update_json:
        return True
    last = row.last_update_json
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    elapsed = (datetime.now(UTC) - last).total_seconds()
    return elapsed >= interval_seconds


async def _run_mitre_enrichment(
    session_factory: sessionmaker[Session],
    interval_seconds: int,
) -> None:
    """Run incremental MITRE enrichment if due."""
    with session_factory() as session:
        if not _mitre_enrichment_due(session, interval_seconds):
            logger.debug("MITRE enrichment not due yet, skipping")
            return

        logger.info("Starting MITRE ATT&CK incremental enrichment")
        t0 = time.monotonic()
        try:
            stats = enrich_groups_incremental(session)
            if stats.get("skipped"):
                logger.info("MITRE enrichment skipped (bundle unchanged, no new groups)")
            else:
                logger.info(
                    "MITRE enrichment complete (%.2fs): matched=%d, ttps=%d, tools=%d",
                    time.monotonic() - t0,
                    stats["matched_groups"],
                    stats["ttps_added"],
                    stats["tools_added"],
                )
        except Exception:
            logger.exception("MITRE enrichment failed (%.2fs)", time.monotonic() - t0)


def _enrichment_due(session: Session, category: str, interval_seconds: int) -> bool:
    row = session.query(InfoUpdate).filter_by(category=category).first()
    if not row or not row.last_update_json:
        return True
    last = row.last_update_json
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    elapsed = (datetime.now(UTC) - last).total_seconds()
    return elapsed >= interval_seconds


async def _run_enrichment(
    session_factory: sessionmaker[Session],
    name: str,
    category: str,
    enrich_fn,
    interval_seconds: int,
) -> None:
    with session_factory() as session:
        if not _enrichment_due(session, category, interval_seconds):
            logger.debug("%s enrichment not due yet, skipping", name)
            return

        logger.info("Starting %s enrichment", name)
        t0 = time.monotonic()
        try:
            stats = enrich_fn(session)
            if stats.get("skipped"):
                logger.info("%s enrichment skipped (fresh)", name)
            else:
                logger.info(
                    "%s enrichment complete (%.2fs): %s",
                    name,
                    time.monotonic() - t0,
                    stats,
                )
        except Exception:
            logger.exception("%s enrichment failed (%.2fs)", name, time.monotonic() - t0)


# "I find your lack of imagination disturbing." — Sherlock Holmes, Elementary
async def run_scheduler(
    session_factory: sessionmaker[Session],
    source_names: list[str] | None = None,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    mitre_interval_seconds: int = DEFAULT_MITRE_INTERVAL_SECONDS,
    ransomwhere_interval_seconds: int | None = None,
    deepdarkcti_interval_seconds: int | None = None,
    article_interval_seconds: int = DEFAULT_ARTICLE_INTERVAL_SECONDS,
) -> None:
    if ransomwhere_interval_seconds is None:
        ransomwhere_interval_seconds = mitre_interval_seconds
    if deepdarkcti_interval_seconds is None:
        deepdarkcti_interval_seconds = mitre_interval_seconds
    sources = source_names or list(SOURCES.keys())
    stop_event = asyncio.Event()

    def _handle_signal() -> None:
        logger.info("Received shutdown signal, stopping after current cycle")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal)

    logger.info(
        "Scheduler started: sources=%s, interval=%ds, mitre_interval=%ds, article_interval=%ds",
        sources,
        interval_seconds,
        mitre_interval_seconds,
        article_interval_seconds,
    )

    try:
        await _scheduler_loop(
            session_factory,
            sources,
            stop_event,
            interval_seconds,
            mitre_interval_seconds,
            ransomwhere_interval_seconds,
            deepdarkcti_interval_seconds,
            article_interval_seconds,
        )
    finally:
        # Unregister so a second run_scheduler in the same loop (tests,
        # embedded drivers) doesn't act on a stale stop_event (LO-03)
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)

    logger.info("Scheduler stopped gracefully")


async def _scheduler_loop(
    session_factory: sessionmaker[Session],
    sources: list[str],
    stop_event: asyncio.Event,
    interval_seconds: int,
    mitre_interval_seconds: int,
    ransomwhere_interval_seconds: int,
    deepdarkcti_interval_seconds: int,
    article_interval_seconds: int = DEFAULT_ARTICLE_INTERVAL_SECONDS,
) -> None:
    while not stop_event.is_set():
        for name in sources:
            if stop_event.is_set():
                break
            t0 = time.monotonic()
            try:
                await _run_cycle(session_factory, name)
                logger.info(
                    "Cycle completed for %s (%.2fs)",
                    name,
                    time.monotonic() - t0,
                    extra={"source": name, "duration_s": round(time.monotonic() - t0, 2)},
                )
            except Exception:
                logger.exception(
                    "Cycle failed for %s (%.2fs), will retry next cycle",
                    name,
                    time.monotonic() - t0,
                    extra={"source": name, "duration_s": round(time.monotonic() - t0, 2)},
                )

        # Enrichments post-cycle (respect enabled flags)
        mitre_on = rw_on = dd_on = art_on = False
        if not stop_event.is_set():
            with session_factory() as s:
                mitre_on = _is_enrichment_enabled(s, "mitre")
                rw_on = _is_enrichment_enabled(s, "ransomwhere")
                dd_on = _is_enrichment_enabled(s, "deepdarkcti")
                art_on = _is_enrichment_enabled(s, "articles")

            if mitre_on:
                await _run_mitre_enrichment(session_factory, mitre_interval_seconds)
            else:
                logger.debug("MITRE enrichment disabled, skipping")
        if not stop_event.is_set() and rw_on:
            await _run_enrichment(
                session_factory,
                "Ransomwhere",
                RANSOMWHERE_CATEGORY,
                enrich_ransomwhere,
                ransomwhere_interval_seconds,
            )
        if not stop_event.is_set() and dd_on:
            await _run_enrichment(
                session_factory,
                "deepdarkCTI",
                DEEPDARK_CATEGORY,
                enrich_deepdarkcti,
                deepdarkcti_interval_seconds,
            )
        if not stop_event.is_set() and art_on:
            await _run_enrichment(
                session_factory,
                "Articles",
                ARTICLES_CATEGORY,
                run_article_ingest,
                article_interval_seconds,
            )

        # Health checks post-enrichment
        if not stop_event.is_set():
            try:
                with session_factory() as session:
                    run_health_checks(session)
            except Exception:
                logger.exception("Health check failed")

        if not stop_event.is_set():
            logger.info("Next cycle in %d seconds", interval_seconds)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
