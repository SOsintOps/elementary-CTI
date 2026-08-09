# "I abhor the dull routine of existence." — Sherlock Holmes, Elementary
import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from pestilentia.clients.base import BaseSource, SourceError
from pestilentia.models import InfoUpdate
from pestilentia.pipeline.ingest import (
    IngestResult,
    _get_or_create_source,
    _ingest_cyberattacks,
    _ingest_groups,
    _ingest_victims,
)

logger = logging.getLogger(__name__)

BACKFILL_FIRST_YEAR = 2020
BACKFILL_CATEGORY = "backfill_complete"


# "I have always regarded cold cases as the truest test." — Sherlock, Elementary
def is_backfill_done(session: Session, source_name: str) -> bool:
    return (
        session.query(InfoUpdate).filter_by(category=f"{BACKFILL_CATEGORY}:{source_name}").first()
        is not None
    )


def mark_backfill_done(session: Session, source_name: str) -> None:
    record = InfoUpdate(
        category=f"{BACKFILL_CATEGORY}:{source_name}",
        last_update_json=datetime.now(UTC),
    )
    session.add(record)
    session.commit()


def _backfill_year_done(session: Session, source_name: str, year: int) -> bool:
    return (
        session.query(InfoUpdate).filter_by(category=f"backfill_year:{source_name}:{year}").first()
        is not None
    )


def _mark_year_done(session: Session, source_name: str, year: int) -> None:
    record = InfoUpdate(
        category=f"backfill_year:{source_name}:{year}",
        last_update_json=datetime.now(UTC),
    )
    session.add(record)
    session.commit()


# "Problems without solutions aren't problems, they're facts." — Sherlock Holmes, Elementary
async def run_backfill(session: Session, source: BaseSource) -> list[IngestResult]:
    results = []
    ds = _get_or_create_source(session, source.source_name)
    current_year = datetime.now(UTC).year

    try:
        raw_groups = await source.fetch_groups()
        added, skipped = _ingest_groups(session, raw_groups, ds.id)
        session.commit()
        logger.info("Backfill groups from %s: +%d, skipped %d", source.source_name, added, skipped)
    except SourceError as exc:
        logger.warning("Backfill groups failed for %s: %s", source.source_name, exc)

    for year in range(BACKFILL_FIRST_YEAR, current_year + 1):
        if _backfill_year_done(session, source.source_name, year):
            logger.info("Backfill %s year %d already done, skipping", source.source_name, year)
            continue

        result = IngestResult(source=source.source_name, errors=[])
        try:
            raw_victims = await source.fetch_all_victims(year)
            result.victims_added, result.victims_skipped = _ingest_victims(
                session, raw_victims, ds.id
            )
            session.commit()
            logger.info(
                "Backfill %s/%d: +%d victims, skipped %d",
                source.source_name,
                year,
                result.victims_added,
                result.victims_skipped,
            )
        except SourceError as exc:
            logger.warning("Backfill victims %s/%d failed: %s", source.source_name, year, exc)
            result.errors.append(f"victims/{year}: {exc}")
            results.append(result)
            continue

        _mark_year_done(session, source.source_name, year)
        results.append(result)

    try:
        raw_attacks = await source.fetch_all_cyberattacks()
        added, skipped = _ingest_cyberattacks(session, raw_attacks, ds.id)
        session.commit()
        logger.info(
            "Backfill cyberattacks from %s: +%d, skipped %d",
            source.source_name,
            added,
            skipped,
        )
    except SourceError as exc:
        logger.warning("Backfill cyberattacks failed for %s: %s", source.source_name, exc)

    mark_backfill_done(session, source.source_name)
    logger.info("Backfill complete for %s", source.source_name)
    return results
