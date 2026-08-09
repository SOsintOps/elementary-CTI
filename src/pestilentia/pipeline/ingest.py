# "It is the obvious which is so difficult to see most of the time." — Sherlock
import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pestilentia.classify import is_hacktivist_description
from pestilentia.clients.base import BaseSource, SourceError
from pestilentia.clients.registry import SOURCES
from pestilentia.clients.schemas import RawCyberattack, RawGroup, RawVictim
from pestilentia.models import (
    Country,
    Cyberattack,
    DataSource,
    Group,
    GroupLocation,
    GroupReference,
    GroupSourceData,
    Victim,
    VictimDuplicate,
)
from pestilentia.pipeline.source_evidence import upsert_source_evidence

logger = logging.getLogger(__name__)


@dataclass
class IngestResult:
    source: str
    victims_added: int = 0
    victims_skipped: int = 0
    groups_added: int = 0
    groups_skipped: int = 0
    cyberattacks_added: int = 0
    cyberattacks_skipped: int = 0
    errors: list[str] | None = None


# "One begins to twist facts to suit theories, instead of theories to suit facts." — Sherlock
def _get_or_create_source(session: Session, source_name: str, base_url: str = "") -> DataSource:
    ds = session.query(DataSource).filter_by(source_name=source_name).first()
    if not ds:
        ds = DataSource(source_name=source_name, base_url=base_url)
        session.add(ds)
        session.flush()
    return ds


def _get_or_create_country(session: Session, iso_code: str) -> Country | None:
    if not iso_code:
        return None
    country = session.query(Country).filter_by(iso_code=iso_code.upper()).first()
    if not country:
        country = Country(iso_code=iso_code.upper())
        session.add(country)
        session.flush()
    return country


def _get_or_create_group(session: Session, group_name: str, source_id: int) -> Group | None:
    if not group_name:
        return None
    group = session.query(Group).filter_by(group_name=group_name).first()
    if not group:
        group = Group(group_name=group_name, source_id=source_id)
        session.add(group)
        session.flush()
    return group


def _merge_altname(existing_aliases: str | None, altname: str) -> str | None:
    """Merge altname into existing aliases JSON list, avoiding duplicates."""
    if not altname:
        return existing_aliases

    try:
        current = json.loads(existing_aliases) if existing_aliases else []
    except (json.JSONDecodeError, TypeError):
        current = []

    # Check case-insensitive to avoid duplicates like "BlackCat" and "blackcat"
    lower_set = {a.lower() for a in current}
    if altname.lower() not in lower_set:
        current.append(altname)

    return json.dumps(current) if current else None


def _ingest_groups(session: Session, raw_groups: list[RawGroup], source_id: int) -> tuple[int, int]:
    added = 0
    skipped = 0
    for rg in raw_groups:
        existing = session.query(Group).filter_by(group_name=rg.name).first()
        if existing:
            if rg.altname:
                existing.aliases = _merge_altname(existing.aliases, rg.altname)
            skipped += 1
            continue
        group = Group(
            group_name=rg.name,
            description=rg.description or None,
            is_hacktivist=is_hacktivist_description(rg.description),
            url=rg.url or None,
            meta=rg.meta or None,
            aliases=json.dumps([rg.altname]) if rg.altname else None,
            source_id=source_id,
        )
        # Savepoint-guard the insert: a concurrent writer (or web /refresh
        # overlapping the scheduler) may insert the same group_name between the
        # dedup check above and this flush. Absorb the unique-violation so one
        # collision can't roll back the whole multi-minute cycle.
        try:
            with session.begin_nested():
                session.add(group)
                session.flush()
        except IntegrityError:
            existing = session.query(Group).filter_by(group_name=rg.name).first()
            if existing and rg.altname:
                existing.aliases = _merge_altname(existing.aliases, rg.altname)
            skipped += 1
            continue

        for loc in rg.locations:
            gl = GroupLocation(
                group_id=group.id,
                fqdn=loc.get("fqdn"),
                slug=loc.get("slug"),
                title=loc.get("title"),
                type=loc.get("type"),
                available=loc.get("available"),
                enabled=loc.get("enabled"),
            )
            session.add(gl)

        added += 1
    return added, skipped


def _enrich_group_from_detail(session: Session, group: Group, detail: dict, source_id: int) -> None:
    """Enrich a group record with data from the detail endpoint."""
    # Update structured fields (API returns mixed types — normalize to strings)
    raw_type = detail.get("type")
    if isinstance(raw_type, dict):
        # e.g. {"raas": False} → extract keys where value is truthy, or store as JSON
        group.group_type = json.dumps(raw_type)
    elif raw_type:
        group.group_type = str(raw_type)

    raw_ext = detail.get("extensions")
    if isinstance(raw_ext, list):
        group.extensions = json.dumps(raw_ext)
    elif raw_ext:
        group.extensions = str(raw_ext)

    raw_lin = detail.get("lineage")
    if isinstance(raw_lin, list):
        group.lineage = json.dumps(raw_lin)
    elif raw_lin:
        group.lineage = str(raw_lin)

    btc = detail.get("btc_address")
    if isinstance(btc, list):
        group.btc_addresses = json.dumps(btc)
    elif btc:
        group.btc_addresses = str(btc)

    # Update description/meta if richer than current
    desc = detail.get("description")
    if desc and (not group.description or len(desc) > len(group.description)):
        group.description = desc
        group.is_hacktivist = is_hacktivist_description(desc)

    meta = detail.get("meta")
    if meta:
        group.meta = meta if isinstance(meta, str) else json.dumps(meta)

    # Update locations from detail (fresher data)
    detail_locs = detail.get("locations") or []
    if detail_locs:
        session.query(GroupLocation).filter_by(group_id=group.id).delete()
        for loc in detail_locs:
            session.add(
                GroupLocation(
                    group_id=group.id,
                    fqdn=loc.get("fqdn"),
                    slug=loc.get("slug"),
                    title=loc.get("title"),
                    type=loc.get("type"),
                    available=loc.get("available"),
                    enabled=loc.get("enabled"),
                )
            )

    # Save profile URLs as references
    profile = detail.get("profile")
    if profile:
        urls = []
        if isinstance(profile, list):
            urls = profile
        elif isinstance(profile, str):
            urls = [profile]
        cleaned: list[str] = []
        for raw_url in urls:
            # Profile entries can be markdown links: [text](url) or plain URLs
            url = raw_url.strip()
            if "](" in url:
                url = url.split("](", 1)[1].rstrip(")")
            if not url.startswith("http"):
                continue
            cleaned.append(url)
            existing_ref = (
                session.query(GroupReference).filter_by(group_id=group.id, url=url).first()
            )
            if not existing_ref:
                session.add(GroupReference(group_id=group.id, url=url))
        # Store the cleaned URLs, not the raw markdown — templates render this
        # field directly (HI-04).
        group.profile_urls = json.dumps(cleaned) if cleaned else None

    # Save raw JSON as attributed evidence; previous version is archived
    # to group_source_history when the content changed
    upsert_source_evidence(session, group.group_name, source_id, json.dumps(detail, default=str))


def _ingest_victims(
    session: Session, raw_victims: list[RawVictim], source_id: int
) -> tuple[int, int]:
    added = 0
    skipped = 0
    for rv in raw_victims:
        domain_val = rv.domain or None
        attackdate_val = rv.attackdate
        existing = (
            session.query(Victim)
            .filter(
                Victim.domain.is_(None) if domain_val is None else Victim.domain == domain_val,
                Victim.attackdate.is_(None)
                if attackdate_val is None
                else Victim.attackdate == attackdate_val,
            )
            .first()
        )
        if existing:
            if existing.source_id != source_id:
                dup = VictimDuplicate(
                    victim_id=existing.id,
                    dup_attackdate=rv.attackdate,
                    dup_group=rv.group,
                )
                session.add(dup)
            skipped += 1
            continue

        country = _get_or_create_country(session, rv.country)
        group = _get_or_create_group(session, rv.group, source_id)

        victim = Victim(
            victim_name=rv.victim_name,
            domain=domain_val,
            group_id=group.id if group else None,
            country_id=country.id if country else None,
            attackdate=attackdate_val,
            discovered=rv.discovered,
            claim_url=rv.claim_url or None,
            screenshot=rv.screenshot or None,
            url=rv.url or None,
            activity=rv.activity or None,
            description=rv.description or None,
            source_id=source_id,
        )
        session.add(victim)
        session.flush()
        added += 1

    return added, skipped


def _ingest_cyberattacks(
    session: Session, raw_attacks: list[RawCyberattack], source_id: int
) -> tuple[int, int]:
    added = 0
    skipped = 0
    for ra in raw_attacks:
        attack_date_val = ra.attack_date
        existing = (
            session.query(Cyberattack)
            .filter(
                Cyberattack.victim_name == ra.victim_name,
                Cyberattack.attack_date.is_(None)
                if attack_date_val is None
                else Cyberattack.attack_date == attack_date_val,
            )
            .first()
        )
        if existing:
            skipped += 1
            continue

        attack = Cyberattack(
            victim_name=ra.victim_name,
            domain=ra.domain or None,
            country=ra.country or None,
            attack_date=attack_date_val,
            added=ra.added,
            discovered=ra.discovered,
            title=ra.title or None,
            summary=ra.summary or None,
            article_url=ra.article_url or None,
            source_id=source_id,
        )
        session.add(attack)
        session.flush()
        added += 1

    return added, skipped


async def ingest_source(session: Session, source: BaseSource) -> IngestResult:
    t0 = time.monotonic()
    result = IngestResult(source=source.source_name, errors=[])
    ds = _get_or_create_source(session, source.source_name)

    for endpoint, fetcher, ingestor in [
        ("groups", source.fetch_groups, lambda raw: _ingest_groups(session, raw, ds.id)),
        ("victims", source.fetch_victims, lambda raw: _ingest_victims(session, raw, ds.id)),
        (
            "cyberattacks",
            source.fetch_cyberattacks,
            lambda raw: _ingest_cyberattacks(session, raw, ds.id),
        ),
    ]:
        try:
            raw = await fetcher()
            added, skipped = ingestor(raw)
            setattr(result, f"{endpoint}_added", added)
            setattr(result, f"{endpoint}_skipped", skipped)
            logger.debug(
                "Fetched %s/%s: %d records",
                source.source_name,
                endpoint,
                len(raw),
                extra={
                    "source": source.source_name,
                    "endpoint": endpoint,
                    "record_count": len(raw),
                },
            )
            session.flush()
        except SourceError as exc:
            logger.warning(
                "Failed to fetch %s from %s: %s",
                endpoint,
                source.source_name,
                exc,
                extra={
                    "source": source.source_name,
                    "endpoint": endpoint,
                    "error_type": type(exc).__name__,
                },
            )
            result.errors.append(f"{endpoint}: {exc}")

    # Enrich groups with detail endpoint data (skip recently enriched, rate-limit safe)
    if hasattr(source, "fetch_group_detail"):
        try:
            all_groups = session.query(Group).filter_by(source_id=ds.id).all()
            # Find groups already enriched in last 24h
            cutoff = datetime.now(UTC) - timedelta(hours=24)
            fresh = set(
                row.group_name
                for row in session.query(GroupSourceData.group_name)
                .filter(
                    GroupSourceData.source_id == ds.id,
                    GroupSourceData.fetched_at >= cutoff,
                )
                .all()
            )
            stale_groups = [g for g in all_groups if g.group_name not in fresh]
            enriched = 0
            for group in stale_groups:
                try:
                    detail = await source.fetch_group_detail(group.group_name)
                    if detail:
                        _enrich_group_from_detail(session, group, detail, ds.id)
                        enriched += 1
                        session.flush()
                except Exception as exc:
                    logger.debug("Detail enrichment failed for %s: %s", group.group_name, exc)
                    session.rollback()
                # Rate limit: 2s between calls
                await asyncio.sleep(2)
            logger.info(
                "Enriched %d/%d groups from %s detail endpoint (%d skipped, fresh)",
                enriched,
                len(stale_groups),
                source.source_name,
                len(fresh),
            )
        except Exception as exc:
            logger.warning(
                "Group detail enrichment failed for %s: %s",
                source.source_name,
                exc,
            )
            result.errors.append(f"group_detail: {exc}")

    session.commit()
    duration = round(time.monotonic() - t0, 2)
    logger.info(
        "Ingestion from %s: +%d victims, +%d groups, +%d attacks (%.2fs)",
        source.source_name,
        result.victims_added,
        result.groups_added,
        result.cyberattacks_added,
        duration,
        extra={
            "source": source.source_name,
            "record_count": result.victims_added + result.groups_added + result.cyberattacks_added,
            "duration_s": duration,
        },
    )
    return result


# "Come at once if convenient. If inconvenient, come all the same." — Sherlock
async def run_ingestion(
    session: Session, source_names: list[str] | None = None
) -> list[IngestResult]:
    results = []
    sources = source_names or list(SOURCES.keys())

    for name in sources:
        if name not in SOURCES:
            logger.error("Unknown source: %s", name)
            continue

        source = SOURCES[name]()
        try:
            result = await ingest_source(session, source)
            results.append(result)
        finally:
            await source.close()

    return results
