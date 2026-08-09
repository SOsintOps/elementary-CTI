from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pestilentia.clients.base import BaseSource, SourceError
from pestilentia.clients.schemas import RawCyberattack, RawGroup, RawVictim
from pestilentia.models import Base, Victim
from pestilentia.pipeline.backfill import is_backfill_done, run_backfill


class BackfillSource(BaseSource):
    source_name = "backfill_test"

    def __init__(self):
        self._victims_by_year = {
            2024: [
                RawVictim(
                    victim_name="victim-2024",
                    group="group-a",
                    domain="v2024.com",
                    attackdate=datetime(2024, 6, 15),
                    source="backfill_test",
                ),
            ],
            2025: [
                RawVictim(
                    victim_name="victim-2025",
                    group="group-b",
                    domain="v2025.com",
                    attackdate=datetime(2025, 3, 1),
                    source="backfill_test",
                ),
            ],
        }
        self._fail_year = None

    async def fetch_victims(self) -> list[RawVictim]:
        return []

    async def fetch_groups(self) -> list[RawGroup]:
        return [RawGroup(name="group-a", source="backfill_test")]

    async def fetch_cyberattacks(self) -> list[RawCyberattack]:
        return [
            RawCyberattack(
                victim_name="attack-victim",
                attack_date=datetime(2025, 1, 1),
                source="backfill_test",
            ),
        ]

    async def fetch_all_victims(self, year: int, month: int | None = None) -> list[RawVictim]:
        if year == self._fail_year:
            raise SourceError("backfill_test", f"Failed for {year}")
        return self._victims_by_year.get(year, [])

    async def fetch_all_cyberattacks(self) -> list[RawCyberattack]:
        return await self.fetch_cyberattacks()

    async def close(self) -> None:
        pass


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.mark.anyio
async def test_backfill_stores_historical_victims(session):
    source = BackfillSource()
    await run_backfill(session, source)

    victims = session.query(Victim).all()
    names = {v.victim_name for v in victims}
    assert "victim-2024" in names
    assert "victim-2025" in names


@pytest.mark.anyio
async def test_backfill_marks_complete(session):
    source = BackfillSource()
    assert not is_backfill_done(session, "backfill_test")

    await run_backfill(session, source)
    assert is_backfill_done(session, "backfill_test")


@pytest.mark.anyio
async def test_backfill_resumes_after_failure(session):
    source = BackfillSource()
    source._fail_year = 2025
    await run_backfill(session, source)

    victims = session.query(Victim).all()
    names = {v.victim_name for v in victims}
    assert "victim-2024" in names
    assert "victim-2025" not in names


@pytest.mark.anyio
async def test_backfill_skips_completed_years(session):
    source = BackfillSource()
    await run_backfill(session, source)

    count_before = session.query(Victim).count()
    await run_backfill(session, source)
    count_after = session.query(Victim).count()

    assert count_before == count_after
