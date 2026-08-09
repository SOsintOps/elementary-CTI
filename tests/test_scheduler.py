from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pestilentia.clients.base import BaseSource
from pestilentia.clients.registry import SOURCES
from pestilentia.clients.schemas import RawCyberattack, RawGroup, RawVictim
from pestilentia.models import Base, Victim
from pestilentia.pipeline.backfill import mark_backfill_done
from pestilentia.pipeline.scheduler import _run_cycle


class SchedulerTestSource(BaseSource):
    source_name = "scheduler_test"

    async def fetch_victims(self) -> list[RawVictim]:
        return [
            RawVictim(
                victim_name="sched-victim",
                group="sched-group",
                domain="sched.com",
                attackdate=datetime(2026, 1, 1),
                source="scheduler_test",
            ),
        ]

    async def fetch_groups(self) -> list[RawGroup]:
        return []

    async def fetch_cyberattacks(self) -> list[RawCyberattack]:
        return []

    async def fetch_all_victims(self, year: int, month: int | None = None) -> list[RawVictim]:
        return []

    async def fetch_all_cyberattacks(self) -> list[RawCyberattack]:
        return []

    async def close(self) -> None:
        pass


@pytest.fixture
def sf():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture(autouse=True)
def _register_source():
    SOURCES["scheduler_test"] = SchedulerTestSource
    yield
    SOURCES.pop("scheduler_test", None)


@pytest.mark.anyio
async def test_run_cycle_triggers_backfill_then_incremental(sf):
    # First cycle: backfill (no backfill_done marker)
    await _run_cycle(sf, "scheduler_test")

    with sf() as session:
        # After backfill, mark done to test incremental path
        mark_backfill_done(session, "scheduler_test")

    # Second cycle: incremental
    await _run_cycle(sf, "scheduler_test")

    with sf() as session:
        victims = session.query(Victim).all()
        assert len(victims) == 1
        assert victims[0].victim_name == "sched-victim"


@pytest.mark.anyio
async def test_run_cycle_unknown_source(sf, caplog):
    await _run_cycle(sf, "nonexistent_source")
    assert "Unknown source" in caplog.text
