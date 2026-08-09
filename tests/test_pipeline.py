from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pestilentia.clients.base import BaseSource, SourceError
from pestilentia.clients.schemas import RawCyberattack, RawGroup, RawVictim
from pestilentia.models import Base, Cyberattack, Group, Victim, VictimDuplicate
from pestilentia.pipeline.ingest import ingest_source


class FakeSource(BaseSource):
    source_name = "fake"

    def __init__(self, victims=None, groups=None, attacks=None, fail_on=None):
        self._victims = victims or []
        self._groups = groups or []
        self._attacks = attacks or []
        self._fail_on = fail_on or set()

    async def fetch_victims(self) -> list[RawVictim]:
        if "victims" in self._fail_on:
            raise SourceError("fake", "victims fetch failed")
        return self._victims

    async def fetch_groups(self) -> list[RawGroup]:
        if "groups" in self._fail_on:
            raise SourceError("fake", "groups fetch failed")
        return self._groups

    async def fetch_cyberattacks(self) -> list[RawCyberattack]:
        if "attacks" in self._fail_on:
            raise SourceError("fake", "attacks fetch failed")
        return self._attacks

    async def close(self) -> None:
        pass


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


VICTIMS = [
    RawVictim(
        victim_name="acme-corp",
        group="lockbit",
        domain="acme.com",
        country="US",
        attackdate=datetime(2026, 1, 15),
        source="fake",
    ),
    RawVictim(
        victim_name="globex",
        group="blackcat",
        domain="globex.com",
        country="DE",
        attackdate=datetime(2026, 2, 1),
        source="fake",
    ),
]

GROUPS = [
    RawGroup(
        name="lockbit",
        description="Ransomware group",
        locations=[{"fqdn": "lockbit.onion", "title": "DLS", "type": "DLS"}],
        source="fake",
    ),
]

ATTACKS = [
    RawCyberattack(
        victim_name="globex",
        domain="globex.com",
        country="DE",
        attack_date=datetime(2026, 2, 1),
        title="Globex hit",
        source="fake",
    ),
]


@pytest.mark.anyio
async def test_ingest_victims(session):
    source = FakeSource(victims=VICTIMS, groups=GROUPS)
    result = await ingest_source(session, source)

    assert result.victims_added == 2
    assert result.victims_skipped == 0
    assert result.groups_added == 1
    assert session.query(Victim).count() == 2
    assert session.query(Group).count() == 2


@pytest.mark.anyio
async def test_ingest_cyberattacks(session):
    source = FakeSource(attacks=ATTACKS)
    result = await ingest_source(session, source)

    assert result.cyberattacks_added == 1
    assert session.query(Cyberattack).count() == 1


@pytest.mark.anyio
async def test_no_duplicates_on_rerun(session):
    source = FakeSource(victims=VICTIMS, groups=GROUPS)
    await ingest_source(session, source)
    result = await ingest_source(session, source)

    assert result.victims_added == 0
    assert result.victims_skipped == 2
    assert result.groups_added == 0
    assert result.groups_skipped == 1
    assert session.query(Victim).count() == 2


@pytest.mark.anyio
async def test_cross_source_duplicate_tracked(session):
    source1 = FakeSource(victims=VICTIMS[:1])
    source1.source_name = "source_a"
    await ingest_source(session, source1)

    same_victim = [
        RawVictim(
            victim_name="acme-corp",
            group="lockbit",
            domain="acme.com",
            country="US",
            attackdate=datetime(2026, 1, 15),
            source="source_b",
        )
    ]
    source2 = FakeSource(victims=same_victim)
    source2.source_name = "source_b"
    result = await ingest_source(session, source2)

    assert result.victims_skipped == 1
    assert session.query(VictimDuplicate).count() == 1


@pytest.mark.anyio
async def test_partial_failure_still_stores(session):
    source = FakeSource(victims=VICTIMS, attacks=ATTACKS, fail_on={"groups"})
    result = await ingest_source(session, source)

    assert result.victims_added == 2
    assert result.cyberattacks_added == 1
    assert len(result.errors) == 1
    assert "groups" in result.errors[0]


@pytest.mark.anyio
async def test_empty_source(session):
    source = FakeSource()
    result = await ingest_source(session, source)

    assert result.victims_added == 0
    assert result.groups_added == 0
    assert result.cyberattacks_added == 0
    assert len(result.errors) == 0
