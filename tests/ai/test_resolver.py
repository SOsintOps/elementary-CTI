# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""The deterministic name-to-Group resolver (Phase 5, step 5).

Roadmap criterion 3. The tests that matter most are the ones proving what the
resolver refuses to do: two existing groups are never merged, and an ambiguous
fuzzy hit resolves to neither rather than to the first one found.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.enrichment.resolver import Resolution, resolve
from pestilentia.models.base import Base
from pestilentia.models.tables import Article, ArticleSource, Group, GroupAliasProposal


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        yield db


def _group(session, name: str) -> Group:
    row = Group(group_name=name)
    session.add(row)
    session.commit()
    return row


def _article(session) -> Article:
    session.add(ArticleSource(id=1, name="feed", url="https://feed.test"))
    row = Article(
        id=1, source_id=1, url="https://a.test/1", url_canonical_hash="h1", title="t", body="b"
    )
    session.add(row)
    session.commit()
    return row


# --- the four steps, in order ------------------------------------------------


def test_an_exact_name_resolves_exactly(session):
    akira = _group(session, "Akira")

    result = resolve(session, "Akira")

    assert result.group is akira
    assert result.how is Resolution.EXACT


@pytest.mark.parametrize("written", ["akira", "  Akira  ", "AKIRA", "A k i r a".replace(" ", "")])
def test_the_articles_own_spacing_and_case_do_not_defeat_an_exact_match(session, written):
    akira = _group(session, "Akira")

    assert resolve(session, written).group is akira


def test_an_approved_alias_resolves_to_its_group(session):
    akira = _group(session, "Akira")
    _article(session)
    session.add(
        GroupAliasProposal(
            group_id=akira.id, article_id=1, proposed_alias="Storm-1567", status="approved"
        )
    )
    session.commit()

    result = resolve(session, "Storm-1567")

    assert result.group is akira
    assert result.how is Resolution.ALIAS


def test_a_pending_alias_does_not_resolve_anything(session):
    """A proposal is a suggestion nobody accepted. Resolving through one would
    let the AI's own unreviewed guess become the route by which its next guess
    is attached to a group, which is the alias-safety rule defeated by a side
    door rather than by the front one."""
    akira = _group(session, "Akira")
    _article(session)
    session.add(
        GroupAliasProposal(
            group_id=akira.id, article_id=1, proposed_alias="Howling Scorpius", status="pending"
        )
    )
    session.commit()

    result = resolve(session, "Howling Scorpius", create=False)

    assert result.group is None
    assert result.how is not Resolution.ALIAS


def test_a_near_miss_resolves_by_fuzzy_match(session):
    lockbit = _group(session, "LockBit")

    result = resolve(session, "Lockbit3")

    assert result.group is lockbit
    assert result.how is Resolution.FUZZY
    assert result.score >= 85


def test_a_name_nobody_holds_creates_a_group(session):
    result = resolve(session, "Gunra")

    assert result.how is Resolution.CREATED
    assert result.group.group_name == "Gunra"
    assert session.query(Group).count() == 1


def test_the_created_name_is_the_articles_own_wording_trimmed_only(session):
    result = resolve(session, "  Gunra  ")

    assert result.group.group_name == "Gunra"


# --- what it refuses to do ---------------------------------------------------


def test_two_existing_groups_are_never_merged_on_any_path(session):
    """Criterion 3's hard rule. A merge cannot be undone by rewriting a field:
    the rows that were folded together no longer exist to be separated."""
    first = _group(session, "Akira")
    second = _group(session, "Akira Group")

    for written in ("Akira", "Akira Group", "Akira  Group", "AKIRA"):
        result = resolve(session, written, create=False)
        assert result.group in (first, second, None)

    assert session.query(Group).count() == 2, "no path may delete or fold a group"


def test_two_names_differing_only_in_spacing_are_ambiguous_at_the_exact_step(session):
    """Found by this test before it was found in production.

    `group_name` is unique as stored, which does not stop "DarkSide" and
    "DarkSide " from both existing. A LIMIT 1 on the exact step picked between
    them by whatever order the database felt like: an accidental merge arrived
    at through the one step nobody suspects, because "exact match" sounds like
    it cannot be ambiguous.
    """
    _group(session, "DarkSide")
    _group(session, "DarkSide ")

    result = resolve(session, "Darkside", create=False)

    assert result.group is None
    assert result.how is Resolution.AMBIGUOUS
    assert len(result.candidates) == 2


def test_an_ambiguous_fuzzy_hit_resolves_to_neither(session):
    """Two candidates scoring the same is exactly how a merge gets made by
    accident, and the row that results looks true. Picking the first one found
    would make the answer depend on insertion order."""
    _group(session, "Blackcat")
    _group(session, "Blackcet")

    result = resolve(session, "Blackcut", create=False)

    assert result.group is None
    assert result.how is Resolution.AMBIGUOUS
    assert len(result.candidates) == 2


def test_one_alias_approved_onto_two_groups_resolves_to_neither(session):
    """A curation error, and resolving it either way would launder that error
    into the adversary tables where it stops looking like an error."""
    first = _group(session, "Akira")
    second = _group(session, "Storm-1567")
    _article(session)
    for group in (first, second):
        session.add(
            GroupAliasProposal(
                group_id=group.id, article_id=1, proposed_alias="Howling", status="approved"
            )
        )
    session.commit()

    result = resolve(session, "Howling", create=False)

    assert result.group is None
    assert result.how is Resolution.AMBIGUOUS


def test_an_ambiguous_result_names_the_candidates_for_a_reviewer(session):
    _group(session, "Cl0p")
    _group(session, "Cl0p ")

    result = resolve(session, "cl0p", create=False)

    assert result.candidates == tuple(sorted(result.candidates)), (
        "stable order, not insertion order"
    )


def test_a_distant_name_does_not_fuzzy_match_something_unrelated(session):
    _group(session, "LockBit")

    result = resolve(session, "Qilin", create=False)

    assert result.group is None
    assert result.how is Resolution.REFUSED


def test_the_threshold_is_the_threshold(session):
    _group(session, "LockBit")

    assert resolve(session, "LockBot", threshold=100, create=False).group is None
    assert resolve(session, "LockBot", threshold=50, create=False).group is not None


@pytest.mark.parametrize("empty", ["", "   ", "\n"])
def test_an_empty_name_is_refused_rather_than_creating_a_nameless_group(session, empty):
    result = resolve(session, empty)

    assert result.how is Resolution.REFUSED
    assert session.query(Group).count() == 0


def test_asking_without_creating_never_writes(session):
    """The caller deciding whether a finding is worth enriching must be able to
    ask the question without answering it."""
    resolve(session, "Nobody Has Heard Of This", create=False)

    assert session.query(Group).count() == 0


def test_resolving_twice_returns_the_same_group_rather_than_a_second_one(session):
    """Idempotence, which the gate needs because it runs again on a re-analysis."""
    first = resolve(session, "Gunra")
    session.commit()
    second = resolve(session, "Gunra")

    assert second.group.id == first.group.id
    assert second.how is Resolution.EXACT
    assert session.query(Group).count() == 1
