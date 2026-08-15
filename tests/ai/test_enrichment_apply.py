# "Never trust to general impressions, but concentrate yourself on details."
"""The audited write and its inverse (Phase 5, steps 6 and 7).

Criteria 4 and 5. The alias tests carry the most weight, because a wrong alias
is the only failure here that leaves no trace: it merges two adversaries in the
reader's mind without a single questionable row appearing anywhere.
"""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.enrichment.apply import (
    CORROBORATION_REQUIRED,
    ENRICH_ACTION,
    NEGATIVE_ALIASES,
    REVERT_ACTION,
    apply_enrichment,
)
from pestilentia.ai.enrichment.revert import NotRevertibleError, revert_article, revert_audit_row
from pestilentia.models.base import Base
from pestilentia.models.tables import (
    AiEnrichmentAudit,
    Article,
    ArticleSource,
    Group,
    GroupAliasProposal,
    StagedFinding,
)


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        yield db


def _setup(session, *, aliases=None, country=None) -> tuple[Group, Article]:
    session.add(ArticleSource(id=1, name="feed-1", url="https://feed1.test"))
    session.add(ArticleSource(id=2, name="feed-2", url="https://feed2.test"))
    article = Article(
        id=1, source_id=1, url="https://a.test/1", url_canonical_hash="h1", title="t", body="b"
    )
    group = Group(group_name="Akira", aliases=aliases, country_of_origin=country)
    session.add_all([article, group])
    session.commit()
    return group, article


def _enrich(session, group, article, values, **kwargs):
    defaults = {"model_name": "llama-70b", "confidence": 0.91, "tlp": "clear"}
    return apply_enrichment(
        session, group=group, article=article, values=values, **{**defaults, **kwargs}
    )


def _corroborate(session, kind, target_row_id, value, source_ids):
    """Give the record N independent feeds that already proposed `value`."""
    for index, source_id in enumerate(source_ids, start=10):
        session.add(
            Article(
                id=index,
                source_id=source_id,
                url=f"https://a.test/{index}",
                url_canonical_hash=f"h{index}",
                title="t",
                body="b",
            )
        )
        session.add(
            StagedFinding(
                article_id=index,
                finding_kind=kind,
                target_row_id=target_row_id,
                payload_json={"value": value},
                score_raw=0.9,
                source_grade="B",
                source_factor_applied=0.9,
                info_grade="3",
                info_factor_applied=0.75,
                threshold_applied=0.85,
                score_total=0.9,
                decision="auto",
                tlp="clear",
            )
        )
    session.commit()


# --- criterion 4: the alias rules --------------------------------------------


def test_an_ai_alias_is_a_proposal_and_never_a_write(session):
    """Whatever the score. `Group.aliases` is only ever changed by a person."""
    group, article = _setup(session)

    result = _enrich(session, group, article, {"aliases": ["Storm-1567"]}, confidence=1.0)
    session.commit()

    assert group.aliases is None, "the AI wrote directly onto the group"
    assert session.query(GroupAliasProposal).count() == 1
    assert result.proposals[0].status == "pending"


def test_an_alias_on_the_negative_list_is_blocked_before_a_human_is_asked(session):
    group, article = _setup(session)
    blocked = sorted(NEGATIVE_ALIASES)[0]

    result = _enrich(session, group, article, {"aliases": [blocked, "Storm-1567"]})
    session.commit()

    proposed = {row.proposed_alias for row in session.query(GroupAliasProposal)}
    assert blocked not in proposed
    assert "Storm-1567" in proposed
    assert f"alias:{blocked}" in result.withheld


def test_the_negative_list_matches_regardless_of_case(session):
    group, article = _setup(session)

    _enrich(session, group, article, {"aliases": ["UNKNOWN", "Ransomware"]})
    session.commit()

    assert session.query(GroupAliasProposal).count() == 0


def test_an_alias_equal_to_the_group_name_is_not_proposed(session):
    """It says nothing, and a reviewer's time is the scarce resource here."""
    group, article = _setup(session)

    _enrich(session, group, article, {"aliases": ["akira", "Akira"]})
    session.commit()

    assert session.query(GroupAliasProposal).count() == 0


def test_an_alias_already_proposed_is_not_proposed_again(session):
    """Idempotence. The gate runs again on a re-analysis, and a queue that grew
    a duplicate on every pass would stop being reviewable."""
    group, article = _setup(session)

    _enrich(session, group, article, {"aliases": ["Storm-1567"]})
    session.commit()
    _enrich(session, group, article, {"aliases": ["Storm-1567"]})
    session.commit()

    assert session.query(GroupAliasProposal).count() == 1


def test_an_alias_the_group_already_holds_is_not_proposed(session):
    group, article = _setup(session, aliases=json.dumps(["Storm-1567"]))

    _enrich(session, group, article, {"aliases": ["storm-1567"]})
    session.commit()

    assert session.query(GroupAliasProposal).count() == 0


# --- criterion 4: corroboration on high-impact fields ------------------------


def test_a_country_from_one_source_waits_for_a_second(session):
    """One article is one article. Country and lineage change what an analyst
    believes about who is behind something."""
    group, article = _setup(session)

    result = _enrich(session, group, article, {"country_of_origin": "RU"})
    session.commit()

    assert group.country_of_origin is None
    assert "country_of_origin" in result.withheld
    assert f"of {CORROBORATION_REQUIRED}" in result.withheld["country_of_origin"]


def test_a_country_two_independent_feeds_agree_on_is_written(session):
    group, article = _setup(session)
    _corroborate(session, "country_of_origin", group.id, "RU", source_ids=[1, 2])

    result = _enrich(session, group, article, {"country_of_origin": "RU"})
    session.commit()

    assert group.country_of_origin == "RU"
    assert "country_of_origin" not in result.withheld


def test_two_articles_from_one_feed_do_not_corroborate_each_other(session):
    """Counted over distinct feeds, not articles: the same syndication trap the
    information axis avoids."""
    group, article = _setup(session)
    _corroborate(session, "country_of_origin", group.id, "RU", source_ids=[1, 1])

    _enrich(session, group, article, {"country_of_origin": "RU"})
    session.commit()

    assert group.country_of_origin is None


def test_an_ordinary_field_needs_no_corroboration(session):
    """The rule is aimed at attribution, not at everything. A profile URL that
    turns out wrong is a bad link; a wrong country is a wrong adversary."""
    group, article = _setup(session)

    _enrich(session, group, article, {"profile_urls": ["https://leak.example/akira"]})
    session.commit()

    assert json.loads(group.profile_urls) == ["https://leak.example/akira"]


# --- append, never replace ---------------------------------------------------


def test_a_new_value_is_appended_and_what_was_there_survives(session):
    group, article = _setup(session)
    group.btc_addresses = json.dumps(["bc1old"])
    session.commit()

    _enrich(session, group, article, {"btc_addresses": ["bc1new"]})
    session.commit()

    assert json.loads(group.btc_addresses) == ["bc1old", "bc1new"]


def test_a_duplicate_is_not_appended_and_writes_no_audit_row(session):
    group, article = _setup(session)
    group.profile_urls = json.dumps(["https://leak.example/akira"])
    session.commit()

    result = _enrich(session, group, article, {"profile_urls": ["https://leak.example/akira"]})
    session.commit()

    assert json.loads(group.profile_urls) == ["https://leak.example/akira"]
    assert result.audit_rows == []


def test_an_unreadable_array_is_refused_rather_than_overwritten(session):
    """Treating it as empty and appending would write a list that discards its
    own history, which is exactly the deletion the append-only rule forbids."""
    group, article = _setup(session)
    group.btc_addresses = "not json at all"
    session.commit()

    result = _enrich(session, group, article, {"btc_addresses": ["bc1new"]})
    session.commit()

    assert group.btc_addresses == "not json at all"
    assert "btc_addresses" in result.withheld


# --- criterion 5: one audit row per field, same transaction ------------------


def test_every_changed_field_gets_its_own_audit_row(session):
    group, article = _setup(session)

    _enrich(session, group, article, {"profile_urls": ["https://a"], "description": "an operator"})
    session.commit()

    rows = session.query(AiEnrichmentAudit).all()
    assert len(rows) == 2
    assert {row.after_json["field"] for row in rows} == {"profile_urls", "description"}


def test_an_audit_row_carries_the_article_the_model_and_the_tlp_at_the_time(session):
    group, article = _setup(session)

    _enrich(session, group, article, {"description": "an operator"})
    session.commit()

    row = session.query(AiEnrichmentAudit).one()
    assert row.article_id == article.id
    assert row.model_name == "llama-70b"
    assert row.confidence == 0.91
    assert row.tlp == "clear"
    assert row.action == ENRICH_ACTION


def test_the_audit_action_does_not_collide_with_the_tlp_override_vocabulary(session):
    """The two share the table. audit.py writes confidence=1.0 as a sentinel for
    a human decision, and no Phase 5 statistic may average that into model
    confidence: telling them apart by action is how."""
    from pestilentia.ai.audit import OVERRIDE_ACTION

    assert ENRICH_ACTION != OVERRIDE_ACTION
    assert REVERT_ACTION != OVERRIDE_ACTION


def test_a_rolled_back_change_takes_its_audit_row_with_it(session):
    """An audit row that survived a rolled-back change would be a record of
    something that never happened, which is worse than no record."""
    group, article = _setup(session)

    _enrich(session, group, article, {"description": "an operator"})
    session.rollback()

    assert session.query(AiEnrichmentAudit).count() == 0
    assert session.get(Group, group.id).description is None


# --- criterion 5: the inverse ------------------------------------------------


def test_enrich_then_revert_restores_the_field_exactly(session):
    """The inverse test the criterion asks for, on a real delta rather than a
    fixture: the state after reverting is the state before enriching."""
    group, article = _setup(session)
    group.btc_addresses = json.dumps(["bc1old"])
    group.description = "what was there before"
    session.commit()
    before = (group.btc_addresses, group.description)

    _enrich(session, group, article, {"btc_addresses": ["bc1new"], "description": "rewritten"})
    session.commit()
    assert (group.btc_addresses, group.description) != before

    revert_article(session, article.id, actor="rosse")
    session.commit()

    assert (group.btc_addresses, group.description) == before


def test_reverting_a_field_written_twice_goes_back_to_the_first_state(session):
    """Newest first. Replaying the older `before` last would restore the state
    before the first write, which is the one a reviewer undoing this means."""
    group, article = _setup(session)
    group.description = "original"
    session.commit()

    _enrich(session, group, article, {"description": "first pass"})
    session.commit()
    _enrich(session, group, article, {"description": "second pass"})
    session.commit()

    revert_article(session, article.id, actor="rosse")
    session.commit()

    assert group.description == "original"


def test_the_revert_is_itself_audited_rather_than_erasing_the_history(session):
    """Deleting the enrichment row would make the database agree with itself
    about a past that did not happen."""
    group, article = _setup(session)

    _enrich(session, group, article, {"description": "an operator"})
    session.commit()
    revert_article(session, article.id, actor="rosse")
    session.commit()

    actions = [
        row.action for row in session.query(AiEnrichmentAudit).order_by(AiEnrichmentAudit.id)
    ]
    assert actions == [ENRICH_ACTION, REVERT_ACTION]
    assert (
        session.query(AiEnrichmentAudit).filter_by(action=REVERT_ACTION).one().decided_by == "rosse"
    )


def test_reverting_a_row_this_module_did_not_write_is_refused_not_skipped(session):
    """A revert that quietly did nothing would report success on a change still
    in the database, and the caller could not tell that apart from a real undo."""
    group, article = _setup(session)
    row = AiEnrichmentAudit(
        article_id=article.id,
        table_name="groups",
        row_id=group.id,
        action="tlp_override",
        before_json={"field": "description", "value": None},
        after_json={"field": "description", "value": "x"},
        model_name="m",
        confidence=1.0,
        tlp="clear",
        decision="override",
    )
    session.add(row)
    session.commit()

    with pytest.raises(NotRevertibleError):
        revert_audit_row(session, row, actor="rosse")


def test_reverting_when_the_group_is_gone_is_refused(session):
    group, article = _setup(session)
    _enrich(session, group, article, {"description": "an operator"})
    session.commit()
    row = session.query(AiEnrichmentAudit).one()
    session.delete(group)
    session.commit()

    with pytest.raises(NotRevertibleError):
        revert_audit_row(session, row, actor="rosse")
