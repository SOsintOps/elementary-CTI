# "The world is full of obvious things which nobody by any chance ever observes."
"""The gate end to end, on rows rather than on mocks (Phase 5, step 8).

No provider is involved and none should be: the gate makes no model calls, and
a test that needed one would be testing the wrong thing. What is under test is
that a real finding comes out of the machine's own rows with four components, a
grade on each axis, a threshold and a decision, and that running it twice
changes nothing.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.enrichment.gate import run_gate
from pestilentia.config import Settings
from pestilentia.models.base import Base
from pestilentia.models.tables import (
    AiEnrichmentAudit,
    Article,
    ArticleAnalysisRun,
    ArticleIoc,
    ArticleSource,
    ArticleTtp,
    Group,
    GroupAliasProposal,
    StagedFinding,
)

CONFIG = Settings()


@pytest.fixture(autouse=True)
def published_space(monkeypatch):
    """The exclusion feeds, supplied rather than inherited from the disk.

    Found by the isolated gate in the distributable, where the feeds are not
    fetched: without this the enrichment tests passed on the machine that had
    downloaded them and failed everywhere else. A unit test that reads what
    happens to be in `data/` is not testing the gate, it is testing the
    developer's afternoon.
    """
    from pestilentia.ai.enrichment import gate as gate_module

    gate_module._rented_space.cache_clear()
    monkeypatch.setattr(gate_module, "load_address_ranges", lambda: ("192.0.2.0/24",))
    yield
    gate_module._rented_space.cache_clear()


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        yield db


def _article(session, *, grade="A", quality="high", verify_status="ok", kept=29, rejected=6):
    source = ArticleSource(id=1, name="feed-1", url="https://f1.test")
    if grade is not None:
        source.reliability_grade = grade
    session.add(source)
    article = Article(
        id=1,
        source_id=1,
        url="https://a.test/1",
        url_canonical_hash="h1",
        title="t",
        body="body",
        tlp="clear",
    )
    session.add(article)
    session.add(
        ArticleAnalysisRun(
            article_id=1,
            state="extract_ioc",
            status="ok",
            attempts=1,
            raw_output_json={
                "output": {"iocs": []},
                "grounding": {
                    "kept": kept,
                    "rejected": [{"value": f"x{n}"} for n in range(rejected)],
                },
            },
        )
    )
    session.add(
        ArticleAnalysisRun(
            article_id=1,
            state="map_ttp",
            status="ok",
            attempts=1,
            raw_output_json={"output": {"mappings": []}, "grounding": {"kept": 10, "rejected": []}},
        )
    )
    session.add(
        ArticleAnalysisRun(
            article_id=1,
            state="verify",
            status=verify_status,
            attempts=1,
            model_id="deepseek-v4-flash",
            prompt_version="verify_v1",
            raw_output_json={"output": {"claims": [], "evidence_quality": quality}},
        )
    )
    session.commit()
    return session.get(Article, 1)


def _ioc(session, value="1.2.3.4", context="the beacon called home"):
    row = ArticleIoc(
        article_id=1,
        ioc_type="ipv4",
        value=value,
        value_defanged=value.replace(".", "[.]", 1),
        span_start=0,
        span_end=7,
        context=context,
    )
    session.add(row)
    session.commit()
    return row


def _ttp(session, technique_id="T1059", confidence=0.9):
    row = ArticleTtp(
        article_id=1,
        technique_id=technique_id,
        technique_name="Command and Scripting",
        evidence_span_start=0,
        evidence_span_end=4,
        confidence=confidence,
    )
    session.add(row)
    session.commit()
    return row


def _sketch(session, *, actors, status="ok"):
    session.add(
        ArticleAnalysisRun(
            article_id=1,
            state="adversary_sketch",
            status=status,
            attempts=1,
            model_id="llama-70b",
            raw_output_json={"output": {"named_actors": actors, "attribution_level": "tactical"}},
        )
    )
    session.commit()


# --- it refuses what it cannot judge -----------------------------------------


def test_an_unfinished_analysis_is_not_gated(session):
    """Scoring a half-analysed article would read the absence of a critic as a
    critic's silence, and the two are not the same thing."""
    _article(session, verify_status="error")
    _ioc(session)

    outcome = run_gate(session, session.get(Article, 1), settings=CONFIG)

    assert outcome.scored == 0
    assert "verify" in outcome.skipped_because
    assert session.query(StagedFinding).count() == 0


# --- every finding gets a row, whatever the answer ---------------------------


def test_a_passing_finding_gets_a_row_and_not_only_the_failing_ones(session):
    """Criterion 1's real content: a table of only the rejected cannot say
    whether the threshold is too high."""
    _article(session)
    _ioc(session)

    outcome = run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    assert outcome.scored == 1
    row = session.query(StagedFinding).one()
    assert row.decision in ("auto", "staged")
    assert row.finding_kind == "ioc"


def test_the_four_components_are_persisted_and_the_total_is_none_of_them(session):
    _article(session)
    _ioc(session)

    run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    row = session.query(StagedFinding).one()
    assert row.anchor_ratio == pytest.approx(29 / 35)
    assert row.critic_agreement == 1.0, "evidence_quality high"
    assert row.schema_completeness == 1.0, "context was populated"
    assert row.self_assessed is None, "the model reports none for indicators"
    assert row.score_total not in (row.anchor_ratio, row.critic_agreement, row.schema_completeness)


def test_the_two_axes_are_stored_apart_with_the_factor_each_applied(session):
    _article(session, grade="B")
    _ioc(session)

    run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    row = session.query(StagedFinding).one()
    assert row.source_grade == "B"
    assert row.source_factor_applied == 0.90
    assert row.info_grade == "3", "uncorroborated first report"
    assert row.info_factor_applied == 0.75
    assert row.score_raw != row.score_total, "the axes acted"


def test_the_composite_is_written_back_onto_the_finding_row(session):
    """`article_iocs.confidence` has been null since Phase 4 and exists for this."""
    _article(session)
    ioc = _ioc(session)

    run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    assert ioc.confidence is not None
    assert ioc.confidence == session.query(StagedFinding).one().score_total


def test_a_technique_carries_its_self_report_where_an_indicator_does_not(session):
    _article(session)
    _ioc(session)
    _ttp(session, confidence=0.8)

    run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    by_kind = {row.finding_kind: row for row in session.query(StagedFinding)}
    assert by_kind["ttp"].self_assessed == 0.8
    assert by_kind["ioc"].self_assessed is None


def test_a_source_nobody_graded_stages_the_finding_however_good_the_score(session):
    """Criterion 1c, on a real row rather than on a constructed score.

    The column defaults to F rather than D since 0021, and this is the test that
    the default matters: D is "not usually reliable", a judgement nobody made,
    and it would have let an unassessed feed enrich at 0.55 instead of staging.
    """
    _article(session, grade=None)
    _ioc(session)

    run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    row = session.query(StagedFinding).one()
    assert row.decision == "staged"
    assert row.source_grade == "F"
    assert "could not be graded" in row.notes


def test_the_reason_is_stored_so_the_queue_explains_itself(session):
    _article(session)
    _ioc(session)

    run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    assert session.query(StagedFinding).one().notes


# --- criterion 2, on real rows -----------------------------------------------


def test_moving_a_threshold_moves_a_real_finding_between_auto_and_staged(session):
    """The recalibration criterion, and it costs no model call."""
    _article(session)
    _ioc(session)
    article = session.get(Article, 1)

    strict = run_gate(session, article, settings=Settings(ai_gate_ioc_min=0.99))
    session.commit()
    assert strict.auto == 0 and strict.staged == 1

    lenient = run_gate(
        session, article, settings=Settings(ai_gate_ioc_min=0.10, ai_gate_overall_min=0.10)
    )
    session.commit()
    assert lenient.auto == 1 and lenient.staged == 0


def test_a_local_run_stages_what_the_cloud_would_have_passed(session):
    _article(session)
    _ioc(session)
    article = session.get(Article, 1)
    lenient = Settings(ai_gate_ioc_min=0.50, ai_gate_overall_min=0.50, ai_gate_local_lift=0.45)

    assert run_gate(session, article, settings=lenient).auto == 1
    session.commit()
    assert run_gate(session, article, settings=lenient, local_run=True).staged == 1


# --- idempotence -------------------------------------------------------------


def test_a_second_pass_replaces_the_rows_instead_of_doubling_the_queue(session):
    """The machine is restartable and the gate has to be too."""
    _article(session)
    _ioc(session)
    article = session.get(Article, 1)

    run_gate(session, article, settings=CONFIG)
    session.commit()
    run_gate(session, article, settings=CONFIG)
    session.commit()

    assert session.query(StagedFinding).count() == 1


# --- the kinds with no table of their own ------------------------------------


def test_the_narrative_and_the_sketch_get_rows_though_they_have_no_findings_table(session):
    """Half of why staged_findings exists: they have nowhere else to carry a
    confidence, and they are the two outputs a person actually reads."""
    _article(session)
    session.add(
        ArticleAnalysisRun(
            article_id=1,
            state="narrative",
            status="ok",
            attempts=1,
            raw_output_json={"output": {"key_judgement": "Akira is likely responsible."}},
        )
    )
    session.commit()
    _sketch(session, actors=["Akira"])

    run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    kinds = {row.finding_kind for row in session.query(StagedFinding)}
    assert {"narrative", "sketch"} <= kinds


def test_a_staged_sketch_enriches_nothing_at_all(session):
    """The gate's whole point: below threshold, nothing reaches the adversary
    tables, not even as a proposal.

    Sunk here by the judge rather than by the threshold, which is the honest way
    for a sketch to fail: three of its four components are structurally absent,
    so its score *is* the judge's verdict on the article, and a low verdict is
    the only thing that can sink it.
    """
    _article(session, quality="low")
    session.add(Group(id=1, group_name="Akira"))
    session.commit()
    _sketch(session, actors=["Akira", "Storm-1567"])

    outcome = run_gate(session, session.get(Article, 1), settings=CONFIG)
    session.commit()

    assert outcome.proposals == 0
    assert session.query(GroupAliasProposal).count() == 0


# --- what the first corpus run taught the enrichment path --------------------


def test_the_gate_never_creates_a_group_from_a_named_actor(session):
    """The first corpus run created sixteen, among them "secpo" and
    "@BonJoviGoesHard", which is a Twitter handle.

    `named_actors` is defined as the names the article uses, and an article uses
    plenty of names that are not adversaries. Creating an adversary row from a
    string is the act that wants a person, so an unresolved actor stays in the
    staged payload for Phase 6.
    """
    _article(session)
    _sketch(session, actors=["@BonJoviGoesHard", "secpo"])

    run_gate(
        session,
        session.get(Article, 1),
        settings=Settings(ai_gate_sketch_min=0.10, ai_gate_overall_min=0.10),
    )
    session.commit()

    assert session.query(Group).count() == 0


def test_named_actors_are_never_proposed_as_aliases_of_one_another(session):
    """The same run made "MOIS", "IRGC Intelligence Organization" and "Handala
    Hack Team" aliases of each other. They are three distinct entities that one
    article mentioned together, and nothing in the schema says the names in one
    article denote one actor. This is the alias collision the design warns
    about, arrived at by the system itself."""
    _article(session)
    session.add(Group(id=1, group_name="MOIS"))
    session.commit()
    _sketch(session, actors=["MOIS", "Handala Hack Team", "Homeland Justice"])

    run_gate(
        session,
        session.get(Article, 1),
        settings=Settings(ai_gate_sketch_min=0.10, ai_gate_overall_min=0.10),
    )
    session.commit()

    assert session.query(GroupAliasProposal).count() == 0


def test_a_known_group_receives_the_wallets_and_leak_sites_that_passed(session):
    """Criterion 3: an existing Group gains profile_urls or BTC, with the
    provenance tracing back to the article."""
    import json

    _article(session)
    session.add(Group(id=1, group_name="Akira"))
    session.commit()
    _ioc(session, value="bc1qexample", context="the ransom note names")
    session.query(ArticleIoc).filter_by(value="bc1qexample").update({"ioc_type": "btc_address"})
    session.commit()
    _sketch(session, actors=["Akira"])

    lenient = Settings(ai_gate_sketch_min=0.10, ai_gate_overall_min=0.10, ai_gate_ioc_min=0.10)
    outcome = run_gate(session, session.get(Article, 1), settings=lenient)
    session.commit()

    assert json.loads(session.get(Group, 1).btc_addresses) == ["bc1qexample"]
    assert "btc_addresses" in outcome.enriched_fields
    audit = session.query(AiEnrichmentAudit).one()
    assert audit.article_id == 1 and audit.table_name == "groups"


def test_an_indicator_the_gate_staged_does_not_ride_in_on_a_good_sketch(session):
    """An indicator the gate would not trust on its own has no business being
    trusted because a sketch beside it scored well."""
    _article(session)
    session.add(Group(id=1, group_name="Akira"))
    session.commit()
    _ioc(session, value="bc1qexample", context="")
    session.query(ArticleIoc).filter_by(value="bc1qexample").update({"ioc_type": "btc_address"})
    session.commit()
    _sketch(session, actors=["Akira"])

    strict_iocs = Settings(ai_gate_sketch_min=0.10, ai_gate_overall_min=0.10, ai_gate_ioc_min=0.99)
    run_gate(session, session.get(Article, 1), settings=strict_iocs)
    session.commit()

    assert session.get(Group, 1).btc_addresses is None
    assert session.query(AiEnrichmentAudit).count() == 0


def test_a_hash_is_not_written_onto_the_adversary(session):
    """A hash rotates and an IP is rented; a leak-site address and a wallet are
    the operation's own furniture. Only the durable kinds are carried over."""
    _article(session)
    session.add(Group(id=1, group_name="Akira"))
    session.commit()
    _ioc(session, value="1.2.3.4")
    _sketch(session, actors=["Akira"])

    lenient = Settings(ai_gate_sketch_min=0.10, ai_gate_overall_min=0.10, ai_gate_ioc_min=0.10)
    run_gate(session, session.get(Article, 1), settings=lenient)
    session.commit()

    assert session.get(Group, 1).profile_urls is None
    assert session.get(Group, 1).btc_addresses is None
