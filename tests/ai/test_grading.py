# "I never guess. It is a shocking habit." — Sherlock Holmes
"""The two UNODC axes: six grades each, and the two that mean no answer.

The rule the whole design turns on is principle 2 of chapter 4, that the source
is evaluated separately from the information. Most of these tests are there to
stop the two from being quietly recombined by a later hand.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.confidence.grading import (
    INFO_FACTORS,
    SOURCE_FACTORS,
    Corroboration,
    InfoGrade,
    SourceGrade,
    apply_axes,
    corroboration_for_ioc,
    corroboration_for_ttp,
    grade_for_weight,
    info_grade_of,
    set_source_grade,
    source_grade_of,
)
from pestilentia.models.base import Base
from pestilentia.models.tables import Article, ArticleIoc, ArticleSource, ArticleTtp


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        yield db


# --- the source axis ---------------------------------------------------------


@pytest.mark.parametrize("letter", ["A", "B", "C", "D", "E", "F"])
def test_every_grade_on_the_source_scale_is_readable(letter):
    assert source_grade_of(letter) == SourceGrade(letter)


@pytest.mark.parametrize("letter", ["a", " b ", "C"])
def test_a_grade_survives_the_way_it_was_typed(letter):
    assert source_grade_of(letter) in SourceGrade


@pytest.mark.parametrize("bad", [None, "", "Z", "1", "excellent"])
def test_a_source_nobody_has_assessed_cannot_be_judged_rather_than_scored_low(bad):
    """F is not the bottom of the scale. E is. F means the question was never
    answered, and the consequence is staging, not a poor score."""
    assert source_grade_of(bad) is SourceGrade.CANNOT_BE_JUDGED


def test_the_top_grade_carries_no_penalty():
    """The 0.9 it replaces was a literal in seeds.py with nothing behind it, and
    it made the 0.85 IOC threshold unreachable for every source in the field."""
    assert SOURCE_FACTORS[SourceGrade.COMPLETELY_RELIABLE] == 1.0


def test_the_source_factors_fall_monotonically():
    ordered = [
        SourceGrade.COMPLETELY_RELIABLE,
        SourceGrade.USUALLY_RELIABLE,
        SourceGrade.FAIRLY_RELIABLE,
        SourceGrade.NOT_USUALLY_RELIABLE,
        SourceGrade.UNRELIABLE,
    ]
    factors = [SOURCE_FACTORS[grade] for grade in ordered]

    assert factors == sorted(factors, reverse=True)


def test_the_ungradeable_letters_have_no_factor_at_all():
    """Giving them one would turn an absent judgement into a poor one."""
    assert SourceGrade.CANNOT_BE_JUDGED not in SOURCE_FACTORS
    assert InfoGrade.CANNOT_BE_JUDGED not in INFO_FACTORS


# --- the information axis ----------------------------------------------------


def test_confirmed_by_another_feed_is_grade_one():
    assert info_grade_of(Corroboration(independent_sources=1)) is InfoGrade.CONFIRMED


def test_contradicted_is_grade_five_even_when_others_reported_it():
    """A contradiction is information about the subject and outranks a count.
    Corroboration and contradiction are not two ends of one number."""
    corroborated_and_contradicted = Corroboration(independent_sources=3, contradicted=True)

    assert info_grade_of(corroborated_and_contradicted) is InfoGrade.IMPROBABLE


def test_an_ordinary_first_report_is_possibly_true_and_not_doubtful():
    """Grade 3 is the honest default: not confirmed, not contradicted. Filing a
    first report as doubtful would punish every scoop for being a scoop."""
    assert info_grade_of(Corroboration()) is InfoGrade.POSSIBLY_TRUE


def test_incompatible_with_what_is_held_is_improbable():
    assert info_grade_of(Corroboration(consistent_with_record=False)) is InfoGrade.IMPROBABLE


def test_no_corroboration_object_at_all_cannot_be_judged():
    """Different from an empty one. An empty Corroboration is a completed
    enquiry that found nothing; None is an enquiry that never ran."""
    assert info_grade_of(None) is InfoGrade.CANNOT_BE_JUDGED
    assert info_grade_of(Corroboration()) is not InfoGrade.CANNOT_BE_JUDGED


def test_doubtful_is_not_reachable_from_the_predicates_and_that_is_deliberate():
    """Telling 'doubtful' from 'possibly true' needs a judgement about the
    claim's own plausibility that nothing in the schema supports. Reaching it by
    rule would be manufacturing a grade rather than assigning one."""
    reachable = {
        info_grade_of(
            Corroboration(independent_sources=n, contradicted=c, consistent_with_record=k)
        )
        for n in (0, 1, 5)
        for c in (True, False)
        for k in (True, False)
    }

    assert InfoGrade.DOUBTFUL not in reachable


# --- the two axes acting on a score ------------------------------------------


def test_both_factors_multiply_and_both_are_recorded():
    graded = apply_axes(0.80, SourceGrade.USUALLY_RELIABLE, InfoGrade.CONFIRMED)

    assert graded.source_factor == 0.90
    assert graded.info_factor == 1.00
    assert graded.score_total == pytest.approx(0.80 * 0.90)
    assert graded.score_raw == 0.80, "the pre-axis score survives for recalibration"


def test_the_raw_score_is_kept_so_a_new_map_needs_no_llm_call():
    """The real content of roadmap criterion 1. A retuned map applied to stored
    rows has to be able to move findings between auto and staged without
    re-running anything."""
    graded = apply_axes(0.90, SourceGrade.FAIRLY_RELIABLE, InfoGrade.POSSIBLY_TRUE)
    retuned = apply_axes(
        graded.score_raw,
        graded.source_grade,
        graded.info_grade,
        source_factors={SourceGrade.FAIRLY_RELIABLE: 1.0},
        info_factors={InfoGrade.POSSIBLY_TRUE: 1.0},
    )

    assert retuned.score_total == pytest.approx(0.90)
    assert retuned.score_total > graded.score_total


@pytest.mark.parametrize(
    ("source", "info"),
    [
        (SourceGrade.CANNOT_BE_JUDGED, InfoGrade.CONFIRMED),
        (SourceGrade.COMPLETELY_RELIABLE, InfoGrade.CANNOT_BE_JUDGED),
        (SourceGrade.CANNOT_BE_JUDGED, InfoGrade.CANNOT_BE_JUDGED),
    ],
)
def test_an_unjudgeable_axis_flags_the_finding_however_good_the_number(source, info):
    """Criterion 1c. The gate stages what it cannot judge, and the flag is what
    it reads: a perfect raw score on an ungraded source is still not enrichable."""
    graded = apply_axes(1.0, source, info)

    assert graded.unjudgeable is True


def test_a_missing_judgement_does_not_act_as_a_silent_penalty():
    """It would be easy to treat an absent factor as zero and let the number
    make the decision. Then a staged finding would also be a low-scoring one,
    and the reason for staging would be lost in the score."""
    graded = apply_axes(0.90, SourceGrade.CANNOT_BE_JUDGED, InfoGrade.CANNOT_BE_JUDGED)

    assert graded.score_total == pytest.approx(0.90)
    assert graded.source_factor is None and graded.info_factor is None


def test_both_grades_survive_on_the_result_and_are_never_fused():
    """Principle 2 applied to the return value, not only to the schema."""
    graded = apply_axes(0.5, SourceGrade.UNRELIABLE, InfoGrade.CONFIRMED)

    assert graded.source_grade is SourceGrade.UNRELIABLE
    assert graded.info_grade is InfoGrade.CONFIRMED


# --- corroboration read from the record --------------------------------------


def _article(session: Session, article_id: int, source_id: int) -> Article:
    row = Article(
        id=article_id,
        source_id=source_id,
        url=f"https://example.test/{article_id}",
        url_canonical_hash=f"hash-{article_id}",
        title=f"Article {article_id}",
        body="body",
    )
    session.add(row)
    session.commit()
    return row


def _sources(session: Session, count: int) -> None:
    for index in range(1, count + 1):
        session.add(ArticleSource(id=index, name=f"feed-{index}", url=f"https://feed{index}.test"))
    session.commit()


def test_an_indicator_another_feed_also_reported_is_corroborated(session):
    _sources(session, 2)
    _article(session, 1, source_id=1)
    _article(session, 2, source_id=2)
    for article_id in (1, 2):
        session.add(
            ArticleIoc(
                article_id=article_id,
                ioc_type="ipv4",
                value="1.2.3.4",
                value_defanged="1.2.3[.]4",
                span_start=0,
                span_end=7,
            )
        )
    session.commit()

    assert corroboration_for_ioc(session, 1, "1.2.3.4").independent_sources == 1


def test_a_feed_repeating_itself_never_confirms_itself(session):
    """Syndication is not corroboration. Three write-ups of one vendor's
    research are one source's claim repeated, and counting articles instead of
    feeds would manufacture confirmation out of republication."""
    _sources(session, 1)
    for article_id in (1, 2, 3):
        _article(session, article_id, source_id=1)
        session.add(
            ArticleIoc(
                article_id=article_id,
                ioc_type="ipv4",
                value="1.2.3.4",
                value_defanged="1.2.3[.]4",
                span_start=0,
                span_end=7,
            )
        )
    session.commit()

    assert corroboration_for_ioc(session, 1, "1.2.3.4").independent_sources == 0
    assert info_grade_of(corroboration_for_ioc(session, 1, "1.2.3.4")) is InfoGrade.POSSIBLY_TRUE


def test_an_indicator_nobody_else_reported_is_uncorroborated_not_contradicted(session):
    _sources(session, 2)
    _article(session, 1, source_id=1)
    session.add(
        ArticleIoc(
            article_id=1,
            ioc_type="ipv4",
            value="9.9.9.9",
            value_defanged="9.9.9[.]9",
            span_start=0,
            span_end=7,
        )
    )
    session.commit()

    corroboration = corroboration_for_ioc(session, 1, "9.9.9.9")

    assert corroboration.independent_sources == 0
    assert corroboration.contradicted is False


def test_a_technique_two_other_feeds_mapped_counts_both(session):
    _sources(session, 3)
    for article_id, source_id in ((1, 1), (2, 2), (3, 3)):
        _article(session, article_id, source_id=source_id)
        session.add(
            ArticleTtp(
                article_id=article_id,
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                evidence_span_start=0,
                evidence_span_end=4,
            )
        )
    session.commit()

    assert corroboration_for_ttp(session, 1, "T1059").independent_sources == 2


# --- the grade is a person's to set, and the change leaves a trail -----------


def test_changing_a_grade_records_who_changed_it_from_what_to_what(session):
    _sources(session, 1)
    source = session.get(ArticleSource, 1)
    source.reliability_grade = "C"
    session.commit()

    entry = set_source_grade(session, source, SourceGrade.USUALLY_RELIABLE, actor_name="rosse")
    session.commit()

    assert source.reliability_grade == "B"
    assert entry.action == "source_grade"
    assert entry.actor_name == "rosse"
    assert entry.target == "feed-1"
    assert entry.detail == "C -> B"


def test_a_grade_change_is_admin_audit_and_not_the_ai_audit_table(session):
    """A person changing configuration is not a model changing data. Mixing the
    two would put a human decision into the statistics that measure model
    behaviour, which is the same trap `audit.py`'s confidence=1.0 sentinel sets."""
    from pestilentia.models.tables import AdminAudit, AiEnrichmentAudit

    _sources(session, 1)
    set_source_grade(session, session.get(ArticleSource, 1), SourceGrade.UNRELIABLE, actor_name="x")
    session.commit()

    assert session.query(AdminAudit).count() == 1
    assert session.query(AiEnrichmentAudit).count() == 0


def test_a_note_survives_onto_the_audit_row(session):
    _sources(session, 1)
    entry = set_source_grade(
        session,
        session.get(ArticleSource, 1),
        SourceGrade.FAIRLY_RELIABLE,
        actor_name="rosse",
        note="reports others' research, does not originate it",
    )
    session.commit()

    assert "reports others' research" in entry.detail


@pytest.mark.parametrize(
    ("weight", "grade"),
    [(0.9, "A"), (0.85, "B"), (0.8, "B"), (0.6, "C"), (0.5, "D"), (0.1, "E")],
)
def test_a_legacy_weight_reads_as_the_grade_the_migration_gave_it(weight, grade):
    assert grade_for_weight(weight).value == grade


def test_a_feed_with_no_weight_at_all_cannot_be_judged():
    """Different from a bad weight. A weight is knowledge, however crude; the
    absence of one is the question never having been asked."""
    assert grade_for_weight(None) is SourceGrade.CANNOT_BE_JUDGED


def test_the_seed_never_overwrites_a_grade_an_analyst_tuned(session):
    """The `continue` in seed_article_sources is load-bearing, not incidental.

    Since 0020 the grade is the number a person sets by hand. A seed that
    upserted would discard every tuned grade on the next start-up, silently and
    without an audit row. This test exists so that a later hand "fixing" the
    skip into an upsert breaks something visible instead of erasing an
    analyst's work.
    """
    from pestilentia.ai.sources.seeds import SEED_SOURCES, seed_article_sources

    spec = SEED_SOURCES[0]
    session.add(
        ArticleSource(name=spec["name"], url=spec["url"], trust_weight=0.9, reliability_grade="E")
    )
    session.commit()

    seed_article_sources(session)
    session.commit()

    kept = session.query(ArticleSource).filter_by(name=spec["name"]).one()
    assert kept.reliability_grade == "E", "the seed walked over a hand-tuned grade"


def test_a_newly_seeded_feed_starts_from_its_weight_rather_than_ungraded(session):
    """A starting point, not an assessment. F would stage everything from a new
    feed until someone got round to it, which is a defensible policy but not
    this one: the weights were curated, and discarding them would throw away a
    judgement that was already made."""
    from pestilentia.ai.sources.seeds import SEED_SOURCES, seed_article_sources

    seed_article_sources(session)
    session.commit()

    seeded = session.query(ArticleSource).filter_by(name=SEED_SOURCES[0]["name"]).one()
    assert seeded.reliability_grade == grade_for_weight(SEED_SOURCES[0]["trust_weight"]).value
    assert seeded.reliability_grade != SourceGrade.CANNOT_BE_JUDGED.value
