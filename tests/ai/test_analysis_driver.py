# "Nothing clears up a case so much as stating it to another person." — Sherlock Holmes
"""Selection, pacing and counting — the half of the pipeline the machine has no
opinion about.

Nothing here calls a provider: the machine is replaced by a stub whose only job
is to say what happened to each article. What is under test is which articles
get picked, how often requests may go out, and whether the numbers on the
pipeline page match the rows they claim to summarise.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.state.driver import (
    DEFAULT_BATCH,
    BatchOutcome,
    RateLimiter,
    analyse_articles,
    analysis_counters,
    pending_articles,
    stratified_pending,
)
from pestilentia.ai.state.machine import RunReport, RunStatus, StateResult
from pestilentia.models.base import Base
from pestilentia.models.tables import Article, ArticleAnalysisRun, ArticleIoc, ArticleTtp


@pytest.fixture(autouse=True)
def _restore_gate():
    """The gate tests patch a module attribute; put it back afterwards."""
    from pestilentia.ai.state import driver as driver_module

    original = driver_module.run_gate
    yield
    driver_module.run_gate = original


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        yield db


def _article(session, slug="a", body="An article body.", published=None):
    row = Article(
        url=f"https://example.test/{slug}",
        url_canonical_hash=f"hash-{slug}",
        title=f"Article {slug}",
        body=body,
        published_at=published,
        tlp="clear",
    )
    session.add(row)
    session.commit()
    return row


def _run(session, article, state, status):
    session.add(ArticleAnalysisRun(article_id=article.id, state=state, status=status, attempts=1))
    session.commit()


class StubMachine:
    """Reports a fixed outcome per article and records what it was handed."""

    def __init__(self, report_for=lambda article: RunReport(article.id, ())):
        self._report_for = report_for
        self.seen = []

    def run(self, session, article, override=None):
        self.seen.append(article.id)
        report = self._report_for(article)
        if isinstance(report, Exception):
            raise report
        return report


def _completed(article):
    return RunReport(article.id, (StateResult("verify", RunStatus.OK),))


def _dropped(article):
    return RunReport(
        article.id,
        (StateResult("triage", RunStatus.DROPPED),),
        stopped_at="triage",
        stopped_because="triage: not relevant",
    )


# --- selection ---------------------------------------------------------------


def test_an_article_nobody_has_analysed_is_picked_up(session):
    article = _article(session)

    assert [row.id for row in pending_articles(session)] == [article.id]


def test_a_finished_article_is_not_picked_up_again(session):
    article = _article(session)
    _run(session, article, "verify", RunStatus.OK)

    assert pending_articles(session) == []


def test_an_article_dropped_at_triage_is_not_re_offered(session):
    """It is not owed an analysis; triage already answered."""
    article = _article(session)
    _run(session, article, "triage", RunStatus.DROPPED)

    assert pending_articles(session) == []


@pytest.mark.parametrize("status", ["staged", "blocked_tlp", "source_ban", "too_large"])
def test_a_state_that_needs_a_person_stops_the_scheduler_retrying(session, status):
    article = _article(session)
    _run(session, article, "classify", status)

    assert pending_articles(session) == []


@pytest.mark.parametrize("status", ["error", "budget_exhausted", "no_provider", "pending"])
def test_a_condition_that_ends_comes_back_round(session, status):
    """An outage, an exhausted cap and a missing key all stop being true."""
    article = _article(session)
    _run(session, article, "triage", status)

    assert [row.id for row in pending_articles(session)] == [article.id]


def test_an_article_with_no_body_is_never_offered(session):
    _article(session, slug="empty", body=None)
    _article(session, slug="blank", body="")

    assert pending_articles(session) == []


def test_the_newest_article_goes_first(session):
    from datetime import UTC, datetime

    old = _article(session, slug="old", published=datetime(2024, 1, 1, tzinfo=UTC))
    new = _article(session, slug="new", published=datetime(2026, 8, 1, tzinfo=UTC))

    assert [row.id for row in pending_articles(session)] == [new.id, old.id]


def test_the_batch_is_bounded(session):
    for index in range(DEFAULT_BATCH + 3):
        _article(session, slug=f"a{index}")

    assert len(pending_articles(session)) == DEFAULT_BATCH
    assert len(pending_articles(session, limit=2)) == 2


# --- stratified selection, for the Phase 5 calibration corpus ----------------


def _sourced(session, source_id, slug, published=None):
    row = _article(session, slug=slug, published=published)
    row.source_id = source_id
    session.commit()
    return row


def test_no_feed_can_dominate_the_calibration_sample(session):
    """The reason this function exists.

    In the real backlog two feeds of twelve carry 64% of the articles. Drawn in
    publication order, a sample of that backlog is a sample of those two feeds,
    and a gate tuned on it is tuned on them.
    """
    for index in range(20):
        _sourced(session, 1, f"loud{index}")
    for index in range(3):
        _sourced(session, 2, f"quiet{index}")

    sample = stratified_pending(session, per_source=5)
    by_source = {}
    for article in sample:
        by_source[article.source_id] = by_source.get(article.source_id, 0) + 1

    assert by_source == {1: 5, 2: 3}


def test_a_thin_feed_contributes_what_it_has_and_is_not_padded(session):
    """CISA has eight pending and The Record five. Borrowing from a richer feed
    to fill their cells would hide the shortfall instead of reporting it."""
    _sourced(session, 1, "only-one")
    for index in range(4):
        _sourced(session, 2, f"other{index}")

    sample = stratified_pending(session, per_source=10)

    assert len(sample) == 5


def test_the_stratified_sample_still_refuses_what_is_not_pending(session):
    """It samples the pending set, so triage drops and finished runs stay out."""
    kept = _sourced(session, 1, "kept")
    finished = _sourced(session, 1, "finished")
    _run(session, finished, "verify", RunStatus.OK)

    assert [row.id for row in stratified_pending(session, per_source=10)] == [kept.id]


def test_an_article_still_carrying_its_rss_summary_stays_out_of_the_sample(session):
    """The scheduler is right to analyse a summary — better than nothing — and
    calibration is right to refuse one.

    A truncated article keeps its summary in `body`, which is non-empty and so
    passes the scheduler's selection. An anchoring ratio measured on 600
    characters is not comparable to one measured on 29,000, and body length is
    the covariate the calibration step has to hold: letting summaries in would
    confound the variable being controlled for. Three real Check Point articles
    behind a WAF challenge would have entered on ~600-character summaries.
    """
    full = _sourced(session, 1, "full")
    summary = _sourced(session, 1, "summary")
    summary.truncated = True
    session.commit()

    assert [row.id for row in stratified_pending(session, per_source=10)] == [full.id]
    assert [row.id for row in pending_articles(session)] != [], "the scheduler still wants it"


def test_within_a_feed_the_newest_articles_are_the_ones_taken(session):
    from datetime import UTC, datetime

    old = _sourced(session, 1, "old", published=datetime(2024, 1, 1, tzinfo=UTC))
    new = _sourced(session, 1, "new", published=datetime(2026, 8, 1, tzinfo=UTC))

    assert [row.id for row in stratified_pending(session, per_source=1)] == [new.id]
    assert old.id not in [row.id for row in stratified_pending(session, per_source=1)]


# --- the batch ---------------------------------------------------------------


def test_each_outcome_is_counted_under_its_own_heading(session):
    completed = _article(session, slug="one")
    dropped = _article(session, slug="two")
    stopped = _article(session, slug="three")
    reports = {
        completed.id: _completed(completed),
        dropped.id: _dropped(dropped),
        stopped.id: RunReport(
            stopped.id, (), stopped_at="map_ttp", stopped_because="output rejected"
        ),
    }

    outcome = analyse_articles(session, StubMachine(lambda article: reports[article.id]))

    assert (outcome.analysed, outcome.dropped, outcome.incomplete) == (1, 1, 1)
    assert outcome.stopped == {"map_ttp": 1}


def test_a_caller_that_chose_its_own_articles_gets_exactly_those(session):
    """The corpus runner hands over a stratified sample and wants the counting,
    not the selection. Copying the counting into the script is how the two
    would drift, and the triage-drop count is the one number the calibration
    step cannot afford to have two versions of."""
    chosen = _article(session, slug="chosen")
    _article(session, slug="ignored")
    machine = StubMachine(_completed)

    outcome = analyse_articles(session, machine, articles=[chosen])

    assert machine.seen == [chosen.id]
    assert outcome.analysed == 1


def test_an_explicit_empty_batch_asks_nothing_of_the_provider(session):
    """Not the same as no argument, which means 'you pick'."""
    _article(session, slug="pending")
    machine = StubMachine(_completed)

    outcome = analyse_articles(session, machine, articles=[])

    assert machine.seen == []
    assert outcome.attempted == 0


def test_one_article_blowing_up_does_not_cost_the_others_their_turn(session):
    first = _article(session, slug="one", published=None)
    second = _article(session, slug="two")
    machine = StubMachine(
        lambda article: RuntimeError("boom") if article.id == second.id else _completed(article)
    )

    outcome = analyse_articles(session, machine)

    assert set(machine.seen) == {first.id, second.id}, "the survivor still got its turn"
    assert outcome.analysed == 1 and outcome.incomplete == 1


def test_with_nothing_pending_nothing_is_asked_of_the_provider(session):
    machine = StubMachine()

    outcome = analyse_articles(session, machine)

    assert machine.seen == []
    assert outcome == BatchOutcome()


# --- pacing ------------------------------------------------------------------


def test_the_first_call_is_not_delayed():
    slept = []
    limiter = RateLimiter(rpm=60, now=lambda: 0.0, sleep=slept.append)

    limiter()

    assert slept == []


def test_calls_are_spaced_to_the_ceiling():
    """Sixty a minute is one a second; two back-to-back cost a second's wait."""
    clock = iter([0.0, 0.0, 1.0])
    slept = []
    limiter = RateLimiter(rpm=60, now=lambda: next(clock), sleep=slept.append)

    limiter()
    limiter()

    assert slept == [1.0]


def test_a_caller_that_took_its_time_waits_no_longer():
    clock = iter([0.0, 5.0])
    slept = []
    limiter = RateLimiter(rpm=60, now=lambda: next(clock), sleep=slept.append)

    limiter()
    limiter()

    assert slept == []


def test_a_zero_ceiling_means_no_pacing_at_all():
    limiter = RateLimiter(rpm=0, now=lambda: 0.0, sleep=lambda _: pytest.fail("should not sleep"))

    limiter()
    limiter()


# --- counters ----------------------------------------------------------------


def test_the_counters_add_up_to_the_articles_there_are(session):
    analysed = _article(session, slug="one")
    _run(session, analysed, "verify", RunStatus.OK)
    dropped = _article(session, slug="two")
    _run(session, dropped, "triage", RunStatus.DROPPED)
    staged = _article(session, slug="three")
    _run(session, staged, "classify", RunStatus.STAGED)
    _article(session, slug="four")  # untouched

    counters = analysis_counters(session)

    assert counters["total_articles"] == 4
    assert (counters["analysed"], counters["dropped"], counters["staged"]) == (1, 1, 1)
    assert counters["pending"] == 1


def test_a_blocked_article_is_counted_apart_from_a_staged_one(session):
    """One needs the TLP boundary moved, the other needs its output read."""
    blocked = _article(session, slug="one")
    _run(session, blocked, "triage", "blocked_tlp")

    counters = analysis_counters(session)

    assert counters["blocked"] == 1 and counters["staged"] == 0


def test_the_findings_are_counted_from_the_findings_tables(session):
    article = _article(session)
    session.add(
        ArticleIoc(
            article_id=article.id,
            ioc_type="ipv4",
            value="203.0.113.7",
            value_defanged="203.0.113[.]7",
            span_start=0,
            span_end=13,
        )
    )
    session.add(
        ArticleTtp(
            article_id=article.id,
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic_id="TA0040",
            tactic_name="Impact",
            evidence_span_start=0,
            evidence_span_end=10,
        )
    )
    session.commit()

    counters = analysis_counters(session)

    assert (counters["indicators"], counters["techniques"]) == (1, 1)


def test_an_empty_deployment_reports_zeroes_rather_than_nulls(session):
    """The page renders these; a None would show up as an error, not a zero."""
    counters = analysis_counters(session)

    assert set(counters.values()) == {0}


# --- the gate rides along, and cannot cost the analysis ----------------------


def test_a_completed_analysis_is_gated_in_the_same_cycle(session):
    """Phase 5 step 8. The gate is not a ninth state: it makes no model calls,
    so it has no business inside the retry and budget machinery."""
    from pestilentia.ai.state import driver as driver_module

    article = _article(session)
    calls = []
    driver_module.run_gate = lambda s, a: calls.append(a.id) or _GateStub()

    analyse_articles(session, StubMachine(_completed))

    assert calls == [article.id]


def test_a_dropped_article_is_not_gated(session):
    """Triage said no. There is nothing to score, and scoring it would put a
    row in the queue for an article nobody analysed."""
    from pestilentia.ai.state import driver as driver_module

    _article(session)
    calls = []
    driver_module.run_gate = lambda s, a: calls.append(a.id) or _GateStub()

    analyse_articles(session, StubMachine(_dropped))

    assert calls == []


def test_the_gate_blowing_up_does_not_cost_the_analysis(session):
    """The eight states are paid for and committed. Scoring can be redone for
    free on the next pass; the calls cannot."""
    from pestilentia.ai.state import driver as driver_module

    _article(session)

    def _boom(session, article):
        raise RuntimeError("gate exploded")

    driver_module.run_gate = _boom

    outcome = analyse_articles(session, StubMachine(_completed))

    assert outcome.analysed == 1, "the analysis still counts"
    assert outcome.gated == 0


class _GateStub:
    """Stands in for GateOutcome: the driver only reads these two."""

    scored = 3
    enriched_fields: ClassVar[list[str]] = ["profile_urls"]
