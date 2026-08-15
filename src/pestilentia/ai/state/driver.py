# "You know my methods. Apply them." — Sherlock Holmes
"""What the scheduler calls: pick the articles, pace the calls, count the results.

The machine analyses one article and knows nothing about queues or quotas. This
module is the other half — which articles are still owed an analysis, how fast
the account may be asked, and how much of the backlog is left — and it is kept
separate because those three answers change with the deployment while the state
machine does not.

**Selection is by what the rows say, not by a flag on the article.** An article
is owed an analysis when it has no finished `verify` row and nothing terminal
against it: dropped by triage, staged for a human, or refused on TLP or size.
Everything else — an outage, an exhausted budget, a missing provider — is a
condition that ends, so those articles come back round on the next cycle.

**The rate limit belongs to the account, not the article.** NIM's free tier is
about forty requests a minute shared across every model, and one article costs
up to eight of them. So the pacer sits in front of every request rather than
between articles, where a burst of eight would sail straight past a per-article
delay.

**The batch is small on purpose.** Measured on this deployment: ~110 articles a
week arrive, and the scheduler wakes every two hours. A dozen per cycle clears
that with room to spare, and it keeps a first backlog run from spending hours
inside one cycle where nothing else can happen.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pestilentia.ai.budget import BudgetGuard, monthly_spend
from pestilentia.ai.enrichment.gate import run_gate
from pestilentia.ai.extraction.attack_catalog import AttackCatalog
from pestilentia.ai.router.nvidia import NvidiaProvider
from pestilentia.ai.router.router import Router
from pestilentia.ai.schemas import STATE_ORDER
from pestilentia.ai.state.machine import ExtractionMachine, RunStatus
from pestilentia.config import get_settings
from pestilentia.models.tables import (
    Article,
    ArticleAnalysisRun,
    ArticleIoc,
    ArticleTtp,
)

log = logging.getLogger(__name__)

#: Articles per scheduler cycle. See the module docstring: sized to the measured
#: arrival rate, not to how fast the pipeline could go.
DEFAULT_BATCH = 12

#: Requests per minute. NIM's free tier shares ~40 across all models; the
#: headroom is for the health checks and anything else holding the same key.
DEFAULT_RPM = 30

#: A run that reached one of these is not retried by the scheduler. Each needs a
#: person: to look at a staged output, to move the TLP boundary, to decide the
#: article is genuinely out of scope. `budget_exhausted` is deliberately absent —
#: it stops being true tomorrow.
TERMINAL_STATUSES = (
    RunStatus.DROPPED.value,
    RunStatus.STAGED.value,
    "blocked_tlp",
    "source_ban",
    "too_large",
)

FINAL_STATE = STATE_ORDER[-1]


class RateLimiter:
    """Spaces calls out to a requests-per-minute ceiling.

    Clock and sleep are injected so a test can prove the spacing without
    spending the wall-clock time proving it.
    """

    def __init__(
        self,
        rpm: int = DEFAULT_RPM,
        now: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._interval = 60.0 / rpm if rpm > 0 else 0.0
        self._now = now
        self._sleep = sleep
        self._last: float | None = None

    def __call__(self) -> None:
        if self._interval <= 0:
            return
        moment = self._now()
        if self._last is not None:
            wait = self._interval - (moment - self._last)
            if wait > 0:
                self._sleep(wait)
                moment = self._now()
        self._last = moment


@dataclass
class BatchOutcome:
    """What one cycle did. Logged, and shown on the pipeline page."""

    analysed: int = 0
    dropped: int = 0
    incomplete: int = 0
    stopped: dict[str, int] = field(default_factory=dict)
    #: Findings the confidence gate scored, and fields it enriched (Phase 5).
    gated: int = 0
    enriched: int = 0

    @property
    def attempted(self) -> int:
        return self.analysed + self.dropped + self.incomplete


def pending_articles(session: Session, limit: int = DEFAULT_BATCH) -> list[Article]:
    """The articles still owed an analysis, newest first.

    Newest first because a week-old incident report is worth less than this
    morning's, and a backlog run should not hold today's articles behind 2024.
    """
    finished = select(ArticleAnalysisRun.article_id).where(
        ArticleAnalysisRun.state == FINAL_STATE,
        ArticleAnalysisRun.status == RunStatus.OK.value,
    )
    terminal = select(ArticleAnalysisRun.article_id).where(
        ArticleAnalysisRun.status.in_(TERMINAL_STATUSES)
    )
    return list(
        session.scalars(
            select(Article)
            .where(
                Article.body.isnot(None),
                Article.body != "",
                Article.id.notin_(finished),
                Article.id.notin_(terminal),
            )
            .order_by(Article.published_at.desc().nullslast(), Article.id.desc())
            .limit(limit)
        )
    )


def stratified_pending(session: Session, per_source: int, pool: int = 5_000) -> list[Article]:
    """Pending articles, at most `per_source` from any one feed.

    For the Phase 5 calibration corpus, not for the scheduler, which wants the
    newest articles regardless of who published them. Calibration wants the
    opposite: the backlog is not evenly spread — two of the twelve feeds carry
    64% of it — and a sample drawn in publication order would tune the gate on
    those two. Sampling evenly per feed also spreads body length, which the
    calibration step has to hold as a covariate, so it must vary by design and
    not by luck.

    Feeds with fewer than `per_source` pending articles contribute what they
    have. A thin cell is a wide confidence interval, and it gets reported as
    one; padding it from a richer feed would only disguise the shortfall.

    **Still-truncated articles are excluded, unlike in the scheduler's
    selection.** An article whose full text never came back keeps its RSS
    summary in `body`, which is non-empty and therefore passes
    `pending_articles` — correctly, because in production analysing a summary
    beats analysing nothing. For calibration it is poison twice over: an
    anchoring ratio measured on 600 characters is not comparable to one
    measured on 29,000, and body length is a covariate the calibration step has
    to hold, so letting summaries in would confound the very variable being
    controlled for. Measured 2026-08-14: three Check Point articles behind a
    WAF challenge would have entered the sample on ~600-character summaries.
    """
    by_source: dict[int | None, list[Article]] = {}
    for article in pending_articles(session, limit=pool):
        if article.truncated:
            continue
        bucket = by_source.setdefault(article.source_id, [])
        if len(bucket) < per_source:
            bucket.append(article)
    return [article for bucket in by_source.values() for article in bucket]


def build_machine(pacer: Callable[[], None] | None = None) -> ExtractionMachine | None:
    """Assemble the machine from settings, or explain why it cannot be.

    Returns None rather than raising: a deployment with no key, or one that has
    never fetched the ATT&CK bundle, is a deployment where this feature is off,
    not one where the scheduler should fall over. The reason is logged once per
    cycle, which is where an operator will look for it.
    """
    settings = get_settings()
    if not settings.ai_nvidia_api_key:
        log.info("article analysis idle: no PEST_AI_NVIDIA_API_KEY configured")
        return None
    try:
        catalog = AttackCatalog.load()
    except FileNotFoundError as exc:
        log.warning("article analysis idle: %s", exc)
        return None

    return ExtractionMachine(
        router=Router(cloud_max=settings.ai_tlp_cloud_max),
        providers={"nvidia": NvidiaProvider(api_key=settings.ai_nvidia_api_key)},
        catalog=catalog,
        budget=BudgetGuard(
            daily_cap_usd=settings.ai_daily_budget_usd,
            monthly_cap_usd=settings.ai_monthly_budget_usd,
        ),
        pacer=pacer if pacer is not None else RateLimiter(),
    )


def analyse_articles(
    session: Session,
    machine: ExtractionMachine | None = None,
    limit: int = DEFAULT_BATCH,
    articles: list[Article] | None = None,
) -> BatchOutcome:
    """Run one batch. Never raises on a single article's account.

    One article failing must not cost the rest of the batch their turn: the
    machine already writes what it learned before it stopped, so an exception
    here is logged against that article and the cycle carries on.

    `articles` overrides the selection for callers that have already chosen —
    the calibration corpus draws a stratified sample — so the counting of
    triage drops and stop reasons stays in one place instead of being copied
    into a script where it would quietly drift from this one.
    """
    engine = machine if machine is not None else build_machine()
    outcome = BatchOutcome()
    if engine is None:
        return outcome

    batch = articles if articles is not None else pending_articles(session, limit)
    for article in batch:
        try:
            report = engine.run(session, article)
        except Exception:
            session.rollback()
            log.exception("article %s failed mid-analysis", article.id)
            outcome.incomplete += 1
            continue

        if report.completed:
            outcome.analysed += 1
            # The gate runs here rather than as a ninth state: it makes no model
            # calls, so it has no business inside the retry and budget machinery
            # that exists for things which fail expensively. Its own failure must
            # not cost the analysis either — the eight states are paid for and
            # committed, and scoring can be redone for free on the next pass.
            try:
                gated = run_gate(session, article)
                outcome.gated += gated.scored
                outcome.enriched += len(gated.enriched_fields)
            except Exception:
                session.rollback()
                log.exception("gate failed for article %s; the analysis stands", article.id)
        elif report.stopped_at == STATE_ORDER[0] and "not relevant" in report.stopped_because:
            outcome.dropped += 1
        else:
            outcome.incomplete += 1
            outcome.stopped[report.stopped_at or "unknown"] = (
                outcome.stopped.get(report.stopped_at or "unknown", 0) + 1
            )

    log.info(
        "article analysis: %s analysed, %s dropped by triage, %s incomplete %s; "
        "gate scored %s findings and enriched %s fields",
        outcome.analysed,
        outcome.dropped,
        outcome.incomplete,
        outcome.stopped or "",
        outcome.gated,
        outcome.enriched,
    )
    return outcome


def analysis_counters(session: Session) -> dict:
    """The pipeline page's view of the extraction pipeline.

    Counted from the rows every time rather than kept in a running total: a
    counter that drifts from the rows is worse than no counter, because it is
    the one an operator believes.
    """

    def _articles_with(*conditions) -> int:
        return int(
            session.scalar(
                select(func.count(func.distinct(ArticleAnalysisRun.article_id))).where(*conditions)
            )
            or 0
        )

    total = int(session.scalar(select(func.count(Article.id))) or 0)
    analysed = _articles_with(
        ArticleAnalysisRun.state == FINAL_STATE,
        ArticleAnalysisRun.status == RunStatus.OK.value,
    )
    dropped = _articles_with(ArticleAnalysisRun.status == RunStatus.DROPPED.value)
    staged = _articles_with(ArticleAnalysisRun.status == RunStatus.STAGED.value)
    blocked = _articles_with(
        ArticleAnalysisRun.status.in_(("blocked_tlp", "source_ban", "too_large"))
    )
    return {
        "total_articles": total,
        "analysed": analysed,
        "dropped": dropped,
        "staged": staged,
        "blocked": blocked,
        "pending": max(0, total - analysed - dropped - staged - blocked),
        "indicators": int(session.scalar(select(func.count(ArticleIoc.id))) or 0),
        "techniques": int(session.scalar(select(func.count(ArticleTtp.id))) or 0),
        "spend_this_month": monthly_spend(session),
    }
