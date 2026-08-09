"""B4: spend estimation, enforcement and accounting.

Real rows in a real (in-memory) database, because the whole point of the guard
is what it reads back out of `LlmCallLog`. Still zero LLM spend: nothing here
calls a provider.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.budget import (
    DEGRADE_AT,
    BudgetGuard,
    estimate_tokens,
    estimated_cost,
    monthly_spend,
    record_call,
    spend_by_provider,
    spend_on,
    year_month,
)
from pestilentia.ai.router import Tier
from pestilentia.models.base import Base
from pestilentia.models.tables import LlmCallLog


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


def test_token_estimate_scales_with_length():
    short = estimate_tokens("a" * 400)
    long = estimate_tokens("a" * 4000)
    assert short == 100
    assert long == 10 * short


def test_empty_text_still_estimates_at_least_one_token():
    """Zero would make a free call look free-and-unlimited to the guard."""
    assert estimate_tokens("") == 1


def test_pricing_uses_the_registry():
    """1M in + 1M out on the triage tier at $1/$5."""
    assert estimated_cost(Tier.TRIAGE, "anthropic", 1_000_000, 1_000_000) == pytest.approx(6.0)


def test_local_calls_are_free():
    assert estimated_cost(Tier.TRIAGE, "ollama", 1_000_000, 1_000_000) == 0.0


def test_an_unknown_provider_prices_at_zero_rather_than_guessing():
    """A fabricated price would corrupt the figure that gates every call."""
    assert estimated_cost(Tier.ANALYSIS, "nonesuch", 1_000, 1_000) == 0.0


def test_record_call_writes_one_row_and_prices_it(session):
    row = record_call(
        session,
        provider="anthropic",
        model_id="claude-haiku-4-5",
        tokens_in=1_000_000,
        tokens_out=0,
        tier=Tier.TRIAGE,
    )
    assert session.query(LlmCallLog).count() == 1
    assert float(row.usd_cost) == pytest.approx(1.0)
    assert row.year_month == year_month()


def test_monthly_spend_sums_and_filters_by_provider(session):
    for provider, cost in (("anthropic", 1.5), ("anthropic", 2.0), ("ollama", 0.0)):
        record_call(
            session, provider=provider, model_id="m", tokens_in=1, tokens_out=1, usd_cost=cost
        )
    assert monthly_spend(session) == pytest.approx(3.5)
    assert monthly_spend(session, provider="anthropic") == pytest.approx(3.5)
    assert monthly_spend(session, provider="ollama") == pytest.approx(0.0)


def test_spend_by_provider_breaks_the_month_down(session):
    record_call(
        session, provider="anthropic", model_id="m", tokens_in=1, tokens_out=1, usd_cost=2.0
    )
    record_call(session, provider="openai", model_id="m", tokens_in=1, tokens_out=1, usd_cost=0.5)
    assert spend_by_provider(session) == {
        "anthropic": pytest.approx(2.0),
        "openai": pytest.approx(0.5),
    }


def test_yesterdays_spend_does_not_count_against_today(session):
    """The daily cap resets. A row from yesterday inside the same month must
    not keep the guard degraded into today."""
    now = datetime.now(UTC)
    yesterday = now - timedelta(days=1)
    record_call(
        session, provider="anthropic", model_id="m", tokens_in=1, tokens_out=1, usd_cost=9.0
    )

    stale = session.query(LlmCallLog).one()
    stale.created_at = yesterday
    # year_month has to move with created_at. It is stamped at insert time, so
    # backdating only the timestamp leaves the row self-inconsistent — and on
    # the 1st of a month that lands the row in a partition its own date does
    # not belong to, which is a test that passes 30 days in 31.
    stale.year_month = yesterday.strftime("%Y-%m")
    session.flush()

    assert spend_on(session, now.date()) == pytest.approx(0.0)
    assert spend_on(session, yesterday.date()) == pytest.approx(9.0)


def test_under_budget_everything_runs(session):
    verdict = BudgetGuard(daily_cap_usd=2.0, monthly_cap_usd=30.0).verdict(session)
    assert verdict.allows_tier is True
    assert verdict.exhausted is False


def test_at_the_degrade_threshold_analysis_pauses_but_not_everything(session):
    """Criterion 4: 80% of the daily cap drops to cheap-tier-only."""
    record_call(
        session,
        provider="anthropic",
        model_id="m",
        tokens_in=1,
        tokens_out=1,
        usd_cost=2.0 * DEGRADE_AT,
    )
    verdict = BudgetGuard(daily_cap_usd=2.0, monthly_cap_usd=30.0).verdict(session)
    assert verdict.allows_tier is False
    assert verdict.exhausted is False, "degraded, not stopped"
    assert "cheap tier" in verdict.detail


def test_at_the_daily_cap_everything_stops(session):
    record_call(
        session, provider="anthropic", model_id="m", tokens_in=1, tokens_out=1, usd_cost=2.0
    )
    verdict = BudgetGuard(daily_cap_usd=2.0, monthly_cap_usd=30.0).verdict(session)
    assert verdict.exhausted is True
    assert "daily" in verdict.detail


def test_the_monthly_ceiling_stops_a_day_that_is_still_under_its_own_cap(session):
    """The outer bound has to bind independently, or thirty cheap days walk
    straight past the monthly envelope."""
    record_call(
        session, provider="anthropic", model_id="m", tokens_in=1, tokens_out=1, usd_cost=30.0
    )
    verdict = BudgetGuard(daily_cap_usd=100.0, monthly_cap_usd=30.0).verdict(session)
    assert verdict.exhausted is True
    assert "monthly" in verdict.detail


def test_the_verdict_feeds_the_router_without_it_touching_the_database(session):
    """The seam that keeps the router unit-testable: the guard produces two
    booleans, the router consumes them."""
    from pestilentia.ai.router import ProviderSpec, Refusal, Router

    record_call(
        session, provider="anthropic", model_id="m", tokens_in=1, tokens_out=1, usd_cost=2.0
    )
    verdict = BudgetGuard(daily_cap_usd=2.0, monthly_cap_usd=30.0).verdict(session)

    cloud = ProviderSpec(name="anthropic", is_local=False, models={Tier.TRIAGE: "m"})
    decision = Router(providers=[cloud]).choose(
        Tier.TRIAGE,
        article_tlp="clear",
        budget_allows_tier=verdict.allows_tier,
        budget_exhausted=verdict.exhausted,
    )
    assert isinstance(decision, Refusal)
