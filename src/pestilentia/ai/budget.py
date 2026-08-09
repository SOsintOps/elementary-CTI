# "I never guess. It is a shocking habit." — Sherlock Holmes, Elementary
"""Spend estimation, enforcement and accounting for LLM calls.

Three jobs, deliberately separable so the router stays cheap to test:

- **Estimate** how many tokens a call will cost, before making it.
- **Decide** whether it may proceed, degrade to the cheap tier, or stop.
- **Record** what it actually cost, one `LlmCallLog` row per call.

The estimate is a heuristic and says so. An exact count needs a tokenizer per
provider, and the guard's job is to stop runaway spend, not to bill accurately
— the recorded row after the fact is where real numbers come from.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pestilentia.ai.router.decisions import Tier
from pestilentia.ai.router.providers import PROVIDERS
from pestilentia.models.tables import LlmCallLog

#: Characters per token. Four is the usual English rule of thumb; security
#: prose sits close to it. Deliberately an under-estimate of token count for
#: dense technical text, which is why it is paired with a hard per-article
#: ceiling rather than trusted alone.
CHARS_PER_TOKEN = 4

#: Fraction of the daily cap past which analysis-tier calls stop and only the
#: cheap tier continues. Roadmap phase 3, criterion 4.
DEGRADE_AT = 0.80


def estimate_tokens(text: str) -> int:
    """Rough input-token count. See CHARS_PER_TOKEN — this is a guard rail,
    not an invoice."""
    return max(1, len(text) // CHARS_PER_TOKEN)


def year_month(moment: datetime | None = None) -> str:
    """The `LlmCallLog.year_month` partition key, always UTC so a spend window
    does not shift with local time."""
    return (moment or datetime.now(UTC)).strftime("%Y-%m")


@dataclass(frozen=True)
class BudgetVerdict:
    """What the guard tells the router. Deliberately plain data: the router
    takes these two booleans and never queries the database itself."""

    allows_tier: bool
    exhausted: bool
    spent_today: float
    spent_this_month: float
    detail: str = ""


class BudgetGuard:
    """Reads spend from `LlmCallLog` and answers whether more may be spent."""

    def __init__(
        self,
        daily_cap_usd: float,
        monthly_cap_usd: float,
        degrade_at: float = DEGRADE_AT,
    ) -> None:
        self.daily_cap_usd = daily_cap_usd
        self.monthly_cap_usd = monthly_cap_usd
        self.degrade_at = degrade_at

    def verdict(self, session: Session, today: date | None = None) -> BudgetVerdict:
        spent_today = spend_on(session, today or datetime.now(UTC).date())
        spent_month = monthly_spend(session)

        if spent_month >= self.monthly_cap_usd:
            return BudgetVerdict(False, True, spent_today, spent_month, "monthly ceiling reached")
        if spent_today >= self.daily_cap_usd:
            return BudgetVerdict(False, True, spent_today, spent_month, "daily ceiling reached")
        if spent_today >= self.daily_cap_usd * self.degrade_at:
            return BudgetVerdict(
                False,
                False,
                spent_today,
                spent_month,
                f"past {self.degrade_at:.0%} of the daily cap; cheap tier only",
            )
        return BudgetVerdict(True, False, spent_today, spent_month)


def estimated_cost(tier: Tier, provider: str, tokens_in: int, tokens_out: int) -> float:
    """Price a hypothetical call. Unknown provider or tier costs nothing —
    a local model is genuinely free, and an unpriced one must not silently
    inflate the spend figure that gates everything else."""
    spec = PROVIDERS.get(provider)
    if spec is None or tier not in spec.pricing:
        return 0.0
    return spec.pricing[tier].usd(tokens_in, tokens_out)


def record_call(
    session: Session,
    *,
    provider: str,
    model_id: str,
    tokens_in: int,
    tokens_out: int,
    usd_cost: float | None = None,
    tier: Tier | None = None,
    article_id: int | None = None,
    run_id: int | None = None,
    state: str | None = None,
) -> LlmCallLog:
    """Write one row per call. Cost is computed from the registry when not
    supplied, so a caller cannot forget to price a call and quietly shrink the
    number the budget gate depends on."""
    if usd_cost is None:
        usd_cost = estimated_cost(tier, provider, tokens_in, tokens_out) if tier else 0.0
    row = LlmCallLog(
        article_id=article_id,
        run_id=run_id,
        provider_name=provider,
        model_id=model_id,
        year_month=year_month(),
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        usd_cost=usd_cost,
        state=state,
    )
    session.add(row)
    session.flush()
    return row


def monthly_spend(session: Session, provider: str | None = None, month: str | None = None) -> float:
    """Spend for a calendar month, optionally for one provider."""
    query = select(func.coalesce(func.sum(LlmCallLog.usd_cost), 0)).where(
        LlmCallLog.year_month == (month or year_month())
    )
    if provider is not None:
        query = query.where(LlmCallLog.provider_name == provider)
    return float(session.scalar(query) or 0)


def spend_on(session: Session, day: date) -> float:
    """Spend for one UTC day.

    Filtered in Python on a month-scoped query rather than with a SQL date cast:
    `created_at` is naive on SQLite and tz-aware on PostgreSQL, and a cast that
    works on one silently shifts the window on the other.
    """
    rows = session.scalars(
        select(LlmCallLog).where(LlmCallLog.year_month == day.strftime("%Y-%m"))
    ).all()
    total = 0.0
    for row in rows:
        stamp = row.created_at
        if stamp is None:
            continue
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone(UTC)
        if stamp.date() == day:
            total += float(row.usd_cost)
    return total


def spend_by_provider(session: Session, month: str | None = None) -> dict[str, float]:
    """Monthly spend broken down per provider — roadmap phase 3, criterion 3."""
    rows = session.execute(
        select(LlmCallLog.provider_name, func.sum(LlmCallLog.usd_cost))
        .where(LlmCallLog.year_month == (month or year_month()))
        .group_by(LlmCallLog.provider_name)
    ).all()
    return {name: float(total or 0) for name, total in rows}
