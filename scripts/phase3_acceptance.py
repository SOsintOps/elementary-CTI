"""Phase 3 live acceptance — the three criteria, executed and verified.

Runs on the host, never in the image. One real triage decision is carried all
the way through: BudgetGuard verdict from the database, Router.choose, an
actual NIM call on a real article, a `llm_call_logs` row written and read
back, and a second identical call to observe the prefix cache.

The database is named **explicitly** (`--db-url`), because the 2026-08-08
deploy lesson is that a bare run follows `.env` to dev SQLite and reports
success while Postgres lags. The dialect in use is printed first so the
transcript shows which database the evidence lives in.

Usage:
    uv run python scripts/phase3_acceptance.py                # dev SQLite dry-run
    uv run python scripts/phase3_acceptance.py --db-url postgresql://…   # the live run
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from pestilentia.ai.budget import BudgetGuard, estimate_tokens, record_call
from pestilentia.ai.router.decisions import ModelChoice, Tier
from pestilentia.ai.router.nvidia import NvidiaProvider
from pestilentia.ai.router.router import Router
from pestilentia.config import get_settings
from pestilentia.models.base import get_session_factory
from pestilentia.models.tables import Article, LlmCallLog

TRIAGE_INSTRUCTION = (
    "You are a CTI triage assistant. Classify the article below for a "
    "ransomware intelligence pipeline. Answer with exactly one word — "
    "HIGH, MEDIUM or LOW — for how urgently an analyst should read it."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-url", default=None, help="explicit DSN; default is .env dev DB")
    parser.add_argument("--article-id", type=int, default=None)
    args = parser.parse_args()

    settings = get_settings()
    db_url = args.db_url or settings.db_url
    factory = get_session_factory(db_url)

    with factory() as session:
        print(f"database: {session.get_bind().dialect.name} ({db_url.split('@')[-1]})")

        article = _pick_article(session, args.article_id)
        if article is None:
            print("no article with a body to triage; ingest first", file=sys.stderr)
            return 2
        share = article.source.share_with_third_party if article.source else True
        print(f"article: #{article.id} tlp={article.tlp} share={share} — {article.title[:70]}")

        guard = BudgetGuard(settings.ai_daily_budget_usd, settings.ai_monthly_budget_usd)
        verdict = guard.verdict(session)
        print(
            f"budget: spent today ${verdict.spent_today:.4f}, month "
            f"${verdict.spent_this_month:.4f} — {verdict.detail or 'clear to proceed'}"
        )

        body = article.body or ""
        decision = Router(cloud_max=settings.ai_tlp_cloud_max).choose(
            Tier.TRIAGE,
            article_tlp=article.tlp,
            source_share_flag=share,
            estimated_tokens=estimate_tokens(body),
            budget_allows_tier=verdict.allows_tier,
            budget_exhausted=verdict.exhausted,
        )
        if not isinstance(decision, ModelChoice):
            print(f"router refused: {decision.reason.value} — {decision.detail}", file=sys.stderr)
            return 2
        print(f"router: {decision.provider} / {decision.model_id} (local={decision.is_local})")

        provider = NvidiaProvider(settings.ai_nvidia_api_key)
        messages = [
            {"role": "system", "content": TRIAGE_INSTRUCTION},
            {"role": "user", "content": f"{article.title}\n\n{body[:8000]}"},
        ]

        rows: list[int] = []
        cached: list[int] = []
        for attempt in ("first", "second"):
            result = provider.complete(decision.model_id, messages, max_tokens=8)
            row = record_call(
                session,
                provider=decision.provider,
                model_id=result.model_id,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
                tier=Tier.TRIAGE,
                article_id=article.id,
                state="acceptance",
            )
            session.commit()
            rows.append(row.id)
            cached.append(result.cached_tokens)
            print(
                f"{attempt} call: reply={result.text.strip()!r} "
                f"tokens={result.tokens_in}/{result.tokens_out} "
                f"cached={result.cached_tokens} -> llm_call_logs.id={row.id}"
            )

        # Criterion 2: the rows exist where we claim they do — read back cold.
        found = session.scalars(select(LlmCallLog).where(LlmCallLog.id.in_(rows))).all()
        for row in found:
            print(
                f"verified row id={row.id}: {row.provider_name}/{row.model_id} "
                f"{row.year_month} tokens={row.tokens_in}/{row.tokens_out} "
                f"usd={row.usd_cost} state={row.state}"
            )
        if len(found) != 2:
            print("FAIL: cost rows not found on read-back", file=sys.stderr)
            return 3

        # Criterion 3: the repeat of an identical prompt hit the prefix cache.
        if cached[1] <= 0:
            print(
                "FAIL: second identical call reported no cached tokens; cache not observed",
                file=sys.stderr,
            )
            return 3

    print("ACCEPTED: real call made, cost rows verified, cache observed")
    return 0


def _pick_article(session, article_id: int | None) -> Article | None:
    if article_id is not None:
        return session.get(Article, article_id)
    return session.scalars(
        select(Article)
        .where(Article.body.is_not(None))
        .order_by(Article.published_at.desc().nulls_last())
        .limit(1)
    ).first()


if __name__ == "__main__":
    sys.exit(main())
