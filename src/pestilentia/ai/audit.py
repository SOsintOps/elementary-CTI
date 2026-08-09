# "There is nothing more deceptive than an obvious fact." — Sherlock Holmes
"""Audit trail for deliberate crossings of the TLP boundary.

When an analyst sends restricted content to a third-party provider anyway, the
decision has to survive them: an entry that answers *who authorised it, why,
what was sent, and where it went* long after the session is closed.

Rows land in `ai_enrichment_audit`, which already carries `decided_by`,
`decided_at` and `notes`. Reusing it avoids a migration and keeps every
human decision about an article in one place, which is where a reviewer will
look for them.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from pestilentia.ai.router.decisions import ModelChoice
from pestilentia.ai.tlp import coerce_tlp
from pestilentia.models.tables import AiEnrichmentAudit

log = logging.getLogger(__name__)

#: `AiEnrichmentAudit.action` and `.decision`, both String(16).
OVERRIDE_ACTION = "tlp_override"
OVERRIDE_DECISION = "override"


class MissingOverrideError(ValueError):
    """Raised when a crossing would go unrecorded.

    Failing the call is the point. If writing the audit row could be skipped,
    the boundary would be crossable without a trace, which is the situation the
    override exists to avoid.
    """


def record_tlp_override(
    session: Session,
    *,
    article_id: int,
    article_tlp: str | None,
    choice: ModelChoice,
    source_share_flag: bool = True,
    run_id: int | None = None,
) -> AiEnrichmentAudit:
    """Write one row per crossing. Call this before the request goes out.

    Ordering matters: the record is written first, so a crash mid-call leaves
    evidence that content was about to be sent. The reverse order can lose the
    only trace of a request that actually left.
    """
    if not choice.requires_audit or choice.override is None:
        raise MissingOverrideError(
            "record_tlp_override called for a decision that crossed no boundary; "
            "branch on ModelChoice.requires_audit"
        )

    override = choice.override
    row = AiEnrichmentAudit(
        article_id=article_id,
        run_id=run_id,
        table_name="articles",
        row_id=article_id,
        action=OVERRIDE_ACTION,
        before_json={
            "tlp": coerce_tlp(article_tlp).value,
            "source_share_with_third_party": source_share_flag,
        },
        # Destination recorded explicitly. "It left the building" is not enough
        # for a review — which third party received it is the question that
        # actually gets asked.
        after_json={
            "provider": choice.provider,
            "model_id": choice.model_id,
            "tier": choice.tier.value,
            "is_local": choice.is_local,
            "source_ban_acknowledged": override.acknowledge_source_ban,
        },
        model_name=choice.model_id[:64],
        # NOT NULL on the table and meaningless here: a human decision has no
        # model confidence. Stored as 1.0 and disambiguated by `decision`,
        # rather than inventing a score that a later query might average in.
        confidence=1.0,
        tlp=coerce_tlp(article_tlp).value,
        decision=OVERRIDE_DECISION,
        decided_at=datetime.now(UTC),
        decided_by=override.actor[:64],
        notes=override.justification[:2048],
    )
    session.add(row)
    session.flush()

    log.warning(
        "TLP override: article %s (%s) sent to %s/%s by %s — %s",
        article_id,
        row.tlp,
        choice.provider,
        choice.model_id,
        override.actor,
        override.justification,
    )
    return row


def overrides_for_article(session: Session, article_id: int) -> list[AiEnrichmentAudit]:
    """Every crossing recorded for one article, oldest first."""
    return list(
        session.scalars(
            select(AiEnrichmentAudit)
            .where(
                AiEnrichmentAudit.article_id == article_id,
                AiEnrichmentAudit.action == OVERRIDE_ACTION,
            )
            .order_by(AiEnrichmentAudit.created_at)
        )
    )


def recent_overrides(session: Session, limit: int = 50) -> list[AiEnrichmentAudit]:
    """Newest crossings across the corpus — the review surface."""
    return list(
        session.scalars(
            select(AiEnrichmentAudit)
            .where(AiEnrichmentAudit.action == OVERRIDE_ACTION)
            .order_by(AiEnrichmentAudit.created_at.desc())
            .limit(limit)
        )
    )
