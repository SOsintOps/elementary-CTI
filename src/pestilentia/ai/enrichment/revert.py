# "When you have eliminated the impossible..." — Sherlock Holmes
"""Undoing an enrichment by rewriting what was there (Phase 5, step 7).

Roadmap criterion 5 asks for reversibility, and there are two ways to build it.
One reconstructs the previous state by working backwards through the change.
The other stores the previous value and writes it back. This is the second, and
the reason is that the first is only as good as its model of the change: an
append that deduplicated, applied in reverse, cannot tell which entries it
added from which were already there.

So `before_json` on the audit row holds the previous value of that one field,
verbatim, and reverting is `setattr`. That is why `apply.py` writes one row per
field rather than a snapshot per row: a snapshot would make the unit of reversal
the whole `Group`, and undoing one bad country of origin would also undo every
good BTC address written in the same pass.

**The revert is itself audited.** It writes its own rows with `action="revert"`,
so the history reads forwards: enriched, then reverted, by whom, when. Silently
erasing the enrichment audit row would make the database agree with itself about
a past that did not happen.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from pestilentia.ai.enrichment.apply import ENRICH_ACTION, REVERT_ACTION
from pestilentia.models.tables import AiEnrichmentAudit, Group

log = logging.getLogger(__name__)

#: `AiEnrichmentAudit.decision` for a reversal. A person asked for it.
REVERT_DECISION = "reverted"


class NotRevertibleError(ValueError):
    """The audit row does not describe something this module can undo.

    Raised rather than skipped. A revert that quietly did nothing would report
    success on a change still in the database, and the caller would have no way
    to tell that apart from a change that was genuinely undone.
    """


def revert_audit_row(
    session: Session,
    row: AiEnrichmentAudit,
    *,
    actor: str,
) -> AiEnrichmentAudit:
    """Put one field back the way it was, and record that this happened.

    The caller commits, for the same reason `apply_enrichment` leaves it to the
    caller: the reversal and its audit row must land together or not at all.
    """
    if row.action != ENRICH_ACTION:
        raise NotRevertibleError(
            f"audit row {row.id} has action {row.action!r}; only {ENRICH_ACTION!r} rows "
            "describe a field this module wrote"
        )
    if row.table_name != "groups":
        raise NotRevertibleError(f"audit row {row.id} targets {row.table_name!r}, not groups")
    if not row.before_json or "field" not in row.before_json:
        raise NotRevertibleError(f"audit row {row.id} carries no before value to write back")

    group = session.get(Group, row.row_id)
    if group is None:
        raise NotRevertibleError(f"group {row.row_id} no longer exists")

    field = row.before_json["field"]
    previous = row.before_json.get("value")
    current = getattr(group, field, None)
    setattr(group, field, previous)

    entry = AiEnrichmentAudit(
        article_id=row.article_id,
        run_id=row.run_id,
        table_name=row.table_name,
        row_id=row.row_id,
        action=REVERT_ACTION,
        before_json={"field": field, "value": current},
        after_json={"field": field, "value": previous},
        model_name=row.model_name,
        # The model's confidence is not this decision's confidence: a person
        # asked for the reversal. Carried over unchanged rather than invented,
        # and readable as a revert row by its action, which is how any query
        # that averages model confidence must exclude it.
        confidence=row.confidence,
        tlp=row.tlp,
        decision=REVERT_DECISION,
        decided_by=actor,
        notes=f"reverts audit row {row.id}",
    )
    session.add(entry)
    return entry


def revert_article(session: Session, article_id: int, *, actor: str) -> list[AiEnrichmentAudit]:
    """Undo every field this article's enrichment wrote, newest first.

    Newest first because two passes over the same article can have written the
    same field twice, and replaying the older `before` value last would restore
    the state before the first write, which is the one the reviewer meant. Doing
    it oldest-first would leave the second pass's value in place.
    """
    rows = list(
        session.scalars(
            select(AiEnrichmentAudit)
            .where(
                AiEnrichmentAudit.article_id == article_id,
                AiEnrichmentAudit.action == ENRICH_ACTION,
            )
            .order_by(AiEnrichmentAudit.id.desc())
        )
    )
    reverted = []
    for row in rows:
        reverted.append(revert_audit_row(session, row, actor=actor))
    log.info("reverted %s enrichment rows for article %s", len(reverted), article_id)
    return reverted
