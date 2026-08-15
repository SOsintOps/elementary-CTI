# "Never trust to general impressions, my boy, but concentrate yourself on details."
"""Writing to the adversary tables, one audited field at a time (step 6).

Every rule in here exists because of a specific way this can go wrong, and the
ways are not equally visible. A wrong indicator is obvious to whoever hunts it.
A wrong alias is not obvious to anybody: it silently merges two adversaries in
an analyst's mind without a single extra row being written, and it keeps doing
so until someone notices that two sets of activity were never the same group.

So the rules, in the order they bite:

**Aliases are always proposals, never writes.** Whatever the score. `Group.aliases`
is only ever changed by a person, and the AI's contribution lands in
`group_alias_proposals` for review. A negative list blocks the collisions that
are already known.

**High-impact fields need two independent sources.** Country of origin and
lineage change what an analyst believes about who is behind something, and a
single article is a single article. Corroboration is counted over
`staged_findings`, which is why that table holds a row for every finding rather
than only for the rejected ones.

**Append, never replace.** The multi-value fields are JSON arrays in `Text`
columns. The AI adds; it does not delete what was already there, and it does not
add a duplicate.

**One audit row per field changed, in the same transaction as the change.** Not
a snapshot of the row: `before_json` holds the previous value of *that field*,
which is what makes `revert.py` a rewrite rather than a reconstruction.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pestilentia.models.tables import (
    AiEnrichmentAudit,
    Article,
    Group,
    GroupAliasProposal,
    StagedFinding,
)

log = logging.getLogger(__name__)

#: `AiEnrichmentAudit.action`, String(16). Distinct from audit.py's
#: `tlp_override` so the two can share the table and still be told apart, which
#: matters because that one writes `confidence=1.0` as a sentinel for a human
#: decision and it must never be averaged into model confidence statistics.
ENRICH_ACTION = "enrich"
REVERT_ACTION = "revert"
#: `AiEnrichmentAudit.decision`, String(16).
AUTO_DECISION = "auto"

#: Fields held as JSON arrays in `Text` columns. Append-only, deduplicated.
ARRAY_FIELDS = ("aliases", "profile_urls", "btc_addresses")

#: Fields that change who an analyst thinks is responsible. One article is one
#: article; these need a second, independent one before they are written.
HIGH_IMPACT_FIELDS = ("country_of_origin", "lineage")

#: Minimum distinct `article_sources` that must have proposed the same value
#: before a high-impact field is written.
CORROBORATION_REQUIRED = 2

#: Known alias collisions: names that look like they identify one group and do
#: not. A module constant rather than a table, decided 2026-08-14: the list is
#: small and curated, and an empty table would be a migration for nothing. If
#: Phase 6 needs it editable without a deploy, Phase 6 opens the migration and
#: this constant becomes its seed. Read from one place so the swap stays a
#: change of source rather than a rewrite.
NEGATIVE_ALIASES: frozenset[str] = frozenset(
    {
        # Umbrella and vendor-cluster names that span several actors.
        "unknown",
        "unattributed",
        "n/a",
        "none",
        "ransomware",
        "raas",
        "affiliate",
        "unc",
        "apt",
        # Ecosystem names routinely written as if they were one group.
        "conti",
        "lockbit affiliate",
        "ransomhub affiliate",
    }
)


@dataclass
class EnrichmentResult:
    """What was written, what was proposed, and what was held back and why."""

    audit_rows: list[AiEnrichmentAudit] = dataclass_field(default_factory=list)
    proposals: list[GroupAliasProposal] = dataclass_field(default_factory=list)
    #: field name -> reason, for everything the rules refused.
    withheld: dict[str, str] = dataclass_field(default_factory=dict)

    @property
    def changed_fields(self) -> list[str]:
        return [row.after_json["field"] for row in self.audit_rows]


def _load_array(raw: str | None) -> list:
    """A JSON array column, as a list. Anything unreadable reads as empty.

    Refusing to parse would block enrichment on a row someone hand-edited years
    ago; treating it as empty would silently drop what is in it. So it reads as
    empty *and* the caller is told, because appending to a value we could not
    read would write a list that discards its own history.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else []


def _is_readable_array(raw: str | None) -> bool:
    if not raw:
        return True
    try:
        return isinstance(json.loads(raw), list)
    except (json.JSONDecodeError, TypeError):
        return False


def corroborating_sources(
    session: Session, finding_kind: str, target_row_id: int, value: str
) -> int:
    """How many distinct feeds have already proposed this value for this target.

    Counted over `staged_findings`, which holds a row for every finding whatever
    the gate decided. A table of only the rejected could not answer this: a
    claim confirmed by three feeds that all passed would look uncorroborated.
    """
    return int(
        session.scalar(
            select(func.count(func.distinct(Article.source_id)))
            .select_from(StagedFinding)
            .join(Article, Article.id == StagedFinding.article_id)
            .where(
                StagedFinding.finding_kind == finding_kind,
                StagedFinding.target_row_id == target_row_id,
                StagedFinding.payload_json["value"].as_string() == value,
                Article.source_id.isnot(None),
            )
        )
        or 0
    )


def _audit(
    *,
    article: Article,
    group: Group,
    field: str,
    before,
    after,
    model_name: str,
    confidence: float,
    tlp: str,
    run_id: int | None,
) -> AiEnrichmentAudit:
    return AiEnrichmentAudit(
        article_id=article.id,
        run_id=run_id,
        table_name="groups",
        row_id=group.id,
        action=ENRICH_ACTION,
        before_json={"field": field, "value": before},
        after_json={"field": field, "value": after},
        model_name=model_name,
        confidence=confidence,
        tlp=tlp,
        decision=AUTO_DECISION,
    )


def apply_enrichment(
    session: Session,
    *,
    group: Group,
    article: Article,
    values: dict[str, object],
    model_name: str,
    confidence: float,
    tlp: str,
    run_id: int | None = None,
) -> EnrichmentResult:
    """Write `values` onto `group`, audited, with the safety rules applied.

    The caller commits. Every audit row is added in the same session as the
    change it describes, so a rollback takes both or neither: an audit row that
    survived a rolled-back change would be a record of something that never
    happened, which is worse than no record at all.

    Nothing here decides *whether* to enrich. The gate decided that; this writes
    what it decided, and refuses the parts its own rules do not allow whatever
    the score was.
    """
    result = EnrichmentResult()

    for name, value in values.items():
        if value is None or value == "" or value == []:
            continue

        if name == "aliases":
            result.proposals.extend(_propose_aliases(session, group, article, value, result))
            continue

        if name in HIGH_IMPACT_FIELDS:
            sources = corroborating_sources(session, name, group.id, str(value))
            if sources < CORROBORATION_REQUIRED:
                result.withheld[name] = (
                    f"{sources} of {CORROBORATION_REQUIRED} independent sources; "
                    "high-impact fields wait for a second one"
                )
                continue

        if name in ARRAY_FIELDS:
            raw = getattr(group, name)
            if not _is_readable_array(raw):
                result.withheld[name] = "the stored value is not a readable JSON array"
                continue
            existing = _load_array(raw)
            incoming = value if isinstance(value, list) else [value]
            fresh = [item for item in incoming if item not in existing]
            if not fresh:
                continue
            after = existing + fresh
            result.audit_rows.append(
                _audit(
                    article=article,
                    group=group,
                    field=name,
                    before=raw,
                    after=json.dumps(after),
                    model_name=model_name,
                    confidence=confidence,
                    tlp=tlp,
                    run_id=run_id,
                )
            )
            setattr(group, name, json.dumps(after))
            continue

        before = getattr(group, name, None)
        if before == value:
            continue
        result.audit_rows.append(
            _audit(
                article=article,
                group=group,
                field=name,
                before=before,
                after=value,
                model_name=model_name,
                confidence=confidence,
                tlp=tlp,
                run_id=run_id,
            )
        )
        setattr(group, name, value)

    for row in result.audit_rows:
        session.add(row)
    for proposal in result.proposals:
        session.add(proposal)
    return result


def _propose_aliases(
    session: Session,
    group: Group,
    article: Article,
    value: object,
    result: EnrichmentResult,
) -> list[GroupAliasProposal]:
    """Aliases go to the queue, always, whatever the confidence.

    A wrong alias is the one mistake here that leaves no trace: it merges two
    adversaries in the reader's mind without adding a row anyone would question.
    So the score never buys a direct write, and the known collisions are blocked
    before a human is even asked.
    """
    proposed = value if isinstance(value, list) else [value]
    existing = {str(a).casefold() for a in _load_array(group.aliases)}
    pending = {
        row.casefold()
        for row in session.scalars(
            select(GroupAliasProposal.proposed_alias).where(GroupAliasProposal.group_id == group.id)
        )
    }

    made: list[GroupAliasProposal] = []
    for alias in proposed:
        text = str(alias).strip()
        if not text:
            continue
        folded = text.casefold()
        if folded in NEGATIVE_ALIASES:
            result.withheld[f"alias:{text}"] = "on the known-collision list"
            continue
        if folded == group.group_name.strip().casefold():
            continue
        if folded in existing or folded in pending:
            continue
        made.append(
            GroupAliasProposal(
                group_id=group.id,
                article_id=article.id,
                proposed_alias=text,
                status="pending",
                notes="proposed by the AI gate; aliases are never written directly",
            )
        )
    return made
