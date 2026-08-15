# "The world is full of obvious things which nobody by any chance ever observes."
"""The confidence gate: score every finding, decide its fate, record both.

Runs after the state machine has finished, not as a ninth state, because it
makes no model calls: it reads rows the machine already wrote and arithmetic
does the rest. Keeping it out of `STATE_ORDER` also keeps it out of the retry
and budget machinery, which exists for things that can fail expensively.

The order is the phase plan's: compose the raw score from four measured
components, apply the two UNODC axes as factors, then compare against the
category floor and the overall one. Every finding gets a `staged_findings` row
whatever the answer, because a gate that only records its refusals cannot be
asked whether its threshold is too high.

**Idempotent.** A second pass over the same article replaces its rows rather
than adding to them, the way `_ground` already replaces findings. The machine is
restartable and the gate has to be too, or a re-analysis would double the queue.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from pestilentia.ai.confidence.composite import (
    Components,
    anchor_ratio,
    composite,
    critic_agreement,
    schema_completeness,
)
from pestilentia.ai.confidence.grading import (
    Corroboration,
    apply_axes,
    corroboration_for_ioc,
    corroboration_for_ttp,
    info_grade_of,
    source_grade_of,
)
from pestilentia.ai.confidence.thresholds import Decision, FindingKind, decide
from pestilentia.ai.enrichment.apply import apply_enrichment
from pestilentia.ai.enrichment.resolver import resolve
from pestilentia.ai.schemas import ExtractedIoc, TtpMapping
from pestilentia.config import Settings
from pestilentia.models.tables import (
    Article,
    ArticleAnalysisRun,
    ArticleIoc,
    ArticleTtp,
    StagedFinding,
)

log = logging.getLogger(__name__)

FINAL_STATE = "verify"


@dataclass
class GateOutcome:
    """What the gate did to one article."""

    scored: int = 0
    auto: int = 0
    staged: int = 0
    enriched_fields: list[str] = field(default_factory=list)
    proposals: int = 0
    skipped_because: str | None = None


def _runs(session: Session, article_id: int) -> dict[str, ArticleAnalysisRun]:
    return {
        row.state: row
        for row in session.scalars(
            select(ArticleAnalysisRun).where(ArticleAnalysisRun.article_id == article_id)
        )
    }


def _critic_for(runs: dict[str, ArticleAnalysisRun]) -> float | None:
    """The judge's verdict on the article, applied to every finding.

    Coarse, and the phase plan says so out loud: the judge audits claims and
    there is no one-to-one map from its claims to finding rows. Building one
    would be a second matching problem with its own errors, so two indicators
    from the same article carry the same critic mark.
    """
    verify = runs.get(FINAL_STATE)
    if verify is None or not verify.raw_output_json:
        return None
    return critic_agreement((verify.raw_output_json.get("output") or {}).get("evidence_quality"))


def _anchor_for(runs: dict[str, ArticleAnalysisRun], state: str) -> float | None:
    run = runs.get(state)
    return anchor_ratio(
        run.raw_output_json.get("grounding") if run and run.raw_output_json else None
    )


def run_gate(
    session: Session,
    article: Article,
    *,
    settings: Settings | None = None,
    local_run: bool = False,
) -> GateOutcome:
    """Score, decide and record every finding this article produced.

    Refuses to run on an article whose analysis did not finish. A gate that
    scored a half-analysed article would be scoring the absence of a critic as
    if it were a critic's silence, and the two are not the same thing.

    The caller commits.
    """
    outcome = GateOutcome()
    runs = _runs(session, article.id)
    verify = runs.get(FINAL_STATE)
    if verify is None or verify.status != "ok":
        outcome.skipped_because = "the analysis has not reached a finished verify"
        return outcome

    # Idempotence: this article's previous verdicts are replaced, not added to.
    session.execute(delete(StagedFinding).where(StagedFinding.article_id == article.id))

    critic = _critic_for(runs)
    source_grade = source_grade_of(article.source.reliability_grade if article.source else None)
    tlp = article.tlp
    model_name = verify.model_id
    prompt_version = verify.prompt_version

    def _record(
        kind: FindingKind,
        payload: dict,
        components: Components,
        info_corroboration,
        *,
        target_table: str | None = None,
        target_row_id: int | None = None,
        run_id: int | None = None,
    ):
        raw = composite(components)
        graded = apply_axes(raw, source_grade, info_grade_of(info_corroboration))
        verdict = decide(graded, kind, local_run=local_run, settings=settings)
        session.add(
            StagedFinding(
                article_id=article.id,
                run_id=run_id,
                finding_kind=kind.value,
                target_table=target_table,
                target_row_id=target_row_id,
                payload_json=payload,
                anchor_ratio=components.anchor_ratio,
                critic_agreement=components.critic_agreement,
                schema_completeness=components.schema_completeness,
                self_assessed=components.self_assessed,
                score_raw=raw,
                source_grade=graded.source_grade.value,
                source_factor_applied=graded.source_factor or 0.0,
                info_grade=graded.info_grade.value,
                info_factor_applied=graded.info_factor or 0.0,
                threshold_applied=verdict.threshold_applied,
                score_total=graded.score_total,
                decision=verdict.decision.value,
                status="pending" if verdict.decision is Decision.STAGED else "not_required",
                tlp=tlp,
                model_name=model_name,
                prompt_version=prompt_version,
                notes=verdict.reason,
            )
        )
        outcome.scored += 1
        if verdict.decision is Decision.AUTO:
            outcome.auto += 1
        else:
            outcome.staged += 1
        return graded, verdict

    ioc_anchor = _anchor_for(runs, "extract_ioc")
    for row in session.scalars(select(ArticleIoc).where(ArticleIoc.article_id == article.id)):
        rebuilt = ExtractedIoc(
            ioc_type=row.ioc_type,
            value=row.value,
            value_as_written=row.value_defanged,
            context=row.context or "",
        )
        graded, _ = _record(
            FindingKind.IOC,
            {"value": row.value, "ioc_type": row.ioc_type},
            Components(
                anchor_ratio=ioc_anchor,
                critic_agreement=critic,
                schema_completeness=schema_completeness(rebuilt),
                self_assessed=None,
                # Structural, not contingent: the schema never asks the model
                # for an indicator's own confidence, so there is no measurement
                # to substitute a neutral for. Leaving the weight in place cost
                # every indicator a fixed 5% and put the 0.85 floor out of
                # reach for the whole category.
                not_applicable=frozenset({"self_assessed"}),
            ),
            corroboration_for_ioc(session, article.id, row.value),
            target_table="article_iocs",
            target_row_id=row.id,
            run_id=row.run_id,
        )
        row.confidence = graded.score_total

    ttp_anchor = _anchor_for(runs, "map_ttp")
    for row in session.scalars(select(ArticleTtp).where(ArticleTtp.article_id == article.id)):
        rebuilt = TtpMapping(
            technique_id=row.technique_id,
            evidence_quote="x",
            confidence=row.confidence if row.confidence is not None else 0.5,
        )
        graded, _ = _record(
            FindingKind.TTP,
            {"value": row.technique_id, "technique_name": row.technique_name},
            Components(
                anchor_ratio=ttp_anchor,
                critic_agreement=critic,
                schema_completeness=schema_completeness(rebuilt),
                # The one category that carries a self-report, per the schema.
                self_assessed=row.confidence,
            ),
            corroboration_for_ttp(session, article.id, row.technique_id),
            target_table="article_ttps",
            target_row_id=row.id,
            run_id=row.run_id,
        )
        row.confidence = graded.score_total

    _gate_prose(session, article, runs, critic, source_grade, outcome, _record, local_run, settings)
    return outcome


def _gate_prose(session, article, runs, critic, source_grade, outcome, record, local_run, settings):
    """Narrative and sketch: the two kinds with no findings table of their own.

    Half of why `staged_findings` exists. They have nowhere else to carry a
    confidence, and without a row here the gate would have nothing to say about
    the two outputs a person actually reads.
    """
    narrative = runs.get("narrative")
    if narrative is not None and narrative.status == "ok" and narrative.raw_output_json:
        output = narrative.raw_output_json.get("output") or {}
        record(
            FindingKind.NARRATIVE,
            {"key_judgement": output.get("key_judgement")},
            Components(
                critic_agreement=critic,
                # Prose has no grounding check and no optional-field count, and
                # the model is not asked to rate its own assessment. Three of
                # the four are structurally absent, so the narrative is scored
                # on the judge's verdict alone and the number says so honestly
                # instead of hiding a single measurement inside four weights.
                not_applicable=frozenset({"anchor_ratio", "schema_completeness", "self_assessed"}),
            ),
            # A written assessment is not the kind of claim our record can
            # confirm or contradict, so its information axis is honestly
            # ungradeable and the narrative always stages. That is the intended
            # answer rather than a limitation: prose is what a person reads, and
            # the gate auto-accepting prose was never the point of it.
            None,
            run_id=narrative.id,
        )

    sketch = runs.get("adversary_sketch")
    if sketch is None or sketch.status != "ok" or not sketch.raw_output_json:
        return

    output = sketch.raw_output_json.get("output") or {}
    actors = _actors_of(output)

    # The sketch's information axis *is* gradeable, unlike the narrative's,
    # because its content is a name the adversary database can confirm. An actor
    # already held is corroborated by everything that put it there; an actor
    # nobody has heard of is an uncorroborated first report, which is grade 3
    # and not grade 6. Asked without creating: grading a name must not be the
    # act that brings it into existence.
    known = [a["name"] for a in actors if resolve(session, a["name"], create=False).matched]
    corroboration = Corroboration(independent_sources=1 if known else 0)

    _, verdict = record(
        FindingKind.SKETCH,
        {"named_actors": actors, "already_known": known},
        Components(
            # Since v3 the sketch is grounded like the extraction states: a name
            # absent from the article is dropped and an unsupported relation is
            # reduced. So it has a survival ratio of its own, and it stops being
            # scored on the judge's verdict alone.
            anchor_ratio=_anchor_for(runs, "adversary_sketch"),
            critic_agreement=critic,
            not_applicable=frozenset({"schema_completeness", "self_assessed"}),
        ),
        corroboration,
        run_id=sketch.id,
    )

    if verdict.decision is not Decision.AUTO:
        return

    # **Only groups the database already holds, and never a new one.** The first
    # corpus run created sixteen, among them "secpo" and "@BonJoviGoesHard",
    # which is a Twitter handle. `named_actors` is defined as the names the
    # article uses, and an article uses plenty of names that are not adversaries.
    # Creating an adversary row from a string is exactly the act that wants a
    # person, so an unresolved actor stays in the staged row's payload for
    # Phase 6 to decide on. The resolver can still create; the gate does not ask
    # it to.
    #
    # **And no cross-aliasing.** The same run proposed every named actor as an
    # alias of every other, so "MOIS", "IRGC Intelligence Organization" and
    # "Handala Hack Team" became aliases of one another. They are three distinct
    # entities that one article happened to mention together. That is the alias
    # collision the design warns about, arrived at by the system itself: nothing
    # in the schema says the names in one article denote one actor.
    for name in known:
        resolved = resolve(session, name, create=False)
        if not resolved.matched:
            continue
        result = apply_enrichment(
            session,
            group=resolved.group,
            article=article,
            # What this article genuinely establishes about the group: the
            # extortion infrastructure and wallets its own indicators name.
            # Both are append-only and both are checkable against the article.
            values=_infrastructure_from(session, article),
            model_name=sketch.model_id or "",
            confidence=1.0,
            tlp=article.tlp,
            run_id=sketch.id,
        )
        outcome.enriched_fields.extend(result.changed_fields)
        outcome.proposals += len(result.proposals)

    # An alias is proposed only where the model said the two names are one actor
    # *and* pointed at a group we hold *and* the article carried a quote that
    # anchored, since the machine reduced the relation otherwise. Three
    # conditions for a claim that merges two adversaries, which is proportionate:
    # it is the one mistake here that nothing downstream can see.
    for name, group in _synonyms(session, actors):
        result = apply_enrichment(
            session,
            group=group,
            article=article,
            values={"aliases": [name]},
            model_name=sketch.model_id or "",
            confidence=1.0,
            tlp=article.tlp,
            run_id=sketch.id,
        )
        outcome.proposals += len(result.proposals)


def _actors_of(output: dict) -> list[dict]:
    """`named_actors`, whichever shape the row was written in.

    Before `adversary_sketch_v3` it was a list of bare strings; now it is a list
    of objects carrying the three identity answers. Both are read, for the same
    reason the two `grounding` shapes are: rewriting what is stored would change
    the meaning of rows already written, and a run from last week has to stay
    comparable with one from today.

    An old string carries no relation, so it reads as `unstated`, which is the
    truth about it: nobody asked.
    """
    actors = []
    for entry in output.get("named_actors") or []:
        if isinstance(entry, str):
            actors.append({"name": entry, "relation": "unstated", "related_to": ""})
        elif isinstance(entry, dict) and entry.get("name"):
            actors.append(entry)
    return actors


def _synonyms(session: Session, actors: list[dict]) -> list[tuple[str, object]]:
    """Names the model called a synonym of a group we hold, and that group.

    The only relation that earns an alias proposal. `affiliate_of` and
    `operator_of` describe two actors and would be falsified by being recorded
    as one name for one of them, which is the whole failure this replaced: the
    gate used to treat co-occurrence as synonymy and merged three entities that
    an article had merely mentioned in the same paragraph.

    Both halves have to hold. The model must say `same_actor`, and the name it
    points at must resolve deterministically to a row. A synonym of something we
    do not hold is a proposal with nothing to attach to.
    """
    pairs = []
    for actor in actors:
        if actor.get("relation") != "same_actor":
            continue
        target = (actor.get("related_to") or "").strip()
        if not target:
            continue
        resolved = resolve(session, target, create=False)
        if resolved.matched and not resolve(session, actor["name"], create=False).matched:
            pairs.append((actor["name"], resolved.group))
    return pairs


#: Indicator types that say something durable about an adversary rather than
#: about one intrusion. A hash rotates and an IP is rented; a leak-site address
#: and a wallet are the operation's own furniture.
INFRASTRUCTURE_TYPES = {"btc_address": "btc_addresses", "url": "profile_urls"}


def _infrastructure_from(session: Session, article: Article) -> dict[str, list[str]]:
    """Wallets and leak-site URLs from this article's indicators that passed.

    Only findings the gate marked `auto` contribute. An indicator the gate would
    not trust on its own has no business being trusted because a sketch beside
    it scored well, and reading them off the staged rows rather than off
    `article_iocs` is what keeps that honest.
    """
    values: dict[str, list[str]] = {}
    rows = session.execute(
        select(StagedFinding.payload_json).where(
            StagedFinding.article_id == article.id,
            StagedFinding.finding_kind == FindingKind.IOC.value,
            StagedFinding.decision == Decision.AUTO.value,
        )
    ).all()
    for (payload,) in rows:
        field_name = INFRASTRUCTURE_TYPES.get((payload or {}).get("ioc_type"))
        if field_name and payload.get("value"):
            values.setdefault(field_name, []).append(payload["value"])
    return values
