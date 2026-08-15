# "When you have eliminated the impossible..." — Sherlock Holmes
"""The runner: eight states, one row each, restartable from wherever it stopped.

The shape is the whole point (ADR-006 §1). Each state writes its own
`ArticleAnalysisRun` row and that row is committed the moment it closes, so a
crash at `MapTTP` does not throw away the `ExtractIOC` that was already paid
for. A second run reads the rows, rebuilds what the finished states produced,
and starts at the first one that is not `ok`.

Nothing here opens a socket. The router, the providers and the ATT&CK catalogue
are all parameters, which is what makes every branch — refusal, retry,
escalation, staging — reachable in a test with no key and no network, the same
discipline that already makes `Router` testable.

Three policies live here rather than in the caller:

**Refusal stops the run.** A router refusal is a decision about the article, not
an error: the row records it and the states after it are never attempted.
`blocked_tlp` in particular is terminal until a human acts, and running the next
state anyway would be an attempt to send the same content to the same place.

**Re-ask, then escalate, then stage.** Two retries on the same model when the
output does not satisfy the schema, then one attempt a tier up, then the state is
`staged` for a human. Only triage has a tier above it; analysis and judge have
nowhere to escalate to and go straight to staged, because spending the same
money twice is not a policy.

**The audit is not run by the model it audits.** `verify` is served by
`Tier.JUDGE` — a different model family — and when nothing serves that tier the
state refuses rather than falling back. An audit by the generator produces
labels, an evidence-quality rating and, in Phase 5, a confidence number: it
*looks* like an audit. A missing audit is visible; a self-audit is not.

**A model that cannot be reached is not a model that answered wrongly.** Schema
failures end in `staged`, transport failures in `error`. They lead to different
actions: one is a prompt or a model problem to look at, the other is an outage to
wait out.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from pestilentia.ai.audit import record_tlp_override
from pestilentia.ai.budget import BudgetGuard, estimate_tokens, record_call
from pestilentia.ai.extraction import iocs, ttps
from pestilentia.ai.extraction.anchors import AnchorIndex, anchor_quote
from pestilentia.ai.extraction.attack_catalog import AttackCatalog
from pestilentia.ai.prompts import PROMPTS, ArticleContext, render
from pestilentia.ai.router.decisions import ModelChoice, Refusal, Tier, TlpOverride
from pestilentia.ai.router.router import Router
from pestilentia.ai.schemas import (
    STATE_ORDER,
    STATE_SCHEMAS,
    ActorRelation,
    AdversarySketchOutput,
    ClassifyOutput,
    ConfidenceLevel,
    DiamondModelOutput,
    DiamondVertex,
    ExtractedIoc,
    ExtractIocOutput,
    MapTtpOutput,
    NamedActor,
    NarrativeOutput,
    TriageOutput,
    TtpMapping,
)
from pestilentia.ai.style import check as style_check
from pestilentia.models.tables import (
    Article,
    ArticleAnalysisRun,
    ArticleIoc,
    ArticleTtp,
    Group,
)

log = logging.getLogger(__name__)

#: ADR-006 §1: two retries on the same model before the tier changes.
RETRIES_PER_MODEL = 2

#: Seconds to wait after a call that never landed, per attempt already made.
#: Schema failures are re-asked immediately — the model is there and answering —
#: but a transport failure means the far end is unwell, and the acceptance run
#: spent all three attempts inside a few seconds against a provider returning
#: "no capacity". Retrying a busy service at full speed is how a queue becomes
#: an outage.
BACKOFF_SECONDS = (5.0, 15.0, 30.0)

#: `raw_output_json` is a wrapper, not the output itself, so the grounding
#: verdict has somewhere to live without colliding with a schema field.
OUTPUT_KEY = "output"
GROUNDING_KEY = "grounding"
#: Where the residual house-style violations sit, beside the grounding verdict
#: and for the same reason: a row has to say what was checked and what survived,
#: or a reader cannot tell a clean text from an unexamined one.
STYLE_KEY = "style"

#: The prose fields each state writes for a human, and whether counsel belongs
#: in them. `recommendations_md` is the one field whose whole job is advice; in
#: every other field advice is a rule violation, which is why the flag travels
#: with the field name rather than being decided at the call site.
PROSE_FIELDS: dict[str, tuple[tuple[str, bool], ...]] = {
    "narrative": (
        ("key_judgement", False),
        ("summary_md", False),
        ("recommendations_md", True),
    ),
    "adversary_sketch": (
        ("cluster_summary", False),
        ("shared_infrastructure_note", False),
        ("false_flag_note", False),
    ),
}

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)

#: Which tier serves which state. `verify` is the only one that is not simply
#: "cheap first, then the good model": it audits what the other states wrote, so
#: it is served by a different model family (`Tier.JUDGE`). A model asked to
#: audit itself grades its own homework, and Phase 5 folds this state's verdict
#: into a confidence score — where the flaw would stop being visible and become
#: a number.
STATE_TIERS: dict[str, Tier] = {"triage": Tier.TRIAGE, "verify": Tier.JUDGE}

#: One step down the ladder, for an assertion whose evidence cannot be produced.
#: `LOW` has nowhere further to fall and stays where it is: inventing a fourth
#: level to say "worse than low" would change the scale every other reader of
#: this field already understands, which is a bigger claim than the one being
#: corrected.
_ONE_LEVEL_DOWN: dict[ConfidenceLevel, ConfidenceLevel] = {
    ConfidenceLevel.HIGH: ConfidenceLevel.MODERATE,
    ConfidenceLevel.MODERATE: ConfidenceLevel.LOW,
    ConfidenceLevel.LOW: ConfidenceLevel.LOW,
}


class RunStatus(StrEnum):
    """`ArticleAnalysisRun.status`. String(16), so these stay short.

    Refusal reasons are written verbatim from `RefusalReason` and are not
    repeated here — they are the router's vocabulary, and duplicating them
    would let the two drift.
    """

    PENDING = "pending"  # in flight; a crash leaves this behind
    OK = "ok"
    #: Triage read the article and said no. The state succeeded — the verdict
    #: is what stopped the run — but it is written here rather than left in the
    #: output, because otherwise the only way to tell a dropped article from one
    #: that crashed after triage is to read JSON out of the row.
    DROPPED = "dropped"
    STAGED = "staged"  # the model never produced output the schema accepts
    ERROR = "error"  # the provider could not be reached


class Completer(Protocol):
    """What the machine needs of a provider — one method, no SDK in sight."""

    def complete(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        max_tokens: int = ...,
        temperature: float = ...,
    ) -> Any: ...


@dataclass(frozen=True)
class StateResult:
    state: str
    status: str
    output: BaseModel | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        """The state produced output its schema accepted.

        `dropped` counts: triage answering "not relevant" is a successful
        triage. What stops the run is the verdict, not a failure.
        """
        return self.status in (RunStatus.OK, RunStatus.DROPPED)


@dataclass(frozen=True)
class RunReport:
    """What one pass over the article did, including the states it skipped.

    `stopped_because` is the sentence an operator reads. A run that ends early
    because triage said no and a run that ends early because the content may not
    leave the building are both "incomplete", and telling them apart from the
    rows alone means reading the last one and knowing the vocabulary.
    """

    article_id: int
    results: tuple[StateResult, ...]
    reused: tuple[str, ...] = ()
    stopped_at: str | None = None
    stopped_because: str = ""

    @property
    def completed(self) -> bool:
        return self.stopped_at is None


def _style_violations(
    output: BaseModel, fields: tuple[tuple[str, bool], ...]
) -> list[dict[str, str]]:
    """Every house-style breach in this output's prose, with the words."""
    found: list[dict[str, str]] = []
    for name, advice_allowed in fields:
        text = getattr(output, name, "") or ""
        for violation in style_check(text, advice_allowed=advice_allowed):
            found.append(
                {
                    "field": name,
                    "rule": violation.rule,
                    "text": violation.text[:120],
                    "note": violation.note,
                }
            )
    return found


def _parse(text: str) -> dict:
    """The JSON in a model's answer, however it wrapped it.

    Lenient about packaging — a markdown fence, a sentence before the object —
    and not lenient about anything else. Every field still goes through the
    schema; this only avoids paying for a retry because a model could not resist
    a code fence.
    """
    stripped = _FENCE.sub("", text.strip())
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(stripped[start : end + 1])


def _rehydrate(state: str, stored: Mapping[str, Any] | None) -> BaseModel | None:
    """Rebuild a finished state's output from its row.

    Computed fields are dropped rather than validated: `model_dump` writes them
    into the row, which is what makes a stored row readable on its own, but the
    schemas forbid unknown fields on the way back in.
    """
    if not stored:
        return None
    payload = stored.get(OUTPUT_KEY)
    if not isinstance(payload, dict):
        return None
    schema = STATE_SCHEMAS[state]
    known = {key: value for key, value in payload.items() if key in schema.model_fields}
    try:
        return schema.model_validate(known)
    except ValidationError:
        log.warning("state %s has a stored output its schema no longer accepts", state)
        return None


class ExtractionMachine:
    """Runs an article through the eight states, or explains why it stopped."""

    def __init__(
        self,
        router: Router,
        providers: Mapping[str, Completer],
        catalog: AttackCatalog,
        budget: BudgetGuard | None = None,
        max_tokens: int | None = None,
        retries_per_model: int = RETRIES_PER_MODEL,
        pacer: Callable[[], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._router = router
        self._providers = providers
        self._catalog = catalog
        self._budget = budget
        # None means "whatever each prompt asked for". An explicit value is a
        # ceiling for a deployment that wants one, not the normal case.
        self._max_tokens = max_tokens
        self._retries = retries_per_model
        # Called immediately before each request. The rate limit belongs to the
        # provider account, not to any one article, so it is imposed where the
        # requests are and injected by whoever knows the account's limit.
        self._pacer = pacer
        self._sleep = sleep

    # -- the pass over the states ----------------------------------------

    def run(
        self,
        session: Session,
        article: Article,
        override: TlpOverride | None = None,
    ) -> RunReport:
        if not article.body:
            return RunReport(
                article_id=article.id,
                results=(),
                stopped_at=STATE_ORDER[0],
                stopped_because="the article has no body to analyse",
            )

        context = ArticleContext(
            title=article.title,
            body=article.body,
            source=article.source.name if article.source else "",
            published=article.published_at.isoformat() if article.published_at else "",
        )
        existing = {
            row.state: row
            for row in session.scalars(
                select(ArticleAnalysisRun).where(ArticleAnalysisRun.article_id == article.id)
            )
        }

        prior: dict[str, BaseModel] = {}
        results: list[StateResult] = []
        reused: list[str] = []

        for state in STATE_ORDER:
            row = existing.get(state)
            if row is not None and row.status in (RunStatus.OK, RunStatus.DROPPED):
                # Idempotent restart: a finished state is not paid for twice,
                # and the later prompts need what it produced.
                restored = _rehydrate(state, row.raw_output_json)
                if restored is not None:
                    prior[state] = restored
                    reused.append(state)
                    # Project again on the way past. It costs nothing, it is
                    # idempotent, and it repairs an article whose columns were
                    # emptied — or, as here, never filled, because the run
                    # predates the projection.
                    self._project(article, restored)
                    if self._irrelevant(state, restored):
                        return self._stop(article, results, reused, state, "triage: not relevant")
                    continue
                log.warning("re-running %s for %s: stored output unusable", state, article.id)

            result = self._run_state(session, article, context, state, prior, override)
            session.commit()
            results.append(result)

            if not result.ok:
                return self._stop(article, results, reused, state, result.detail or result.status)
            assert result.output is not None  # ok implies output
            prior[state] = result.output
            if self._irrelevant(state, result.output):
                return self._stop(article, results, reused, state, "triage: not relevant")

        return RunReport(article_id=article.id, results=tuple(results), reused=tuple(reused))

    @staticmethod
    def _irrelevant(state: str, output: BaseModel) -> bool:
        """Triage's whole purpose: stop before the analysis tier is touched."""
        return state == "triage" and isinstance(output, TriageOutput) and not output.relevant

    @staticmethod
    def _stop(
        article: Article,
        results: list[StateResult],
        reused: list[str],
        state: str,
        because: str,
    ) -> RunReport:
        return RunReport(
            article_id=article.id,
            results=tuple(results),
            reused=tuple(reused),
            stopped_at=state,
            stopped_because=because,
        )

    # -- one state --------------------------------------------------------

    def _known_adversaries(self, session: Session, state: str) -> list[str] | None:
        """The adversary names the database holds, for the prompts that ask.

        Read per state rather than cached on the machine: the sketch is one call
        per article and the query is a single column off a small table, where a
        cache would buy microseconds and cost correctness the first time a run
        creates a group mid-batch.

        Names only. No id crosses into a prompt, which is roadmap criterion 3,
        and the resolver still does the resolving.
        """
        if not PROMPTS[state].wants_known_adversaries:
            return None
        return list(session.scalars(select(Group.group_name).where(Group.group_name != "")))

    def _run_state(
        self,
        session: Session,
        article: Article,
        context: ArticleContext,
        state: str,
        prior: Mapping[str, BaseModel],
        override: TlpOverride | None,
    ) -> StateResult:
        prompt = render(state, context, prior, self._known_adversaries(session, state))
        budget = self._max_tokens or PROMPTS[state].max_output_tokens
        row = self._row_for(session, article, state, prompt.fingerprint)
        estimated = estimate_tokens(prompt.system + prompt.user)
        tier = STATE_TIERS.get(state, Tier.ANALYSIS)

        # Same model until the retries are used up, then one tier higher. The
        # analysis tier has nothing above it, so its ladder simply ends.
        ladder = [tier] * (1 + self._retries)
        if tier is Tier.TRIAGE:
            ladder.append(Tier.ANALYSIS)

        detail = ""
        unreachable = False
        for attempt_tier in ladder:
            decision = self._choose(session, article, attempt_tier, estimated, override)
            if isinstance(decision, Refusal):
                return self._close(row, decision.reason.value, detail=decision.detail)

            row.attempts += 1
            if decision.requires_audit:
                record_tlp_override(
                    session,
                    article_id=article.id,
                    article_tlp=article.tlp,
                    choice=decision,
                    source_share_flag=self._share_flag(article),
                    run_id=row.id,
                )

            provider = self._providers.get(decision.provider)
            if provider is None:
                return self._close(
                    row,
                    RunStatus.ERROR,
                    detail=f"router chose {decision.provider!r}, which is not wired in",
                )

            if self._pacer is not None:
                self._pacer()

            try:
                # The only foreign call in the machine, and the only thing this
                # `except` is allowed to be hiding.
                result = provider.complete(decision.model_id, prompt.messages, max_tokens=budget)
            except Exception as exc:  # a provider's failure modes are its own
                detail, unreachable = f"{decision.provider}: {exc}", True
                log.warning("state %s call failed on attempt %s: %s", state, row.attempts, exc)
                self._back_off(row.attempts)
                continue

            record_call(
                session,
                provider=decision.provider,
                model_id=result.model_id,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
                tier=attempt_tier,
                article_id=article.id,
                run_id=row.id,
                state=state,
            )
            row.model_id = result.model_id
            row.tokens_in = result.tokens_in
            row.tokens_out = result.tokens_out

            try:
                output = STATE_SCHEMAS[state].model_validate(_parse(result.text))
            except (ValidationError, json.JSONDecodeError) as exc:
                if result.tokens_out >= budget:
                    # Not a schema failure in any useful sense: the answer was
                    # cut off mid-object. Saying so is the difference between
                    # rewriting a prompt and raising a number.
                    detail = (
                        f"answer cut off at the {budget}-token ceiling for {state}; "
                        f"raise Prompt.max_output_tokens ({exc})"
                    )
                else:
                    detail = f"output rejected by {state} schema: {exc}"
                unreachable = False
                log.info("state %s attempt %s did not validate", state, row.attempts)
                continue

            grounded, grounding = self._ground(session, article, row, output)
            grounded, style = self._restyle(provider, decision, prompt, state, grounded, budget)
            stored: dict[str, Any] = {OUTPUT_KEY: grounded.model_dump(mode="json")}
            if grounding is not None:
                stored[GROUNDING_KEY] = grounding
            if style is not None:
                stored[STYLE_KEY] = style
            row.raw_output_json = stored
            self._project(article, grounded)
            verdict = RunStatus.DROPPED if self._irrelevant(state, grounded) else RunStatus.OK
            return self._close(row, verdict, output=grounded)

        # Every rung used. Which status depends on how the last rung failed:
        # a model that answered wrongly is a prompt problem for a human, a model
        # that never answered is an outage to wait out.
        return self._close(row, RunStatus.ERROR if unreachable else RunStatus.STAGED, detail=detail)

    def _restyle(
        self,
        provider: Completer,
        decision: ModelChoice,
        prompt: Any,
        state: str,
        output: BaseModel,
        budget: int,
    ) -> tuple[BaseModel, dict[str, Any] | None]:
        """Name the offending words, ask once for a rewrite, keep the better one.

        The measurement that produced this: the style block forbids advice in a
        summary and forbids vagueness, and across seventy regenerated articles
        those two defects moved from 13 to 12 and from 60 to 56. Two different
        wordings of the rule, the same result.

        The diagnosis is in the asymmetry. The block states rules **in general**
        and before the text exists; a violation names **the words in this text**.
        Only the second is information the model did not already have, and it is
        the same reason `iocs.reconcile` does not ask a model to be accurate but
        tells it which indicator is not in the article.

        **Once, not in a loop.** A model that does not fix it on the second
        occasion does not fix it on the fifth, and paying for five to find that
        out is the worst way to find it out.

        What survives is recorded rather than refused. At two violations per
        assessment, staging everything that has one would queue the whole
        corpus, and a queue holding everything is not a queue: it is a refusal
        to work wearing the clothes of rigour.
        """
        fields = PROSE_FIELDS.get(state)
        if fields is None:
            return output, None

        found = _style_violations(output, fields)
        if not found:
            return output, {"violations": [], "rewritten": False}

        rewritten = self._ask_for_a_rewrite(provider, decision, prompt, state, found, budget)
        if rewritten is not None:
            after = _style_violations(rewritten, fields)
            if len(after) < len(found):
                log.info(
                    "state %s restyled: %s violations became %s", state, len(found), len(after)
                )
                return rewritten, {"violations": after, "rewritten": True}

        return output, {"violations": found, "rewritten": rewritten is not None}

    def _ask_for_a_rewrite(
        self,
        provider: Completer,
        decision: ModelChoice,
        prompt: Any,
        state: str,
        found: list[dict[str, str]],
        budget: int,
    ) -> BaseModel | None:
        """One follow-up turn, carrying the exact words that broke the rules."""
        complaints = "\n".join(
            f"- {item['field']}: {item['text']!r} breaks {item['rule']} — {item['note']}"
            for item in found[:12]
        )
        messages = [
            *prompt.messages,
            {
                "role": "user",
                "content": (
                    "Your answer broke the house style in the places listed below. "
                    "Rewrite it, fixing exactly these and changing nothing else about "
                    "what it says. Same JSON schema, no commentary.\n\n" + complaints
                ),
            },
        ]
        try:
            result = provider.complete(decision.model_id, messages, max_tokens=budget)
            return STATE_SCHEMAS[state].model_validate(_parse(result.text))
        except Exception as exc:  # a rewrite is an improvement, never a requirement
            log.info("state %s rewrite did not land: %s", state, exc)
            return None

    def _back_off(self, attempts: int) -> None:
        """Wait before asking again, longer each time, and never on the last."""
        index = min(attempts, len(BACKOFF_SECONDS)) - 1
        if 0 <= index < len(BACKOFF_SECONDS):
            self._sleep(BACKOFF_SECONDS[index])

    def _choose(
        self,
        session: Session,
        article: Article,
        tier: Tier,
        estimated: int,
        override: TlpOverride | None,
    ) -> ModelChoice | Refusal:
        verdict = self._budget.verdict(session) if self._budget else None
        return self._router.choose(
            tier=tier,
            article_tlp=article.tlp,
            source_share_flag=self._share_flag(article),
            estimated_tokens=estimated,
            budget_allows_tier=verdict.allows_tier if verdict else True,
            budget_exhausted=verdict.exhausted if verdict else False,
            override=override,
        )

    @staticmethod
    def _share_flag(article: Article) -> bool:
        source = article.source
        return True if source is None else bool(source.share_with_third_party)

    def _project(self, article: Article, output: BaseModel) -> None:
        """Copy the two findings the rest of the application already reads.

        `Article.article_type`, `summary_md` and `recommendations_md` predate
        this pipeline and are what the article pages, the list filters and the
        exports render. Leaving the analysis only in `raw_output_json` would
        mean the run succeeded and the site showed nothing (roadmap criterion 5
        names these columns).

        A projection, not a second source of truth: the run row stays
        authoritative, and re-running the state overwrites these.
        """
        if isinstance(output, ClassifyOutput):
            article.article_type = output.article_type.value
        elif isinstance(output, NarrativeOutput):
            article.summary_md = output.summary_md
            article.recommendations_md = output.recommendations_md or None

    # -- grounding --------------------------------------------------------

    def _ground(
        self,
        session: Session,
        article: Article,
        run: ArticleAnalysisRun,
        output: BaseModel,
    ) -> tuple[BaseModel, dict[str, Any] | None]:
        """Replace the model's claims with the ones the article supports, and
        write the survivors as findings.

        What the later states receive — and what the run row stores — is the
        reconciled set, never the proposal. A downstream prompt reasoning from
        an indicator the article was already found not to contain would be
        grounding undone one state later.

        The findings tables are written here rather than by the caller because
        this is the only place that holds both the reconciliation and the run
        that produced it. Previous findings for the article are cleared first:
        a state being re-run replaces its results, it does not add to them, and
        the unique keys would refuse the second write anyway.
        """
        body = article.body or ""
        if isinstance(output, ExtractIocOutput):
            reconciliation = iocs.reconcile(body, output)
            session.execute(delete(ArticleIoc).where(ArticleIoc.article_id == article.id))
            session.add_all(
                ArticleIoc(
                    article_id=article.id,
                    run_id=run.id,
                    ioc_type=indicator.ioc_type.value,
                    value=indicator.value,
                    value_defanged=indicator.value_defanged,
                    span_start=indicator.span_start,
                    span_end=indicator.span_end,
                    context=indicator.context,
                )
                for indicator in reconciliation.kept
            )
            kept = ExtractIocOutput(
                iocs=[
                    ExtractedIoc(
                        ioc_type=indicator.ioc_type,
                        value=indicator.value,
                        value_as_written=indicator.value_defanged,
                        context=indicator.context,
                    )
                    for indicator in reconciliation.kept
                ]
            )
            return kept, {
                "kept": len(reconciliation.kept),
                "rejected": [
                    {"value": item.value, "reason": item.reason.value}
                    for item in reconciliation.rejected
                ],
            }

        if isinstance(output, MapTtpOutput):
            reconciliation = ttps.reconcile(body, output, self._catalog)
            session.execute(delete(ArticleTtp).where(ArticleTtp.article_id == article.id))
            session.add_all(
                ArticleTtp(
                    article_id=article.id,
                    run_id=run.id,
                    technique_id=mapping.technique_id,
                    technique_name=mapping.technique_name,
                    tactic_id=mapping.tactic_id,
                    tactic_name=mapping.tactic_name,
                    evidence_span_start=mapping.evidence_span_start,
                    evidence_span_end=mapping.evidence_span_end,
                    confidence=mapping.confidence,
                )
                for mapping in reconciliation.kept
            )
            kept = MapTtpOutput(
                mappings=[
                    TtpMapping(
                        technique_id=mapping.technique_id,
                        evidence_quote=body[
                            mapping.evidence_span_start : mapping.evidence_span_end
                        ],
                        confidence=mapping.confidence,
                    )
                    for mapping in reconciliation.kept
                ]
            )
            return kept, {
                "kept": [
                    {
                        "technique_id": mapping.technique_id,
                        "technique_name": mapping.technique_name,
                        "tactic_id": mapping.tactic_id,
                        "tactic_name": mapping.tactic_name,
                        "span": [mapping.evidence_span_start, mapping.evidence_span_end],
                        "confidence": mapping.confidence,
                    }
                    for mapping in reconciliation.kept
                ],
                "rejected": [
                    {"technique_id": item.technique_id, "reason": item.reason.value}
                    for item in reconciliation.rejected
                ],
            }

        if isinstance(output, AdversarySketchOutput):
            return self._ground_sketch(body, output)

        if isinstance(output, DiamondModelOutput):
            return self._ground_diamond(body, output)

        if isinstance(output, ClassifyOutput):
            return self._ground_classify(body, output)

        return output, None

    def _ground_diamond(
        self, body: str, output: DiamondModelOutput
    ) -> tuple[DiamondModelOutput, dict[str, Any]]:
        """A vertex stands on a quote the article contains, or it does not stand.

        This is the state whose own schema warns that deriving the adversary
        from the infrastructure is how a diamond becomes a guess, and it was the
        state with no check at all. Measured on 68 stored rows before this
        existed: of 203 vertices asserted with a quote, 35 could not be found in
        the article. Six of those were the anchor's fault and are now recovered;
        the rest are the model writing a summary in its own words and labelling
        it evidence.

        A failing vertex becomes `None`, which the prompt already asks for when
        the evidence is not there. Downgrading the label instead was considered
        and refused: `inferred` describes a conclusion drawn from something in
        the article, and there is nothing here to have drawn it from. Leaving
        the sentence in place with a weaker word attached would keep a claim
        with no support visible to a reader, which is the failure, not the fix.
        """
        index = AnchorIndex(body)
        kept: dict[str, DiamondVertex | None] = {}
        rejected: list[dict[str, str]] = []
        for name in ("adversary", "infrastructure", "capability", "victim"):
            vertex: DiamondVertex | None = getattr(output, name)
            if vertex is None:
                continue
            if vertex.evidence_quote and index.find_quote(vertex.evidence_quote) is not None:
                continue
            kept[name] = None
            rejected.append(
                {
                    "vertex": name,
                    "reason": "quote_not_in_article" if vertex.evidence_quote else "no_quote",
                    "label": vertex.label.value,
                }
            )

        grounded = output.model_copy(update=kept) if kept else output
        return grounded, {
            "kept": [
                name
                for name in ("adversary", "infrastructure", "capability", "victim")
                if getattr(grounded, name) is not None
            ],
            "rejected": rejected,
        }

    def _ground_classify(
        self, body: str, output: ClassifyOutput
    ) -> tuple[ClassifyOutput, dict[str, Any]]:
        """The type survives an unfindable quote; the confidence does not.

        Refusing the classification outright was the consistent answer and the
        wrong one. The type drives every state after this, an article with a
        badly copied quote is usually still perfectly classifiable, and the
        measurement says the trade is not close: 3 rows in 88 fail here against
        an entire article's analysis thrown away. So the type is kept, the
        failure is written down where the gate reads it, and the confidence
        drops one level — an assertion whose evidence cannot be produced is not
        as good as one whose evidence can, and saying so is the whole job.
        """
        if output.evidence_quote and anchor_quote(body, output.evidence_quote) is not None:
            return output, {"kept": 1, "article_type": output.article_type.value, "rejected": []}

        lowered = _ONE_LEVEL_DOWN[output.confidence]
        grounded = output.model_copy(update={"confidence": lowered})
        # `kept` is a count, not the type. The gate reads this block through
        # `anchor_ratio`, which counts what survived against what did not, and a
        # string there reads as nothing to count: the failure would be recorded
        # and invisible to the only component that scores it.
        return grounded, {
            "kept": 0,
            "article_type": output.article_type.value,
            "rejected": [
                {
                    "reason": "quote_not_in_article" if output.evidence_quote else "no_quote",
                    "confidence_was": output.confidence.value,
                    "confidence_now": lowered.value,
                }
            ],
        }

    def _ground_sketch(
        self, body: str, output: AdversarySketchOutput
    ) -> tuple[AdversarySketchOutput, dict[str, Any]]:
        """Hold a sketch's names and relations to the article, not to the model.

        Two checks, and neither takes the model's word for anything.

        **A name that is not in the article is an invention**, and it is dropped
        exactly as an unanchored indicator is. This is the same rule the
        extraction states already run, applied where it was missing: the state
        that writes identities was the one state allowed to write them freely.

        **A relation without a quote that anchors is reduced, not believed.**
        A claimed `same_actor` is the single most consequential thing this
        pipeline can assert — it merges two adversaries — so it is held to the
        standard a technique mapping is held to. The actor survives with its
        name; what falls away is the claim about it, downgraded to `unstated`
        with the unsupported quote removed rather than left on the row to be
        read later as evidence.
        """
        kept: list[NamedActor] = []
        rejected: list[dict[str, str]] = []
        for actor in output.named_actors:
            if anchor_quote(body, actor.name) is None:
                rejected.append({"name": actor.name, "reason": "name_not_in_article"})
                continue
            if actor.relation is ActorRelation.UNSTATED:
                kept.append(actor)
                continue
            supported = bool(actor.evidence_quote) and anchor_quote(body, actor.evidence_quote)
            if supported:
                kept.append(actor)
                continue
            rejected.append(
                {
                    "name": actor.name,
                    "reason": "relation_unsupported",
                    "claimed": actor.relation.value,
                }
            )
            kept.append(
                actor.model_copy(
                    update={
                        "relation": ActorRelation.UNSTATED,
                        "related_to": "",
                        "evidence_quote": "",
                    }
                )
            )

        grounded = output.model_copy(update={"named_actors": kept})
        return grounded, {
            "kept": [{"name": actor.name, "relation": actor.relation.value} for actor in kept],
            "rejected": rejected,
        }

    # -- the row ----------------------------------------------------------

    @staticmethod
    def _row_for(
        session: Session, article: Article, state: str, prompt_version: str
    ) -> ArticleAnalysisRun:
        """The row for this state, reused if a previous pass left one.

        Reused rather than replaced because `(article_id, state)` is unique and
        because `attempts` accumulating across passes is the honest number: it
        is what the article has cost so far.
        """
        row = session.scalars(
            select(ArticleAnalysisRun).where(
                ArticleAnalysisRun.article_id == article.id,
                ArticleAnalysisRun.state == state,
            )
        ).one_or_none()
        if row is None:
            row = ArticleAnalysisRun(article_id=article.id, state=state, attempts=0)
            session.add(row)
        row.status = RunStatus.PENDING
        row.prompt_version = prompt_version
        # A state being re-run has no result yet; leaving the previous pass's
        # payload in place would let a failed run read as a finished one.
        row.raw_output_json = None
        row.started_at = datetime.now(UTC)
        row.finished_at = None
        session.flush()  # the id is needed by the call log and the audit row
        return row

    @staticmethod
    def _close(
        row: ArticleAnalysisRun,
        status: str,
        output: BaseModel | None = None,
        detail: str = "",
    ) -> StateResult:
        row.status = status
        row.finished_at = datetime.now(UTC)
        if detail and output is None:
            # A refusal or a stage has no output; the reason takes its place so
            # the row explains itself without a log to read alongside it.
            row.raw_output_json = {"detail": detail[:2000]}
        return StateResult(state=row.state, status=status, output=output, detail=detail)
