"""What the router returns: a model to use, or a reason it refused.

A refusal is a first-class result, not an exception. `blocked_tlp` in
particular is a state the analyst is meant to *see* — an article the pipeline
declined to send anywhere — so it has to survive into `ArticleAnalysisRun`
rather than unwinding the stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Tier(StrEnum):
    """Task tiers from ADR-006. Triage is the cheap pre-filter that decides
    whether analysis is worth spending on at all."""

    TRIAGE = "triage"
    ANALYSIS = "analysis"


class RefusalReason(StrEnum):
    """Persisted verbatim as `ArticleAnalysisRun.status`, so these strings are
    part of the schema contract, not display text.

    That column is `String(16)`, so a value longer than sixteen characters
    would be silently truncated on some backends and quietly stop matching.
    `test_refusal_reasons_fit_the_status_column` pins it.
    """

    BLOCKED_TLP = "blocked_tlp"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TOO_LARGE = "too_large"
    NO_PROVIDER = "no_provider"
    #: The article's TLP was overridden, but the *source* also carries
    #: `share_with_third_party=False`. That is a separate promise to the
    #: publisher, so it takes its own acknowledgement rather than riding along
    #: on the TLP one.
    SOURCE_BAN = "source_ban"


@dataclass(frozen=True)
class TlpOverride:
    """An analyst's decision to send restricted content out anyway.

    Deliberately not a config flag. A setting that relaxes the ceiling applies
    to everything from then on and leaves no record of who chose it or why;
    this applies to one task and carries its own justification, so the audit
    row can answer "who sent this, and what was their reason" months later.

    Both fields are required and validated at construction: an override with an
    empty actor or a blank justification is worse than no audit trail, because
    it looks like one.
    """

    actor: str
    justification: str
    #: Second, separate consent. Overriding the article's TLP does not by
    #: itself override a source's own "never share" flag.
    acknowledge_source_ban: bool = False

    def __post_init__(self) -> None:
        if not self.actor.strip():
            raise ValueError("a TLP override must record who authorised it")
        if not self.justification.strip():
            raise ValueError("a TLP override must record why it was authorised")


@dataclass(frozen=True)
class ModelChoice:
    """A provider and model cleared to run one task."""

    provider: str
    model_id: str
    tier: Tier
    is_local: bool
    #: Why this and not something else — carried so a run row can explain a
    #: downgrade after the fact instead of leaving an unexplained model change.
    reason: str = ""
    #: Present only when the TLP boundary was deliberately crossed. Callers
    #: must write an audit row when this is set; `requires_audit` is the flag
    #: to branch on so the obligation is impossible to miss by accident.
    override: TlpOverride | None = None

    @property
    def allowed(self) -> bool:
        return True

    @property
    def requires_audit(self) -> bool:
        return self.override is not None


@dataclass(frozen=True)
class Refusal:
    """No model may serve this task."""

    reason: RefusalReason
    detail: str

    @property
    def allowed(self) -> bool:
        return False


Decision = ModelChoice | Refusal
