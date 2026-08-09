"""The facade. Two gates, fixed order, no silent downgrades."""

from __future__ import annotations

from collections.abc import Sequence

from pestilentia.ai.router.decisions import (
    Decision,
    ModelChoice,
    Refusal,
    RefusalReason,
    Tier,
    TlpOverride,
)
from pestilentia.ai.router.providers import ProviderSpec, available_providers
from pestilentia.ai.tlp import TlpLevel, cloud_allowed, display_label


class Router:
    """Chooses a model for a task, or refuses and says why.

    Deliberately does not touch the database or any SDK. It is handed the
    numbers it needs — the budget verdict, the size estimate — so that every
    branch is reachable in a unit test without a session or a network.
    """

    def __init__(
        self,
        cloud_max: TlpLevel | str = TlpLevel.GREEN,
        providers: Sequence[ProviderSpec] | None = None,
        max_tokens_per_article: int = 50_000,
    ) -> None:
        self.cloud_max = cloud_max
        self._providers = list(providers) if providers is not None else None
        self.max_tokens_per_article = max_tokens_per_article

    def _registry(self, local_only: bool) -> list[ProviderSpec]:
        if self._providers is None:
            return available_providers(local_only=local_only)
        return [p for p in self._providers if p.is_local or not local_only]

    def choose(
        self,
        tier: Tier,
        article_tlp: TlpLevel | str | None,
        source_share_flag: bool = True,
        estimated_tokens: int = 0,
        budget_allows_tier: bool = True,
        budget_exhausted: bool = False,
        override: TlpOverride | None = None,
    ) -> Decision:
        """Resolve one task to a model, or to a refusal.

        `budget_allows_tier` is False when spend has passed the degrade
        threshold: analysis is refused, triage still runs. `budget_exhausted`
        stops everything. Both are supplied by `BudgetGuard` rather than looked
        up here, because a router that queries the database is a router that
        cannot be tested cheaply.
        """
        if estimated_tokens > self.max_tokens_per_article:
            return Refusal(
                RefusalReason.TOO_LARGE,
                f"{estimated_tokens} tokens exceeds the per-article ceiling of "
                f"{self.max_tokens_per_article}",
            )

        # Gate 1 — TLP, and it resolves *fully* before budget is consulted.
        #
        # Both gates can refuse the same task, so which one answers is a
        # decision, not an accident. A document that may not leave the building
        # must never have that refusal reported as a money problem: the
        # operator's fix for "budget exhausted" is to raise a cap, and after
        # raising it they would retry a document that was never a spending
        # question in the first place. The privacy answer has to be the one
        # they see, and it has to be stable no matter what the budget is doing.
        may_use_cloud = cloud_allowed(article_tlp, source_share_flag, self.cloud_max)
        # Whether the boundary was *actually* in the way, captured before the
        # override can move it. An override attached to content that was
        # within the ceiling anyway crossed nothing, and auditing it would
        # bury the real crossings among false ones.
        boundary_blocked = not may_use_cloud

        # An analyst may cross the boundary deliberately. Two separate consents,
        # because they are two separate promises: the TLP marking is *our*
        # handling rule for the content, while `share_with_third_party=False`
        # is the source's own instruction about its material. Overriding the
        # first must not silently carry the second.
        if override is not None and not may_use_cloud:
            if not source_share_flag and not override.acknowledge_source_ban:
                return Refusal(
                    RefusalReason.SOURCE_BAN,
                    "the source is marked never-share; overriding the article's TLP "
                    "does not cover that. Re-submit with acknowledge_source_ban=True "
                    "to accept it explicitly.",
                )
            may_use_cloud = True

        candidates = [
            spec for spec in self._registry(local_only=not may_use_cloud) if spec.serves(tier)
        ]

        if not candidates:
            # Nothing can serve it. When the cloud was ruled out, that is a TLP
            # refusal and must be recorded as one — the crucial case being a
            # local provider that is down or cannot serve this tier. Reporting
            # it as "no provider" would let a retry policy quietly send the
            # content to a cloud model once one became available.
            if not may_use_cloud:
                return Refusal(
                    RefusalReason.BLOCKED_TLP,
                    f"{display_label(_coerce(article_tlp))} exceeds the cloud ceiling "
                    f"{display_label(_coerce(self.cloud_max))} and no local provider "
                    f"serves the {tier.value} tier",
                )
            return Refusal(
                RefusalReason.NO_PROVIDER,
                f"no registered provider serves the {tier.value} tier",
            )

        # Gate 2 — budget. Only reached once *some* provider is allowed to take
        # the task, so a refusal here really is about money.
        if budget_exhausted:
            return Refusal(
                RefusalReason.BUDGET_EXHAUSTED,
                "spend ceiling reached; no further calls until the window resets",
            )

        if tier is Tier.ANALYSIS and not budget_allows_tier:
            return Refusal(
                RefusalReason.BUDGET_EXHAUSTED,
                "past the degrade threshold; analysis-tier calls are paused",
            )

        spec = candidates[0]
        if override is not None and boundary_blocked and not spec.is_local:
            reason = (
                f"TLP override by {override.actor}: "
                f"{display_label(_coerce(article_tlp))} sent to {spec.name}"
            )
            applied = override
        else:
            reason = "" if may_use_cloud else "TLP ceiling: local providers only"
            applied = None

        return ModelChoice(
            provider=spec.name,
            model_id=spec.models[tier],
            tier=tier,
            is_local=spec.is_local,
            reason=reason,
            override=applied,
        )


def _coerce(raw: TlpLevel | str | None) -> TlpLevel:
    from pestilentia.ai.tlp import coerce_tlp

    return coerce_tlp(raw)
