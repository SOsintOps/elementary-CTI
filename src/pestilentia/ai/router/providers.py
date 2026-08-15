"""Provider registry — the seam that makes swapping a vendor a config change.

Nothing here imports a vendor SDK. A `ProviderSpec` is metadata: what it is
called, whether it runs locally, which model serves each tier, and what a token
costs. The object that actually performs a call arrives in phase 4; keeping the
description separate is what lets the whole router be tested at zero spend.

The roadmap's provider-swap criterion is satisfied structurally: pipeline code
names a `Tier`, never a model or a vendor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from pestilentia.ai.router.decisions import Tier


@dataclass(frozen=True)
class Pricing:
    """USD per million tokens.

    **A dated snapshot, not a source of truth.** Verified against Anthropic's
    published pricing on 2026-08-08. Sonnet 5 carried an introductory rate
    ($2/$10) through 2026-08-31, and the standing rate is recorded here instead
    — budgeting against the promotional price would under-estimate spend from
    September. Re-check before relying on any cost figure derived from this.
    """

    input_per_mtok: float
    output_per_mtok: float

    def usd(self, tokens_in: int, tokens_out: int) -> float:
        return (tokens_in * self.input_per_mtok + tokens_out * self.output_per_mtok) / 1_000_000


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    is_local: bool
    #: Tier to model id. A provider that cannot serve a tier simply omits it,
    #: which is how the local fallback declines analysis-grade work.
    models: dict[Tier, str]
    pricing: dict[Tier, Pricing] = field(default_factory=dict)

    def serves(self, tier: Tier) -> bool:
        return tier in self.models


@runtime_checkable
class Provider(Protocol):
    """What phase 4 will implement to actually make calls."""

    @property
    def spec(self) -> ProviderSpec: ...


class MockProvider:
    """A provider that answers metadata questions and refuses to be called.

    This is what the test suite routes through. Calling it raises rather than
    returning canned text, so a test that accidentally reaches a call path
    fails loudly instead of silently pretending an LLM ran.
    """

    def __init__(self, spec: ProviderSpec) -> None:
        self._spec = spec

    @property
    def spec(self) -> ProviderSpec:
        return self._spec

    def complete(self, *_args, **_kwargs):
        raise AssertionError(
            f"MockProvider({self._spec.name}) was asked to complete a request. "
            "The router decides; it does not call. If a test needs a response, "
            "it is testing phase 4, not phase 3."
        )


# Registry order is preference order. NVIDIA NIM leads — a deliberate
# deviation from ADR-006's "Anthropic primary", decided 2026-08-09 when it
# turned out the Max subscription carries no Console API credit
# (.planning/PLAN-NIM-PROVIDER-2026-08.md; the ADR is a protected path and
# records the original intent until the user amends it). NIM's free tier has
# no per-token price, so these Pricing rows are genuinely zero — cost rows
# stay $0 with real token counts, and BudgetGuard thresholds simply never
# trip. Both tiers are Llama on purpose: one model-family opt-in surface
# (other NIM families 403 without registration), and no reasoning models —
# chain-of-thought is waste where the output is constrained JSON.
# Anthropic stays registered and callable the day a funded key appears.
# Ollama is the local escape valve for content above the cloud TLP ceiling —
# triage only, because a 1.5B model with a ~2k context cannot do
# analysis-grade extraction on this corpus (measured 2026-08-08: mean
# article ~3.4k tokens).
PROVIDERS: dict[str, ProviderSpec] = {
    "nvidia": ProviderSpec(
        name="nvidia",
        is_local=False,
        models={
            Tier.TRIAGE: "meta/llama-3.1-8b-instruct",
            Tier.ANALYSIS: "meta/llama-3.3-70b-instruct",
            # Deliberately not a Llama. The Verify state exists to catch the
            # generator out, and a model from the same family shares its blind
            # spots — the point is uncorrelated failure modes, not a second
            # opinion from the same mind. Verified live 2026-08-12: served in
            # the catalogue (102 models) and answers without the one-time
            # family opt-in some NIM families need.
            Tier.JUDGE: "deepseek-ai/deepseek-v4-flash-0731",
        },
        pricing={
            Tier.TRIAGE: Pricing(0.0, 0.0),
            Tier.ANALYSIS: Pricing(0.0, 0.0),
            Tier.JUDGE: Pricing(0.0, 0.0),
        },
    ),
    "anthropic": ProviderSpec(
        name="anthropic",
        is_local=False,
        # No judge model: one vendor is one family, and a Sonnet auditing a
        # Sonnet is the arrangement this tier exists to avoid. A deployment
        # with only Anthropic therefore has no judge, and `Verify` refuses
        # rather than quietly grading its own homework.
        models={Tier.TRIAGE: "claude-haiku-4-5", Tier.ANALYSIS: "claude-sonnet-5"},
        pricing={
            Tier.TRIAGE: Pricing(1.00, 5.00),
            Tier.ANALYSIS: Pricing(3.00, 15.00),
        },
    ),
    "ollama": ProviderSpec(
        name="ollama",
        is_local=True,
        models={Tier.TRIAGE: "qwen2.5:1.5b"},
        pricing={Tier.TRIAGE: Pricing(0.0, 0.0)},
    ),
}


def available_providers(local_only: bool = False) -> list[ProviderSpec]:
    """Registry order is preference order: the first that serves a tier wins."""
    specs = list(PROVIDERS.values())
    if local_only:
        return [spec for spec in specs if spec.is_local]
    return specs
