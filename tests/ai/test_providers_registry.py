"""The registry's shape is policy, not plumbing — pin it.

Order is preference order, so "nvidia first" is the 2026-08-09 decision that
free NIM inference replaces unfunded Anthropic credit as the working cloud
provider. If a refactor reorders the dict, the router silently changes vendor;
these tests make that a red bar instead.
"""

from __future__ import annotations

from pestilentia.ai.router.decisions import Tier
from pestilentia.ai.router.providers import PROVIDERS, available_providers


def test_nvidia_is_the_preferred_cloud_provider():
    first_cloud = next(spec for spec in available_providers() if not spec.is_local)
    assert first_cloud.name == "nvidia"


def test_nvidia_works_in_llama_and_judges_in_something_else():
    """The judge's whole value is being from another family.

    A Llama auditing a Llama shares its blind spots, which is a second opinion
    from the same mind rather than an independent one.
    """
    spec = PROVIDERS["nvidia"]
    assert spec.serves(Tier.TRIAGE) and spec.serves(Tier.ANALYSIS) and spec.serves(Tier.JUDGE)
    assert spec.models[Tier.TRIAGE].startswith("meta/llama-")
    assert spec.models[Tier.ANALYSIS].startswith("meta/llama-")
    assert not spec.models[Tier.JUDGE].startswith("meta/llama-")


def test_anthropic_offers_no_judge():
    """One vendor is one family. Rather than pretend, it declines the tier —
    and `Verify` then refuses instead of grading its own homework."""
    assert not PROVIDERS["anthropic"].serves(Tier.JUDGE)


def test_nvidia_free_tier_prices_at_zero():
    spec = PROVIDERS["nvidia"]
    for tier in (Tier.TRIAGE, Tier.ANALYSIS, Tier.JUDGE):
        assert spec.pricing[tier].usd(1_000_000, 1_000_000) == 0.0


def test_anthropic_remains_registered_for_the_day_credit_exists():
    assert "anthropic" in PROVIDERS
    assert PROVIDERS["anthropic"].serves(Tier.TRIAGE)


def test_local_escape_valve_is_untouched():
    spec = PROVIDERS["ollama"]
    assert spec.is_local
    assert spec.serves(Tier.TRIAGE) and not spec.serves(Tier.ANALYSIS)
