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


def test_nvidia_serves_both_tiers_with_llama():
    spec = PROVIDERS["nvidia"]
    assert spec.serves(Tier.TRIAGE) and spec.serves(Tier.ANALYSIS)
    assert all(model.startswith("meta/llama-") for model in spec.models.values())


def test_nvidia_free_tier_prices_at_zero():
    spec = PROVIDERS["nvidia"]
    for tier in (Tier.TRIAGE, Tier.ANALYSIS):
        assert spec.pricing[tier].usd(1_000_000, 1_000_000) == 0.0


def test_anthropic_remains_registered_for_the_day_credit_exists():
    assert "anthropic" in PROVIDERS
    assert PROVIDERS["anthropic"].serves(Tier.TRIAGE)


def test_local_escape_valve_is_untouched():
    spec = PROVIDERS["ollama"]
    assert spec.is_local
    assert spec.serves(Tier.TRIAGE) and not spec.serves(Tier.ANALYSIS)
