"""B2/B3: the router facade and the TLP privacy invariant.

Zero LLM spend by construction: the router returns decisions and never calls
anything, and the mock provider raises if asked to. Nothing here imports a
vendor SDK.
"""

from __future__ import annotations

import pytest

from pestilentia.ai.router import (
    MockProvider,
    ModelChoice,
    ProviderSpec,
    Refusal,
    RefusalReason,
    Router,
    Tier,
)
from pestilentia.ai.tlp import TlpLevel

CLOUD = ProviderSpec(
    name="anthropic",
    is_local=False,
    models={
        Tier.TRIAGE: "claude-haiku-4-5",
        Tier.ANALYSIS: "claude-sonnet-5",
        Tier.JUDGE: "a-model-from-another-family",
    },
)
LOCAL = ProviderSpec(name="ollama", is_local=True, models={Tier.TRIAGE: "qwen2.5:1.5b"})
BOTH = [CLOUD, LOCAL]


# --------------------------------------------------------------------------
# The invariant. ADR-006 section 6 and roadmap phase 3 criterion 2.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("tlp", ["amber", "amber+strict", "red"])
def test_privacy_invariant_amber_and_above_never_reach_a_cloud_provider(tlp):
    """The named invariant: restricted content does not leave the building.

    Checked at every tier, because a per-tier routing bug would otherwise let
    analysis escape while triage stayed compliant.
    """
    router = Router(cloud_max=TlpLevel.GREEN, providers=BOTH)
    for tier in Tier:
        decision = router.choose(tier, article_tlp=tlp)
        if isinstance(decision, ModelChoice):
            assert decision.is_local, f"{tlp} reached cloud provider {decision.provider}"


def test_privacy_invariant_holds_when_the_local_provider_cannot_serve():
    """The case that matters most. Ollama serves triage but not analysis, so
    an AMBER article needing analysis has nowhere to go. It must be refused as
    blocked_tlp — not as a missing provider, which a retry policy would happily
    resolve by reaching for the cloud once one appeared."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=BOTH).choose(
        Tier.ANALYSIS, article_tlp="amber"
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BLOCKED_TLP


def test_privacy_invariant_holds_when_no_local_provider_exists_at_all():
    """Ollama down, or never configured. Still a refusal, never a downgrade."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="amber"
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BLOCKED_TLP


def test_the_source_kill_switch_overrides_a_permissive_tlp_level():
    """share_with_third_party=False beats any TLP level, per ADR-006 6."""
    decision = Router(cloud_max=TlpLevel.RED, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="clear", source_share_flag=False
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BLOCKED_TLP


def test_an_unknown_tlp_value_fails_closed():
    """A NULL or garbage TLP coerces to AMBER+STRICT, so it is denied rather
    than treated as public."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp=None
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BLOCKED_TLP


def test_a_relaxed_ceiling_admits_amber_deliberately():
    """The boundary is configurable; the point is that moving it is explicit."""
    decision = Router(cloud_max=TlpLevel.AMBER, providers=[CLOUD]).choose(
        Tier.ANALYSIS, article_tlp="amber"
    )
    assert isinstance(decision, ModelChoice)
    assert decision.provider == "anthropic"


# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------


def test_clear_content_routes_to_the_cloud_tier_model():
    decision = Router(providers=BOTH).choose(Tier.ANALYSIS, article_tlp="clear")
    assert isinstance(decision, ModelChoice)
    assert (decision.provider, decision.model_id) == ("anthropic", "claude-sonnet-5")
    assert decision.is_local is False


def test_tiers_map_to_different_models():
    router = Router(providers=[CLOUD])
    triage = router.choose(Tier.TRIAGE, article_tlp="clear")
    analysis = router.choose(Tier.ANALYSIS, article_tlp="clear")
    assert triage.model_id != analysis.model_id


def test_a_local_route_records_why_it_was_chosen():
    """A downgrade that leaves no trace is indistinguishable from a bug."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=BOTH).choose(
        Tier.TRIAGE, article_tlp="amber"
    )
    assert isinstance(decision, ModelChoice)
    assert decision.is_local
    assert "TLP" in decision.reason


def test_swapping_the_provider_needs_no_pipeline_change():
    """Roadmap criterion 1: callers name a tier, never a vendor or model."""
    replacement = ProviderSpec(
        name="openai", is_local=False, models={Tier.ANALYSIS: "some-other-model"}
    )
    decision = Router(providers=[replacement]).choose(Tier.ANALYSIS, article_tlp="clear")
    assert isinstance(decision, ModelChoice)
    assert decision.provider == "openai"


def test_no_provider_for_a_tier_is_reported_as_such():
    triage_only = ProviderSpec(name="x", is_local=False, models={Tier.TRIAGE: "m"})
    decision = Router(providers=[triage_only]).choose(Tier.ANALYSIS, article_tlp="clear")
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.NO_PROVIDER


# --------------------------------------------------------------------------
# Budget interaction (the guard itself is B4)
# --------------------------------------------------------------------------


def test_an_oversized_article_is_refused_before_anything_else():
    decision = Router(providers=BOTH, max_tokens_per_article=1000).choose(
        Tier.TRIAGE, article_tlp="clear", estimated_tokens=50_000
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.TOO_LARGE


def test_past_the_degrade_threshold_analysis_pauses_but_triage_runs():
    router = Router(providers=BOTH)
    assert isinstance(
        router.choose(Tier.ANALYSIS, article_tlp="clear", budget_allows_tier=False),
        Refusal,
    )
    assert isinstance(
        router.choose(Tier.TRIAGE, article_tlp="clear", budget_allows_tier=False),
        ModelChoice,
    )


def test_exhausted_budget_stops_every_tier():
    router = Router(providers=BOTH)
    for tier in Tier:
        decision = router.choose(tier, article_tlp="clear", budget_exhausted=True)
        assert isinstance(decision, Refusal)
        assert decision.reason is RefusalReason.BUDGET_EXHAUSTED


@pytest.mark.parametrize("exhausted", [False, True])
@pytest.mark.parametrize("allows_tier", [True, False])
def test_a_tlp_refusal_is_not_reported_as_a_money_problem(exhausted, allows_tier):
    """Ordering matters, and the case that proves it is the one where *both*
    gates would refuse.

    An earlier version of this test only passed budget_exhausted=False, so it
    asserted something true but vacuous and let a real inversion through: the
    implementation returned `budget_exhausted` for a TLP-blocked article
    whenever the budget also happened to be spent. The operator's fix for
    "budget exhausted" is to raise a cap, and then retry a document that was
    never a spending question. The privacy answer has to win every time.
    """
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE,
        article_tlp="red",
        budget_exhausted=exhausted,
        budget_allows_tier=allows_tier,
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BLOCKED_TLP


def test_budget_still_refuses_when_tlp_permits():
    """The other side of the ordering: with no privacy objection, a spending
    refusal must still come through rather than being masked."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="clear", budget_exhausted=True
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BUDGET_EXHAUSTED


# --------------------------------------------------------------------------
# Test-harness guarantees
# --------------------------------------------------------------------------


def test_the_mock_provider_refuses_to_be_called():
    """A test that accidentally reaches a call path should fail loudly rather
    than receive canned text and pass."""
    with pytest.raises(AssertionError, match="does not call"):
        MockProvider(CLOUD).complete("anything")


def test_refusal_reasons_are_stable_strings():
    """They are persisted as ArticleAnalysisRun.status, so renaming one is a
    schema change, not a refactor."""
    assert RefusalReason.BLOCKED_TLP.value == "blocked_tlp"
    assert {r.value for r in RefusalReason} == {
        "blocked_tlp",
        "budget_exhausted",
        "too_large",
        "no_provider",
        "source_ban",
    }
    # String(16) on ArticleAnalysisRun.status. A longer value would be
    # truncated on some backends and quietly stop matching.
    assert all(len(reason.value) <= 16 for reason in RefusalReason)
