"""B1: the router's configuration surface.

Small, but two of these defaults are load-bearing safety properties rather than
preferences, so they get tests: the cloud TLP ceiling and the fact that an
unparseable ceiling refuses to start instead of falling back to something
permissive.
"""

from __future__ import annotations

import pytest

import pestilentia.config as config
from pestilentia.ai.tlp import TlpLevel
from pestilentia.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _reset_settings():
    yield
    config._settings = None


def test_cloud_ceiling_defaults_to_green():
    """ADR-006 section 6. AMBER and above must not leave the building without
    a deliberate change, so the default cannot be permissive."""
    assert Settings().ai_tlp_cloud_max == TlpLevel.GREEN.value


def test_default_ceiling_is_a_real_tlp_level():
    assert Settings().ai_tlp_cloud_max in {level.value for level in TlpLevel}


def test_budgets_are_inside_the_adr_envelope():
    settings = Settings()
    assert 30.0 <= settings.ai_monthly_budget_usd <= 150.0
    assert settings.ai_daily_budget_usd > 0


def test_per_article_token_ceiling_is_set():
    """One pathological document must not be able to spend the day's budget."""
    assert Settings().ai_max_tokens_per_article == 50_000


def test_each_tier_names_a_model():
    settings = Settings()
    assert settings.ai_model_triage
    assert settings.ai_model_analysis
    assert settings.ai_model_local
    assert settings.ai_model_triage != settings.ai_model_analysis


def test_an_invalid_ceiling_refuses_to_start(monkeypatch, capsys):
    """Fail loudly. A typo silently coerced to a permissive default is exactly
    how AMBER content ends up at a third party."""
    monkeypatch.setenv("PEST_AI_TLP_CLOUD_MAX", "amberish")
    monkeypatch.setenv("PEST_SECRET_KEY", "x" * 64)
    config._settings = None
    with pytest.raises(SystemExit):
        get_settings()
    assert "PEST_AI_TLP_CLOUD_MAX" in capsys.readouterr().err


def test_the_ceiling_is_overridable(monkeypatch):
    """Relaxation must be possible — it is a conscious choice, not forbidden."""
    monkeypatch.setenv("PEST_AI_TLP_CLOUD_MAX", "amber")
    monkeypatch.setenv("PEST_SECRET_KEY", "x" * 64)
    config._settings = None
    assert get_settings().ai_tlp_cloud_max == "amber"
