# "It is a capital mistake to theorize before one has data." — Sherlock Holmes, Elementary
from __future__ import annotations

import logging
import os
import secrets
import sys
from dataclasses import dataclass

from dotenv import load_dotenv

_PLACEHOLDER_SECRET = "change-me-in-production"


# "Data! Data! Data! I can't make bricks without clay." — Sherlock Holmes, Elementary
@dataclass(frozen=True)
class Settings:
    db_url: str = "sqlite:///elementaryctiDB.db"
    log_level: str = "INFO"
    api_base_url: str = "https://api.ransomware.live/v2"
    poll_interval_hours: int = 4
    web_host: str = "0.0.0.0"
    web_port: int = 8000
    fuzzy_threshold: int = 85
    mitre_enrichment_hours: int = 168  # weekly
    ransomwhere_enrichment_hours: int = 168  # weekly
    deepdarkcti_enrichment_hours: int = 168  # weekly
    # Article ingest rides the outer poll cycle. 0 = "every cycle", which is
    # what we want: the due-gate is evaluated once per outer loop, so a
    # non-zero value equal to the loop period makes a run that is a few
    # minutes short of due wait a *whole* extra loop — observed cadence 4-8h
    # against a documented 4h. Throttling here would only add jitter.
    article_ingest_hours: int = 0
    # --- AI router (ADR-006 phase 3) -------------------------------------
    # Cloud privacy boundary. Content at this TLP level or below may reach a
    # third-party LLM; anything above stays local or is staged for a human.
    # Relaxing it is a conscious config change, per ADR-006 section 6.
    ai_tlp_cloud_max: str = "green"
    # Hard ceilings. At 80% of the daily figure the router drops to the cheap
    # tier; at 100% it refuses. Monthly is the outer bound from the ADR's
    # $30-150 envelope, deliberately set at the bottom of it.
    ai_daily_budget_usd: float = 2.0
    ai_monthly_budget_usd: float = 30.0
    # Per-article ceiling from the roadmap: one pathological document must not
    # be able to spend the day's budget on its own.
    ai_max_tokens_per_article: int = 50000
    # Model per tier. Ids verified against the Anthropic model list on
    # 2026-08-08; re-check before trusting them, model ids do get retired.
    ai_model_triage: str = "claude-haiku-4-5"
    ai_model_analysis: str = "claude-sonnet-5"
    ai_model_local: str = "qwen2.5:1.5b"

    # Campaign clustering vectoriser: "auto" prefers embeddings and falls
    # back to TF-IDF when the model was never fetched; "embedding" and
    # "tfidf" pin one explicitly. Measured comparison in
    # .planning/PLAN-LOCAL-AI-2026-08.md.
    cluster_backend: str = "auto"
    secret_key: str = _PLACEHOLDER_SECRET
    auth_user: str = ""
    auth_pass: str = ""


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is not None:
        return _settings
    _settings = _load()
    return _settings


def _load() -> Settings:
    load_dotenv()

    raw = {
        "db_url": os.getenv("PEST_DB_URL"),
        "log_level": os.getenv("PEST_LOG_LEVEL"),
        "api_base_url": os.getenv("PEST_API_BASE_URL"),
        "poll_interval_hours": os.getenv("PEST_POLL_INTERVAL_HOURS"),
        "web_host": os.getenv("PEST_WEB_HOST"),
        "web_port": os.getenv("PEST_WEB_PORT"),
        "fuzzy_threshold": os.getenv("PEST_FUZZY_THRESHOLD"),
        "mitre_enrichment_hours": os.getenv("PEST_MITRE_ENRICHMENT_HOURS"),
        "ransomwhere_enrichment_hours": os.getenv("PEST_RANSOMWHERE_ENRICHMENT_HOURS"),
        "deepdarkcti_enrichment_hours": os.getenv("PEST_DEEPDARKCTI_ENRICHMENT_HOURS"),
        "article_ingest_hours": os.getenv("PEST_ARTICLE_INGEST_HOURS"),
        "ai_tlp_cloud_max": os.getenv("PEST_AI_TLP_CLOUD_MAX"),
        "ai_daily_budget_usd": os.getenv("PEST_AI_DAILY_BUDGET_USD"),
        "ai_monthly_budget_usd": os.getenv("PEST_AI_MONTHLY_BUDGET_USD"),
        "ai_max_tokens_per_article": os.getenv("PEST_AI_MAX_TOKENS_PER_ARTICLE"),
        "ai_model_triage": os.getenv("PEST_AI_MODEL_TRIAGE"),
        "ai_model_analysis": os.getenv("PEST_AI_MODEL_ANALYSIS"),
        "ai_model_local": os.getenv("PEST_AI_MODEL_LOCAL"),
        "cluster_backend": os.getenv("PEST_AI_CLUSTER_BACKEND"),
        "secret_key": os.getenv("PEST_SECRET_KEY"),
        "auth_user": os.getenv("PEST_AUTH_USER"),
        "auth_pass": os.getenv("PEST_AUTH_PASS"),
    }

    defaults = Settings()
    kwargs: dict = {}

    for key, val in raw.items():
        if val is None:
            continue
        target_type = type(getattr(defaults, key))
        try:
            kwargs[key] = target_type(val)
        except (ValueError, TypeError) as e:
            print(f"ERROR: invalid value for PEST_{key.upper()}={val!r}: {e}", file=sys.stderr)
            sys.exit(1)

    if kwargs.get("secret_key") == _PLACEHOLDER_SECRET:
        print(
            f"ERROR: PEST_SECRET_KEY must not equal the placeholder {_PLACEHOLDER_SECRET!r}. "
            'Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`.',
            file=sys.stderr,
        )
        sys.exit(1)

    tlp_ceiling = kwargs.get("ai_tlp_cloud_max")
    if tlp_ceiling is not None:
        from pestilentia.ai.tlp import TlpLevel

        if tlp_ceiling.lower() not in {level.value for level in TlpLevel}:
            print(
                "ERROR: PEST_AI_TLP_CLOUD_MAX must be a TLP 2.0 level "
                f"(clear, green, amber, amber+strict, red); got {tlp_ceiling!r}.",
                file=sys.stderr,
            )
            sys.exit(1)

    if kwargs.get("cluster_backend") not in (None, "auto", "embedding", "tfidf"):
        print(
            "ERROR: PEST_AI_CLUSTER_BACKEND must be auto, embedding or tfidf "
            f"(got {kwargs['cluster_backend']!r}).",
            file=sys.stderr,
        )
        sys.exit(1)

    if bool(kwargs.get("auth_user")) != bool(kwargs.get("auth_pass")):
        print(
            "ERROR: PEST_AUTH_USER and PEST_AUTH_PASS must be set together "
            "(set both to enable HTTP Basic Auth, or neither to disable it).",
            file=sys.stderr,
        )
        sys.exit(1)

    if "secret_key" not in kwargs:
        kwargs["secret_key"] = secrets.token_hex(32)
        logging.getLogger(__name__).warning(
            "PEST_SECRET_KEY not set — generated an ephemeral secret. "
            "CSRF tokens will be invalidated on every restart. "
            "Set PEST_SECRET_KEY to a persistent value in production."
        )

    return Settings(**kwargs)
