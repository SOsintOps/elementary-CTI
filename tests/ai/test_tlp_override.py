"""The analyst override: crossing the TLP boundary on purpose, with a record.

The boundary itself is tested in test_router.py. These tests cover the escape
hatch — that it works, that it cannot be used silently, and that the second
consent for a source's never-share flag is genuinely separate from the first.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.audit import (
    MissingOverrideError,
    overrides_for_article,
    recent_overrides,
    record_tlp_override,
)
from pestilentia.ai.router import (
    ModelChoice,
    ProviderSpec,
    Refusal,
    RefusalReason,
    Router,
    Tier,
    TlpOverride,
)
from pestilentia.ai.tlp import TlpLevel
from pestilentia.models.base import Base
from pestilentia.models.tables import AiEnrichmentAudit, Article, ArticleSource

CLOUD = ProviderSpec(name="anthropic", is_local=False, models={Tier.TRIAGE: "claude-haiku-4-5"})
LOCAL = ProviderSpec(name="ollama", is_local=True, models={Tier.TRIAGE: "qwen2.5:1.5b"})

AUTHORISED = TlpOverride(actor="sitticus", justification="active incident, triage needed now")


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        source = ArticleSource(name="Internal", url="https://x/feed", source_type="rss")
        db.add(source)
        db.flush()
        db.add(
            Article(
                id=1,
                source_id=source.id,
                url="https://x/1",
                url_canonical_hash="h1",
                title="Restricted incident note",
                tlp="amber",
                truncated=False,
            )
        )
        db.flush()
        yield db


# --------------------------------------------------------------------------
# Constructing an override
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("actor", "justification"),
    [("", "reason"), ("   ", "reason"), ("sitticus", ""), ("sitticus", "   ")],
)
def test_an_override_without_who_or_why_cannot_be_constructed(actor, justification):
    """An audit row that records a crossing but not its reason is worse than
    none: it looks like accountability without providing any."""
    with pytest.raises(ValueError):
        TlpOverride(actor=actor, justification=justification)


def test_the_source_ban_consent_is_off_by_default():
    assert TlpOverride(actor="a", justification="b").acknowledge_source_ban is False


# --------------------------------------------------------------------------
# Routing with an override
# --------------------------------------------------------------------------


@pytest.mark.parametrize("tlp", ["amber", "amber+strict", "red"])
def test_an_analyst_can_send_restricted_content_out(tlp):
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp=tlp, override=AUTHORISED
    )
    assert isinstance(decision, ModelChoice)
    assert decision.provider == "anthropic"
    assert decision.requires_audit is True


def test_without_an_override_the_boundary_still_holds():
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="red"
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BLOCKED_TLP


def test_an_override_that_crossed_nothing_is_not_audited():
    """Attaching an override to content that was within the ceiling anyway
    crossed no boundary. Recording it would bury the real crossings among
    false ones."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="clear", override=AUTHORISED
    )
    assert isinstance(decision, ModelChoice)
    assert decision.requires_audit is False


def test_a_local_route_is_not_an_override_either():
    """With a local provider available the content never leaves, so there is
    nothing to account for even though an override was offered."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[LOCAL]).choose(
        Tier.TRIAGE, article_tlp="red", override=AUTHORISED
    )
    assert isinstance(decision, ModelChoice)
    assert decision.is_local is True
    assert decision.requires_audit is False


def test_the_override_reason_names_the_actor_and_the_destination():
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="red", override=AUTHORISED
    )
    assert "sitticus" in decision.reason
    assert "anthropic" in decision.reason


# --------------------------------------------------------------------------
# The second consent
# --------------------------------------------------------------------------


def test_overriding_the_tlp_does_not_carry_the_source_never_share_flag():
    """Two separate promises. The TLP marking is our handling rule for the
    content; share_with_third_party=False is the source's own instruction
    about its material, and consenting to one is not consenting to the other."""
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="amber", source_share_flag=False, override=AUTHORISED
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.SOURCE_BAN
    assert "acknowledge_source_ban" in decision.detail, "the message must say how to proceed"


def test_the_second_consent_unlocks_it():
    explicit = TlpOverride(
        actor="sitticus",
        justification="legal signed off on sharing this source's material",
        acknowledge_source_ban=True,
    )
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="amber", source_share_flag=False, override=explicit
    )
    assert isinstance(decision, ModelChoice)
    assert decision.requires_audit is True


def test_a_never_share_source_without_any_override_is_still_blocked():
    decision = Router(cloud_max=TlpLevel.RED, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="clear", source_share_flag=False
    )
    assert isinstance(decision, Refusal)
    assert decision.reason is RefusalReason.BLOCKED_TLP


# --------------------------------------------------------------------------
# The audit row
# --------------------------------------------------------------------------


def test_the_audit_row_records_who_why_and_where(session):
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="amber", override=AUTHORISED
    )
    row = record_tlp_override(session, article_id=1, article_tlp="amber", choice=decision)

    assert row.decided_by == "sitticus"
    assert row.notes == "active incident, triage needed now"
    assert row.tlp == "amber"
    assert row.decision == "override"
    # Destination, explicitly — "it left the building" does not answer the
    # question a reviewer actually asks.
    assert row.after_json["provider"] == "anthropic"
    assert row.after_json["model_id"] == "claude-haiku-4-5"
    assert row.before_json["tlp"] == "amber"


def test_the_source_ban_acknowledgement_is_visible_in_the_row(session):
    explicit = TlpOverride(actor="a", justification="b", acknowledge_source_ban=True)
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="red", source_share_flag=False, override=explicit
    )
    row = record_tlp_override(
        session, article_id=1, article_tlp="red", choice=decision, source_share_flag=False
    )
    assert row.after_json["source_ban_acknowledged"] is True
    assert row.before_json["source_share_with_third_party"] is False


def test_recording_a_non_crossing_is_a_programming_error(session):
    """Guards against an audit trail padded with rows for calls that never
    crossed anything, which would make the real ones hard to find."""
    decision = Router(providers=[CLOUD]).choose(Tier.TRIAGE, article_tlp="clear")
    with pytest.raises(MissingOverrideError):
        record_tlp_override(session, article_id=1, article_tlp="clear", choice=decision)


def test_overrides_are_queryable_per_article_and_across_the_corpus(session):
    decision = Router(cloud_max=TlpLevel.GREEN, providers=[CLOUD]).choose(
        Tier.TRIAGE, article_tlp="amber", override=AUTHORISED
    )
    record_tlp_override(session, article_id=1, article_tlp="amber", choice=decision)
    record_tlp_override(session, article_id=1, article_tlp="amber", choice=decision)

    assert len(overrides_for_article(session, 1)) == 2
    assert len(recent_overrides(session)) == 2


def test_unrelated_audit_rows_are_not_mistaken_for_overrides(session):
    session.add(
        AiEnrichmentAudit(
            article_id=1,
            table_name="groups",
            row_id=7,
            action="update",
            model_name="claude-sonnet-5",
            confidence=0.9,
            tlp="clear",
            decision="auto",
        )
    )
    session.flush()
    assert recent_overrides(session) == []


def test_the_persisted_strings_fit_their_columns():
    """action and decision are String(16); a longer value would be truncated
    on some backends and quietly stop matching the queries above."""
    from pestilentia.ai.audit import OVERRIDE_ACTION, OVERRIDE_DECISION

    assert len(OVERRIDE_ACTION) <= 16
    assert len(OVERRIDE_DECISION) <= 16


def test_refusal_reasons_fit_the_status_column():
    """Same hazard for ArticleAnalysisRun.status, String(16)."""
    assert all(len(reason.value) <= 16 for reason in RefusalReason)
