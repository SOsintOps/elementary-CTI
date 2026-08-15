# "The game is afoot." — Sherlock Holmes
"""The runner: what it does when the model answers, and when it does not.

Every provider here is scripted, so the suite spends nothing and every branch —
refusal, retry, escalation, staging, an outage — is reachable without a key. The
scripted answers are deliberately minimal JSON: this file is about the machine's
control flow, and the content of a good answer is `test_prompts`' problem.
"""

from __future__ import annotations

import json
from typing import get_args

import pytest
from pydantic import BaseModel
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pestilentia.ai.confidence.composite import anchor_ratio
from pestilentia.ai.extraction.attack_catalog import AttackCatalog
from pestilentia.ai.prompts import PROMPTS
from pestilentia.ai.router.decisions import Tier, TlpOverride
from pestilentia.ai.router.providers import ProviderSpec
from pestilentia.ai.router.router import Router
from pestilentia.ai.schemas import STATE_ORDER, STATE_SCHEMAS
from pestilentia.ai.state.machine import (
    BACKOFF_SECONDS,
    GROUNDING_KEY,
    OUTPUT_KEY,
    ExtractionMachine,
    RunStatus,
)
from pestilentia.models.base import Base
from pestilentia.models.tables import (
    AiEnrichmentAudit,
    Article,
    ArticleAnalysisRun,
    ArticleIoc,
    ArticleSource,
    ArticleTtp,
    LlmCallLog,
)

BODY = (
    "The intruder authenticated to the VPN with valid credentials, then "
    "encrypted files across the estate. The ransom note pointed at 203.0.113[.]7."
)

CLOUD = ProviderSpec(
    name="nvidia",
    is_local=False,
    models={
        Tier.TRIAGE: "small-model",
        Tier.ANALYSIS: "big-model",
        Tier.JUDGE: "other-family-model",
    },
)
#: A registry that can generate but cannot audit — the shape of a deployment
#: with a single vendor.
NO_JUDGE = ProviderSpec(
    name="nvidia",
    is_local=False,
    models={Tier.TRIAGE: "small-model", Tier.ANALYSIS: "big-model"},
)
LOCAL = ProviderSpec(name="ollama", is_local=True, models={Tier.TRIAGE: "local-small"})

# Minimal valid answers, one per state.
ANSWERS = {
    "triage": {"relevant": True, "reason": "ransomware incident"},
    "classify": {
        "article_type": "incident_report",
        "confidence": "high confidence",
        "evidence_quote": "encrypted files across the estate",
    },
    "extract_ioc": {
        "iocs": [
            {
                "ioc_type": "ipv4",
                "value": "203.0.113.7",
                "value_as_written": "203.0.113[.]7",
                "context": "The ransom note pointed at 203.0.113[.]7.",
            }
        ]
    },
    "map_ttp": {
        "mappings": [
            {
                "technique_id": "T1078",
                "evidence_quote": "authenticated to the VPN with valid credentials",
                "confidence": 0.8,
            }
        ]
    },
    "diamond_model": {
        "infrastructure": {
            "summary": "One address in the ransom note.",
            "label": "observed",
            "evidence_quote": "The ransom note pointed at 203.0.113[.]7.",
        }
    },
    "narrative": {
        "key_judgement": "Access was likely bought.",
        "confidence": "moderate confidence",
        "summary_md": "A logistics operator was encrypted.",
        "recommendations_md": "",
    },
    "adversary_sketch": {
        "attribution_level": "tactical",
        "cluster_summary": "Buys access, encrypts quickly.",
        "named_actors": [],
        "likelihood": "likely",
        "confidence": "low confidence",
        "shared_infrastructure_note": "Operator and affiliate are not separable.",
        "false_flag_note": "Nothing suggests deception.",
    },
    "verify": {
        "claims": [
            {
                "claim": "Access was likely bought.",
                "label": "inferred",
                "justification": "The article says the credentials came from a broker.",
            }
        ]
    },
}


class Reply:
    """What a provider hands back — the fields the machine reads."""

    def __init__(self, text, model_id="small-model", tokens_in=100, tokens_out=50):
        self.text = text
        self.model_id = model_id
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.cached_tokens = 0


class ScriptedProvider:
    """Answers from a script keyed by state, and records what it was asked."""

    def __init__(self, script=None, wrap=lambda payload: json.dumps(payload)):
        self._script = script or {}
        self._wrap = wrap
        self.calls = []

    def complete(self, model_id, messages, max_tokens=1024, temperature=0.0):
        self.calls.append((model_id, messages))
        state = _state_of(messages)
        answer = self._script.get(state, ANSWERS[state])
        if isinstance(answer, Exception):
            raise answer
        text = answer if isinstance(answer, str) else self._wrap(answer)
        return Reply(text, model_id=model_id)


def _state_of(messages):
    """Which state's prompt is this? The version line names it."""
    system = messages[0]["content"]
    for state in STATE_ORDER:
        if f"(Prompt version: {state}_v" in system:
            return state
    raise AssertionError("a prompt with no version line reached a provider")


@pytest.fixture
def factory():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # SQLite ignores foreign keys unless asked. The findings tables lean on
    # ON DELETE CASCADE, and a test engine that does not enforce it would let a
    # broken cascade pass here and fail on PostgreSQL.
    @event.listens_for(engine, "connect")
    def _enforce_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def session(factory):
    with factory() as db:
        yield db


@pytest.fixture
def article(session):
    source = ArticleSource(name="Example Research", url="https://example.test/feed")
    session.add(source)
    session.flush()
    row = Article(
        source_id=source.id,
        url="https://example.test/a",
        url_canonical_hash="hash-a",
        title="Elementary Ransomware Group hits a logistics operator",
        body=BODY,
        tlp="clear",
    )
    session.add(row)
    session.commit()
    return row


@pytest.fixture
def catalog():
    return AttackCatalog.from_bundle(
        {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "ap--1",
                    "name": "Valid Accounts",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1078"}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                    ],
                }
            ]
        }
    )


def _machine(provider, catalog, providers=(CLOUD,), **kwargs):
    # The backoff is real seconds in production and none of them here: a suite
    # that waits out its own retry policy is a suite nobody runs.
    kwargs.setdefault("sleep", lambda _seconds: None)
    return ExtractionMachine(
        router=Router(providers=list(providers)),
        providers={"nvidia": provider, "ollama": provider},
        catalog=catalog,
        **kwargs,
    )


def _runs(session, article):
    return {
        row.state: row
        for row in session.scalars(
            select(ArticleAnalysisRun).where(ArticleAnalysisRun.article_id == article.id)
        )
    }


# --- the happy path ----------------------------------------------------------


def test_an_article_walks_all_eight_states_with_a_row_each(session, article, catalog):
    report = _machine(ScriptedProvider(), catalog).run(session, article)

    assert report.completed
    assert [result.state for result in report.results] == list(STATE_ORDER)
    rows = _runs(session, article)
    assert set(rows) == set(STATE_ORDER)
    assert all(row.status == RunStatus.OK for row in rows.values())


def test_every_row_records_the_prompt_it_used_by_name_and_by_content(session, article, catalog):
    """The name alone would not distinguish two edits of the same file, and the
    shared blocks mean an edit in `base.py` changes all eight prompts at once."""
    _machine(ScriptedProvider(), catalog).run(session, article)

    rows = _runs(session, article)
    assert rows["triage"].prompt_version.startswith("triage_v1+")
    assert all(row.prompt_version for row in rows.values())
    assert len({row.prompt_version for row in rows.values()}) == len(STATE_ORDER)


def test_every_call_is_costed_against_the_article_and_the_state(session, article, catalog):
    _machine(ScriptedProvider(), catalog).run(session, article)

    logs = list(session.scalars(select(LlmCallLog)))
    assert len(logs) == len(STATE_ORDER)
    assert {log.state for log in logs} == set(STATE_ORDER)
    assert all(log.article_id == article.id and log.run_id is not None for log in logs)


def test_triage_runs_on_the_cheap_tier_and_the_rest_do_not(session, article, catalog):
    provider = ScriptedProvider()

    _machine(provider, catalog).run(session, article)

    models = [model for model, _ in provider.calls]
    assert models[0] == "small-model", "triage is the cheap pre-filter"
    assert models[-1] == "other-family-model", "the audit is not run by the generator"
    assert set(models[1:-1]) == {"big-model"}


def test_a_fenced_answer_is_not_paid_for_twice(session, article, catalog):
    """Leniency about packaging only: a code fence is not a schema failure."""
    provider = ScriptedProvider(wrap=lambda payload: f"```json\n{json.dumps(payload)}\n```")

    report = _machine(provider, catalog).run(session, article)

    assert report.completed
    assert len(provider.calls) == len(STATE_ORDER)


# --- grounding ---------------------------------------------------------------


def test_only_grounded_indicators_reach_the_row_and_the_later_prompts(session, article, catalog):
    """The model names a second address the article does not contain."""
    invented = dict(ANSWERS["extract_ioc"])
    invented["iocs"] = [
        *ANSWERS["extract_ioc"]["iocs"],
        {
            "ioc_type": "ipv4",
            "value": "198.51.100.9",
            "value_as_written": "198.51.100.9",
            "context": "second C2",
        },
    ]
    provider = ScriptedProvider({"extract_ioc": invented})

    _machine(provider, catalog).run(session, article)

    stored = _runs(session, article)["extract_ioc"].raw_output_json
    assert [ioc["value"] for ioc in stored[OUTPUT_KEY]["iocs"]] == ["203.0.113.7"]
    assert stored["grounding"]["rejected"] == [{"value": "198.51.100.9", "reason": "model_only"}]
    last_user_message = provider.calls[-1][1][1]["content"]
    assert "198.51.100.9" not in last_user_message, "a later state must not see it either"


def test_a_technique_the_catalogue_refuses_never_reaches_the_row(session, article, catalog):
    provider = ScriptedProvider(
        {
            "map_ttp": {
                "mappings": [
                    *ANSWERS["map_ttp"]["mappings"],
                    {
                        "technique_id": "T9999",
                        "evidence_quote": "encrypted files across the estate",
                        "confidence": 0.9,
                    },
                ]
            }
        }
    )

    _machine(provider, catalog).run(session, article)

    stored = _runs(session, article)["map_ttp"].raw_output_json
    assert [m["technique_id"] for m in stored[OUTPUT_KEY]["mappings"]] == ["T1078"]
    assert stored["grounding"]["kept"][0]["technique_name"] == "Valid Accounts"
    assert stored["grounding"]["rejected"][0]["reason"] == "unknown_technique"


def test_a_diamond_vertex_whose_quote_is_not_in_the_article_is_dropped(session, article, catalog):
    """The state its own schema warns about, finally held to the same rule.

    Measured on 68 stored rows before this existed: 35 of 203 asserted vertices
    carried a quote that could not be found in the article, and every one of
    them was stored and displayed exactly like a supported vertex.
    """
    provider = ScriptedProvider(
        {
            "diamond_model": {
                **ANSWERS["diamond_model"],
                "adversary": {
                    "summary": "A ransomware affiliate.",
                    "label": "observed",
                    "evidence_quote": "The affiliate has operated since 2019.",
                },
            }
        }
    )

    _machine(provider, catalog).run(session, article)

    stored = _runs(session, article)["diamond_model"].raw_output_json
    assert stored[OUTPUT_KEY]["adversary"] is None, "no support, no vertex"
    assert stored[OUTPUT_KEY]["infrastructure"] is not None, "the supported one survives"
    assert stored["grounding"]["rejected"] == [
        {"vertex": "adversary", "reason": "quote_not_in_article", "label": "observed"}
    ]


def test_a_dropped_vertex_is_not_offered_to_the_states_that_follow(session, article, catalog):
    """Grounding undone one state later is grounding not done."""
    provider = ScriptedProvider(
        {
            "diamond_model": {
                "adversary": {
                    "summary": "Sponsored by a state programme.",
                    "label": "inferred",
                    "evidence_quote": "The operation was directed by a state sponsor.",
                }
            }
        }
    )

    _machine(provider, catalog).run(session, article)

    last_user_message = provider.calls[-1][1][1]["content"]
    assert "directed by a state sponsor" not in last_user_message


def test_an_unfindable_classify_quote_costs_confidence_not_the_article(session, article, catalog):
    """The type drives every later state, so it is kept and the doubt is priced.

    Refusing the classification would throw a whole article's analysis away over
    a badly copied sentence; on real rows this fires 3 times in 88.
    """
    provider = ScriptedProvider(
        {
            "classify": {
                **ANSWERS["classify"],
                "evidence_quote": "The report describes a supply chain compromise.",
            }
        }
    )

    _machine(provider, catalog).run(session, article)

    stored = _runs(session, article)["classify"].raw_output_json
    assert stored[OUTPUT_KEY]["article_type"] == "incident_report", "the type survives"
    assert stored[OUTPUT_KEY]["confidence"] == "moderate confidence", "high was not earned"
    assert stored["grounding"]["rejected"][0]["confidence_was"] == "high confidence"
    assert stored["grounding"]["kept"] == 0, "the gate reads this block as a count"
    assert anchor_ratio(stored["grounding"]) == 0.0
    assert article.article_type == "incident_report"


def test_a_supported_classification_keeps_the_confidence_the_model_gave(session, article, catalog):
    _machine(ScriptedProvider(), catalog).run(session, article)

    stored = _runs(session, article)["classify"].raw_output_json
    assert stored[OUTPUT_KEY]["confidence"] == "high confidence"
    assert stored["grounding"]["rejected"] == []
    assert anchor_ratio(stored["grounding"]) == 1.0


def _declares_evidence_quote(model, seen=None):
    """Does this schema, or anything nested in it, ask the model for a quote?"""
    seen = seen if seen is not None else set()
    if model in seen:
        return False
    seen.add(model)
    for name, field in model.model_fields.items():
        if name == "evidence_quote":
            return True
        for annotation in (field.annotation, *get_args(field.annotation)):
            for candidate in (annotation, *get_args(annotation)):
                if (
                    isinstance(candidate, type)
                    and issubclass(candidate, BaseModel)
                    and _declares_evidence_quote(candidate, seen)
                ):
                    return True
    return False


@pytest.mark.parametrize("state", STATE_ORDER)
def test_a_state_that_asks_for_evidence_records_what_became_of_it(session, article, catalog, state):
    """The invariant, so the ninth state cannot forget the eighth's lesson.

    Grounding was a branch someone had to remember to write, and twice it was
    not written: the two states that ask for a quote and never checked it were
    `diamond_model` and `classify`. Asserting it here rather than in each state's
    own test means a new prompt with an `evidence_quote` field has to be ground
    to make this pass, instead of being noticed months later on real rows.
    """
    if not _declares_evidence_quote(STATE_SCHEMAS[state]):
        pytest.skip(f"{state} asserts nothing it must evidence")

    _machine(ScriptedProvider(), catalog).run(session, article)

    stored = _runs(session, article)[state].raw_output_json
    assert GROUNDING_KEY in stored, f"{state} asks for a quote and never says what it did"


# --- the actor identity questions (Passo 11) ---------------------------------

#: A body that names two groups and says how one of them relates to the other.
#: The shared `BODY` names no group at all, which is the right article for the
#: extraction tests and useless here: every actor would be dropped for the same
#: reason and the interesting rule would never be reached.
ACTOR_BODY = (
    "Gunra deployed the locker after buying access from a broker. "
    "Researchers track the same operators as Elementary Ransomware Group."
)


@pytest.fixture
def actor_article(session):
    source = ArticleSource(name="Actor Research", url="https://example.test/actors.xml")
    session.add(source)
    session.flush()
    row = Article(
        source_id=source.id,
        url="https://example.test/actors",
        url_canonical_hash="hash-actors",
        title="Gunra and its other name",
        body=ACTOR_BODY,
        tlp="clear",
    )
    session.add(row)
    session.commit()
    return row


def _sketch_with(*actors):
    return {"adversary_sketch": {**ANSWERS["adversary_sketch"], "named_actors": list(actors)}}


def test_a_named_actor_the_article_never_names_is_dropped(session, actor_article, catalog):
    provider = ScriptedProvider(
        _sketch_with(
            {"name": "Gunra", "relation": "unstated"},
            {"name": "Fancy Bear", "relation": "unstated"},
        )
    )

    _machine(provider, catalog).run(session, actor_article)

    stored = _runs(session, actor_article)["adversary_sketch"].raw_output_json
    assert [a["name"] for a in stored[OUTPUT_KEY]["named_actors"]] == ["Gunra"]
    assert stored["grounding"]["rejected"] == [
        {"name": "Fancy Bear", "reason": "name_not_in_article"}
    ]


def test_a_claimed_synonym_without_a_quote_that_anchors_is_reduced(session, actor_article, catalog):
    """The one mistake nothing downstream can see: two adversaries merged.

    The actor is not deleted — the article does name it — but the claim about
    it is, and the unsupported sentence goes with it rather than staying on the
    row to be read later as evidence.
    """
    provider = ScriptedProvider(
        _sketch_with(
            {
                "name": "Gunra",
                "relation": "same_actor",
                "related_to": "Elementary Ransomware Group",
                "evidence_quote": "The vendor confirmed the two names are one group.",
            }
        )
    )

    _machine(provider, catalog).run(session, actor_article)

    stored = _runs(session, actor_article)["adversary_sketch"].raw_output_json
    actor = stored[OUTPUT_KEY]["named_actors"][0]
    assert actor["name"] == "Gunra", "the name is in the article"
    assert actor["relation"] == "unstated", "the claim about it is not"
    assert actor["related_to"] == "" and actor["evidence_quote"] == ""
    assert stored["grounding"]["rejected"][0]["claimed"] == "same_actor"


def test_a_relation_the_article_states_survives_intact(session, actor_article, catalog):
    provider = ScriptedProvider(
        _sketch_with(
            {
                "name": "Gunra",
                "relation": "same_actor",
                "related_to": "Elementary Ransomware Group",
                "evidence_quote": "Researchers track the same operators as Elementary",
            }
        )
    )

    _machine(provider, catalog).run(session, actor_article)

    stored = _runs(session, actor_article)["adversary_sketch"].raw_output_json
    actor = stored[OUTPUT_KEY]["named_actors"][0]
    assert actor["relation"] == "same_actor"
    assert actor["related_to"] == "Elementary Ransomware Group"
    assert stored["grounding"]["rejected"] == []


# --- triage stops the spending ----------------------------------------------


def test_an_irrelevant_article_costs_exactly_one_call(session, article, catalog):
    provider = ScriptedProvider({"triage": {"relevant": False, "reason": "vendor marketing"}})

    report = _machine(provider, catalog).run(session, article)

    assert len(provider.calls) == 1
    assert report.stopped_at == "triage"
    assert "not relevant" in report.stopped_because
    assert set(_runs(session, article)) == {"triage"}
    # The verdict is in the status, so the driver can tell a dropped article
    # from one that crashed after triage without reading JSON out of the row.
    assert _runs(session, article)["triage"].status == RunStatus.DROPPED


def test_a_dropped_article_is_not_re_triaged_on_the_next_pass(session, article, catalog):
    provider = ScriptedProvider({"triage": {"relevant": False, "reason": "vendor marketing"}})
    machine = _machine(provider, catalog)
    machine.run(session, article)

    report = machine.run(session, article)

    assert len(provider.calls) == 1, "the stored triage row answers the question"
    assert report.reused == ("triage",)


# --- restart -----------------------------------------------------------------


def test_a_second_pass_resumes_at_the_first_state_that_is_not_ok(session, article, catalog):
    """The crash case: three states finished, the fourth never did."""
    broken = ScriptedProvider({"map_ttp": RuntimeError("connection reset")})
    _machine(broken, catalog).run(session, article)
    assert _runs(session, article)["map_ttp"].status == RunStatus.ERROR

    healed = ScriptedProvider()
    report = _machine(healed, catalog).run(session, article)

    assert report.completed
    assert report.reused == ("triage", "classify", "extract_ioc")
    assert {_state_of(messages) for _, messages in healed.calls} == {
        "map_ttp",
        "diamond_model",
        "narrative",
        "adversary_sketch",
        "verify",
    }


def test_attempts_accumulate_across_passes(session, article, catalog):
    """It is the honest number: what the article has cost so far."""
    _machine(ScriptedProvider({"triage": RuntimeError("down")}), catalog).run(session, article)
    _machine(ScriptedProvider(), catalog).run(session, article)

    assert _runs(session, article)["triage"].attempts == 5  # 4 failed, then one that worked


# --- re-ask, escalate, stage -------------------------------------------------


def test_a_schema_failure_is_retried_on_the_same_model_then_escalated(session, article, catalog):
    """ADR-006 §1: two retries, then one tier up, then a human."""
    provider = ScriptedProvider({"triage": "not json at all"})

    report = _machine(provider, catalog).run(session, article)

    models = [model for model, _ in provider.calls]
    assert models == ["small-model"] * 3 + ["big-model"]
    assert report.stopped_at == "triage"
    assert _runs(session, article)["triage"].status == RunStatus.STAGED


def test_an_analysis_state_has_nowhere_to_escalate_to(session, article, catalog):
    provider = ScriptedProvider({"classify": '{"article_type": "nonsense"}'})

    _machine(provider, catalog).run(session, article)

    classify_calls = [model for model, m in provider.calls if _state_of(m) == "classify"]
    assert classify_calls == ["big-model"] * 3
    assert _runs(session, article)["classify"].status == RunStatus.STAGED


def test_a_staged_row_says_why_without_a_log_to_read(session, article, catalog):
    _machine(ScriptedProvider({"triage": "not json at all"}), catalog).run(session, article)

    assert "schema" in _runs(session, article)["triage"].raw_output_json["detail"]


def test_a_provider_that_cannot_be_reached_is_an_outage_not_a_staging(session, article, catalog):
    """Different statuses because they lead to different actions."""
    _machine(ScriptedProvider({"triage": RuntimeError("connection reset")}), catalog).run(
        session, article
    )

    row = _runs(session, article)["triage"]
    assert row.status == RunStatus.ERROR
    assert "connection reset" in row.raw_output_json["detail"]


def test_a_state_that_stages_stops_the_states_after_it(session, article, catalog):
    provider = ScriptedProvider({"classify": "not json"})

    report = _machine(provider, catalog).run(session, article)

    assert report.stopped_at == "classify"
    assert set(_runs(session, article)) == {"triage", "classify"}


# --- refusals ----------------------------------------------------------------


def test_a_tlp_refusal_is_recorded_and_costs_nothing(session, article, catalog):
    article.tlp = "amber"
    session.commit()
    provider = ScriptedProvider()

    report = _machine(provider, catalog).run(session, article)

    assert provider.calls == [], "nothing was sent anywhere"
    assert _runs(session, article)["triage"].status == "blocked_tlp"
    assert report.stopped_at == "triage"


def test_a_refusal_does_not_try_the_states_after_it(session, article, catalog):
    article.tlp = "red"
    session.commit()

    _machine(ScriptedProvider(), catalog).run(session, article)

    assert set(_runs(session, article)) == {"triage"}


def test_an_override_sends_the_article_and_leaves_an_audit_row(session, article, catalog):
    article.tlp = "amber"
    session.commit()
    override = TlpOverride(actor="analyst@example.test", justification="live incident")

    report = _machine(ScriptedProvider(), catalog).run(session, article, override=override)

    assert report.completed
    audits = list(session.scalars(select(AiEnrichmentAudit)))
    assert len(audits) == len(STATE_ORDER)
    assert audits[0].after_json["provider"] == "nvidia"


def test_a_router_choice_with_no_wired_provider_is_an_error_not_a_crash(session, article, catalog):
    machine = ExtractionMachine(
        router=Router(providers=[CLOUD]),
        providers={},  # nothing wired
        catalog=catalog,
    )

    report = machine.run(session, article)

    assert report.stopped_at == "triage"
    assert _runs(session, article)["triage"].status == RunStatus.ERROR
    assert "not wired in" in report.stopped_because


def test_a_local_only_deployment_still_triages_amber_content(session, article, catalog):
    """The TLP gate leaves local providers standing; that is the point of it."""
    article.tlp = "amber"
    session.commit()
    provider = ScriptedProvider()

    report = _machine(provider, catalog, providers=(CLOUD, LOCAL)).run(session, article)

    assert [model for model, _ in provider.calls] == ["local-small"]
    assert _runs(session, article)["triage"].status == RunStatus.OK
    assert report.stopped_at == "classify", "no local model serves the analysis tier"


# --- degenerate input --------------------------------------------------------


def test_an_article_with_no_body_is_refused_before_any_prompt_is_built(session, catalog):
    empty = Article(
        url="https://example.test/empty",
        url_canonical_hash="hash-empty",
        title="Nothing here",
        body=None,
        tlp="clear",
    )
    session.add(empty)
    session.commit()
    provider = ScriptedProvider()

    report = _machine(provider, catalog).run(session, empty)

    assert provider.calls == []
    assert report.results == () and report.stopped_at == "triage"


# --- findings become rows ----------------------------------------------------


def test_kept_indicators_become_rows_whose_spans_cut_the_article(session, article, catalog):
    """The span is the evidence; a row whose offsets do not slice the body is
    an assertion, not a finding."""
    _machine(ScriptedProvider(), catalog).run(session, article)

    (row,) = list(session.scalars(select(ArticleIoc)))
    assert (row.ioc_type, row.value) == ("ipv4", "203.0.113.7")
    assert row.value_defanged == "203.0.113[.]7"
    assert BODY[row.span_start : row.span_end] == "203.0.113[.]7"
    assert row.run_id is not None


def test_kept_techniques_become_rows_named_by_the_catalogue(session, article, catalog):
    _machine(ScriptedProvider(), catalog).run(session, article)

    (row,) = list(session.scalars(select(ArticleTtp)))
    assert (row.technique_id, row.technique_name) == ("T1078", "Valid Accounts")
    assert (row.tactic_id, row.tactic_name) == ("TA0001", "Initial Access")
    assert BODY[row.evidence_span_start : row.evidence_span_end] in BODY
    assert row.confidence == 0.8


def test_a_rejected_indicator_never_reaches_the_findings_table(session, article, catalog):
    provider = ScriptedProvider(
        {
            "extract_ioc": {
                "iocs": [
                    {
                        "ioc_type": "ipv4",
                        "value": "198.51.100.9",
                        "value_as_written": "198.51.100.9",
                        "context": "invented",
                    }
                ]
            }
        }
    )

    _machine(provider, catalog).run(session, article)

    assert list(session.scalars(select(ArticleIoc))) == []


def test_re_running_a_state_replaces_its_findings_rather_than_doubling_them(
    session, article, catalog
):
    """`(article_id, ioc_type, value)` is unique, so adding would fail anyway —
    but the reason to clear is that a re-run's results supersede the old ones."""
    machine = _machine(ScriptedProvider(), catalog)
    machine.run(session, article)
    for row in session.scalars(select(ArticleAnalysisRun)):
        if row.state in {"extract_ioc", "map_ttp"}:
            row.status = RunStatus.STAGED  # force both to run again
    session.commit()

    machine.run(session, article)

    assert len(list(session.scalars(select(ArticleIoc)))) == 1
    assert len(list(session.scalars(select(ArticleTtp)))) == 1


def test_deleting_an_article_takes_its_findings_with_it(session, article, catalog):
    _machine(ScriptedProvider(), catalog).run(session, article)

    session.delete(article)
    session.commit()

    assert list(session.scalars(select(ArticleIoc))) == []
    assert list(session.scalars(select(ArticleTtp))) == []


def test_the_pacer_runs_before_every_request(session, article, catalog):
    """The provider's limit is per account, so it is imposed per request — a
    delay between articles would let a burst of eight sail past it."""
    ticks = []
    provider = ScriptedProvider()

    _machine(provider, catalog, pacer=lambda: ticks.append(len(provider.calls))).run(
        session, article
    )

    assert ticks == list(range(len(STATE_ORDER))), "one tick before each call, none after"


def test_a_call_that_never_landed_is_not_re_sent_at_full_speed(session, article, catalog):
    """The acceptance run spent all three attempts inside a few seconds against
    a provider answering "no capacity". A schema failure is re-asked at once —
    the model is there and answering — but an unreachable service gets time."""
    waits = []

    _machine(
        ScriptedProvider({"triage": RuntimeError("no capacity")}),
        catalog,
        sleep=waits.append,
    ).run(session, article)

    assert waits == [*BACKOFF_SECONDS, BACKOFF_SECONDS[-1]], "one wait per failed attempt"


def test_a_schema_failure_is_re_asked_without_waiting(session, article, catalog):
    waits = []

    _machine(ScriptedProvider({"triage": "not json"}), catalog, sleep=waits.append).run(
        session, article
    )

    assert waits == []


def test_each_state_gets_the_room_its_prompt_asked_for(session, article, catalog):
    """One ceiling for eight schemas cut `extract_ioc` off mid-object on the
    acceptance run: a good answer turned into a failed one and paid for twice."""
    asked = {}

    class Recording(ScriptedProvider):
        def complete(self, model_id, messages, max_tokens=1024, temperature=0.0):
            asked[_state_of(messages)] = max_tokens
            return super().complete(model_id, messages, max_tokens, temperature)

    _machine(Recording(), catalog).run(session, article)

    assert asked["triage"] < asked["map_ttp"] < asked["extract_ioc"]
    assert asked == {state: PROMPTS[state].max_output_tokens for state in STATE_ORDER}


def test_an_answer_cut_off_at_the_ceiling_says_so(session, article, catalog):
    """Otherwise it reads as a schema failure, and the fix looks like rewriting
    a prompt when it is raising a number."""

    class Truncating(ScriptedProvider):
        def complete(self, model_id, messages, max_tokens=1024, temperature=0.0):
            reply = super().complete(model_id, messages, max_tokens, temperature)
            reply.text = reply.text[: len(reply.text) // 2]  # cut mid-object
            reply.tokens_out = max_tokens
            return reply

    _machine(Truncating(), catalog).run(session, article)

    detail = _runs(session, article)["triage"].raw_output_json["detail"]
    assert "cut off" in detail and "max_output_tokens" in detail


def test_the_analysis_reaches_the_columns_the_site_already_renders(session, article, catalog):
    """`article_type`, `summary_md` and `recommendations_md` predate this
    pipeline and are what the article pages show. An analysis that lands only
    in the run rows is an analysis nobody sees."""
    _machine(ScriptedProvider(), catalog).run(session, article)

    assert article.article_type == "incident_report"
    assert article.summary_md == "A logistics operator was encrypted."
    assert article.recommendations_md is None, "an empty recommendation is not a blank one"


def test_a_restart_repairs_the_columns_without_paying_for_them(session, article, catalog):
    provider = ScriptedProvider()
    machine = _machine(provider, catalog)
    machine.run(session, article)
    article.summary_md = None  # as if a migration or an edit had cleared it
    session.commit()

    machine.run(session, article)

    assert article.summary_md == "A logistics operator was encrypted."
    assert len(provider.calls) == len(STATE_ORDER), "no second run was paid for"


# --- the audit is not run by the model it audits ------------------------------


def test_the_audit_runs_on_a_model_the_generator_did_not_write_with(session, article, catalog):
    """The Verify state exists to catch the other states out. A model from the
    same family shares their blind spots, which is a second opinion from the
    same mind."""
    provider = ScriptedProvider()

    _machine(provider, catalog).run(session, article)

    by_state = {_state_of(messages): model for model, messages in provider.calls}
    assert by_state["verify"] != by_state["narrative"]
    logs = {log.state: log.model_id for log in session.scalars(select(LlmCallLog))}
    assert logs["verify"] != logs["narrative"], "and the rows can prove it afterwards"


def test_without_a_judge_the_audit_refuses_instead_of_grading_its_own_homework(
    session, article, catalog
):
    """The whole point of refusing: a self-audit produces labels, a quality
    rating and — in Phase 5 — a confidence number. It looks like an audit. A
    missing one is visible; a self-administered one is not."""
    provider = ScriptedProvider()

    report = _machine(provider, catalog, providers=(NO_JUDGE,)).run(session, article)

    assert report.stopped_at == "verify"
    assert _runs(session, article)["verify"].status == "no_provider"
    assert "big-model" not in [model for model, m in provider.calls if _state_of(m) == "verify"]


def test_the_refusal_names_the_fix_rather_than_the_symptom(session, article, catalog):
    _machine(ScriptedProvider(), catalog, providers=(NO_JUDGE,)).run(session, article)

    detail = _runs(session, article)["verify"].raw_output_json["detail"]
    assert "judge" in detail and "worse than none" in detail


def test_a_degraded_budget_pauses_the_judge_as_well_as_the_analysis(session, article, catalog):
    """Judge spend is analysis-grade. The rule ADR-006 §2 states is that the
    cheap pre-filter keeps running and the expensive work does not."""
    from pestilentia.ai.router.decisions import Refusal, RefusalReason, Tier

    router = Router(providers=[CLOUD])
    verdicts = {
        tier: router.choose(tier, article_tlp="clear", budget_allows_tier=False) for tier in Tier
    }

    assert not isinstance(verdicts[Tier.TRIAGE], Refusal), "triage still runs"
    for tier in (Tier.ANALYSIS, Tier.JUDGE):
        assert isinstance(verdicts[tier], Refusal)
        assert verdicts[tier].reason is RefusalReason.BUDGET_EXHAUSTED


# --- the style rule that gets applied rather than repeated --------------------


def test_a_clean_answer_is_recorded_as_checked_and_not_merely_unflagged(session, article, catalog):
    """A row has to say what was checked, or nobody can tell a clean text from
    an unexamined one."""
    _machine(ScriptedProvider(), catalog).run(session, article)

    style = _runs(session, article)["narrative"].raw_output_json["style"]
    assert style["violations"] == []
    assert style["rewritten"] is False


def test_a_violation_gets_one_rewrite_carrying_the_offending_words(session, article, catalog):
    """The diagnosis behind this step: the style block states rules in general
    and before the text exists, while a violation names the words in this text.
    Only the second is information the model did not already have.
    """
    dirty = {**ANSWERS["narrative"], "summary_md": "They used various tools, and more."}
    clean = {**ANSWERS["narrative"], "summary_md": "They used Mimikatz and PsExec."}
    provider = ScriptedProvider({"narrative": dirty})

    original = provider.complete

    def once_then_clean(model_id, messages, **kwargs):
        if any("broke the house style" in m["content"] for m in messages):
            return Reply(json.dumps(clean), model_id=model_id)
        return original(model_id, messages, **kwargs)

    provider.complete = once_then_clean
    _machine(provider, catalog).run(session, article)

    stored = _runs(session, article)["narrative"].raw_output_json
    assert stored[OUTPUT_KEY]["summary_md"] == "They used Mimikatz and PsExec."
    assert stored["style"]["rewritten"] is True
    assert stored["style"]["violations"] == []


def test_what_the_rewrite_does_not_fix_is_recorded_rather_than_refused(session, article, catalog):
    """At two violations per assessment, staging everything with one would queue
    the whole corpus, and a queue holding everything is a refusal to work wearing
    the clothes of rigour."""
    dirty = {**ANSWERS["narrative"], "summary_md": "They used various tools, and more."}

    _machine(ScriptedProvider({"narrative": dirty}), catalog).run(session, article)

    row = _runs(session, article)["narrative"]
    assert row.status == RunStatus.OK, "recorded as non-conforming, not thrown away"
    rules = {v["rule"] for v in row.raw_output_json["style"]["violations"]}
    assert {"vague_quantifier", "open_enumeration"} <= rules


def test_a_state_that_writes_no_prose_is_not_style_checked(session, article, catalog):
    """`extract_ioc` writes indicators. Measuring its prose would be measuring
    something that does not exist and reporting it as clean."""
    _machine(ScriptedProvider(), catalog).run(session, article)

    assert "style" not in _runs(session, article)["extract_ioc"].raw_output_json
