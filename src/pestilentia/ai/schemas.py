# "I'm a consultant. The police don't hire me." — Sherlock, Elementary
"""Pydantic schemas for the eight extraction states (Phase 4, ADR-006 §1).

One model per state. They are the contract the LLM output must satisfy before
anything is persisted; a validation failure is what triggers the re-ask policy
(2 retries → escalate one tier → stage for review), so these models are the
place where "the model said something odd" becomes a decision rather than a
corrupted row.

Three rules run through all of them:

**Nothing unlabelled.** Every analytic statement carries an `EvidenceLabel`.
The pattern comes from `the-italian-job`'s prompt library, where it is a text
prefix; here it is a field, so the fence is enforced by validation instead of
by reading the prose.

**The model never supplies offsets.** It returns the value and the wording it
saw; `extraction/anchors.py` finds the span in the article body. Asking a
language model for character offsets invites confident arithmetic about text
it cannot count, and a fabricated offset would look exactly like a real one.

**Everything is bounded.** Every string has a `max_length` and every list a
`max_length`. A model that loops must fail validation, not write megabytes
into `ArticleAnalysisRun.raw_output_json`.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, computed_field

# Bounds. Generous enough for real analysis, small enough that a runaway
# generation is a validation error rather than a database problem.
_SHORT = 300
_QUOTE = 1000
_PROSE = 4000
_MARKDOWN = 8000
_MAX_IOCS = 100
#: Roadmap criterion 4: ten techniques per article, enforced in `ttps.py`.
MAX_TTPS = 10
#: What the *schema* allows through, which is deliberately not the same number.
#: The acceptance run threw away three good answers because the model returned
#: eleven mappings: a hard eleven-is-nothing bound turns a nearly-right answer
#: into a total failure at three times the cost, while `ttps.reconcile` can
#: keep the best ten and *report* the rest as `over_cap`. Schema bounds are
#: runaway guards; the criterion is policy, and policy belongs where it can
#: explain itself.
_MAX_TTP_PROPOSALS = 50
#: A runaway guard, like every other bound here. The *policy* — audit the ten
#: to twenty claims that carry the analysis — lives in the prompt, because a
#: model reads the prompt and does not read `maxLength`. Three states have now
#: taught this the expensive way: the triage reason, the TTP list, and this.
_MAX_CLAIMS = 30


class EvidenceLabel(StrEnum):
    """Is this something the article says, or something we concluded?"""

    OBSERVED = "observed"
    INFERRED = "inferred"


class AuditLabel(StrEnum):
    """The Verify state's third option: traceable to nothing at all."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    UNVERIFIED = "unverified"


class ConfidenceLevel(StrEnum):
    """ICD 203 §6 confidence scale. Never mixed with `Likelihood` in one
    statement — "high confidence that this is nearly certain" says nothing."""

    HIGH = "high confidence"
    MODERATE = "moderate confidence"
    LOW = "low confidence"


class Likelihood(StrEnum):
    """ICD 203 §6 likelihood scale, in order."""

    REMOTE = "remote"
    VERY_UNLIKELY = "very unlikely"
    UNLIKELY = "unlikely"
    EVEN_CHANCE = "roughly even chance"
    LIKELY = "likely"
    VERY_LIKELY = "very likely"
    NEARLY_CERTAIN = "nearly certain"


class ArticleType(StrEnum):
    INCIDENT_REPORT = "incident_report"
    ADVISORY = "advisory"
    BLOG = "blog"
    IOC_DUMP = "ioc_dump"
    DISINFORMATION = "disinformation"


class IocType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    BTC_ADDRESS = "btc_address"


class AttributionLevel(StrEnum):
    """Tactical clusters indicators, operational describes capability,
    strategic names an actor. The prompts default to tactical and escalate
    only when the evidence demands it."""

    TACTICAL = "tactical"
    OPERATIONAL = "operational"
    STRATEGIC = "strategic"


class EvidenceQuality(StrEnum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


class _Strict(BaseModel):
    """Unknown fields are rejected rather than ignored.

    A model inventing a field is telling us it misread the task; silently
    dropping it would discard that signal and let the run look clean.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --- 1. Triage ---------------------------------------------------------------


class TriageOutput(_Strict):
    """Cheap tier, run before any analysis-tier spend."""

    relevant: bool
    #: 600, not `_SHORT`. The acceptance run failed twice here on answers that
    #: were correct and 310 characters long: the bound is a runaway guard, and
    #: at 300 it was a brevity rule the model paid three cheap-tier calls to
    #: discover. The prompt now asks for one sentence; this is the ceiling that
    #: catches a model writing an essay, not one writing a long sentence.
    reason: str = Field(max_length=600)


# --- 2. Classify -------------------------------------------------------------


class ClassifyOutput(_Strict):
    article_type: ArticleType
    confidence: ConfidenceLevel
    evidence_quote: str = Field(max_length=_QUOTE)


# --- 3. ExtractIOC -----------------------------------------------------------


class ExtractedIoc(_Strict):
    """One indicator, as the model found it.

    `value_as_written` is the form that appears in the article — often
    defanged (`1.2.3[.]4`). Keeping both lets the anchor step search for the
    text that is really there while the canonical `value` is what gets stored
    and compared.
    """

    ioc_type: IocType
    value: str = Field(max_length=_SHORT)
    value_as_written: str = Field(max_length=_SHORT)
    context: str = Field(default="", max_length=_QUOTE)


class ExtractIocOutput(_Strict):
    iocs: list[ExtractedIoc] = Field(default_factory=list, max_length=_MAX_IOCS)


# --- 4. MapTTP ---------------------------------------------------------------


class TtpMapping(_Strict):
    """`technique_id` is checked against the ATT&CK catalogue and
    `evidence_quote` against the article body; neither is taken on trust.

    `confidence` is numeric here, not an ICD 203 term, because Phase 5 folds
    it into a composite score. The prose states elsewhere carry the words.
    """

    technique_id: str = Field(max_length=20)
    evidence_quote: str = Field(min_length=1, max_length=_QUOTE)
    confidence: float = Field(ge=0.0, le=1.0)


class MapTtpOutput(_Strict):
    mappings: list[TtpMapping] = Field(default_factory=list, max_length=_MAX_TTP_PROPOSALS)


# --- 5. DiamondModel ---------------------------------------------------------


class DiamondVertex(_Strict):
    """A vertex stands on its own evidence.

    Every vertex carries its own label and quote precisely so that one cannot
    be inferred from another — deriving the adversary from the infrastructure
    is the classic way a diamond turns into a guess.
    """

    summary: str = Field(max_length=_PROSE)
    label: EvidenceLabel
    evidence_quote: str = Field(default="", max_length=_QUOTE)


class DiamondModelOutput(_Strict):
    """A vertex with no support in the article is `None` — the honest answer,
    and the one the prompt asks for, rather than a plausible sentence."""

    adversary: DiamondVertex | None = None
    infrastructure: DiamondVertex | None = None
    capability: DiamondVertex | None = None
    victim: DiamondVertex | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def vertices_supported(self) -> int:
        return sum(
            vertex is not None
            for vertex in (self.adversary, self.infrastructure, self.capability, self.victim)
        )


# --- 6. Narrative ------------------------------------------------------------


class NarrativeOutput(_Strict):
    """ICD 203: the main judgement leads, and it is stated as a judgement."""

    key_judgement: str = Field(max_length=_PROSE)
    confidence: ConfidenceLevel
    summary_md: str = Field(max_length=_MARKDOWN)
    recommendations_md: str = Field(default="", max_length=_MARKDOWN)


# --- 7. AdversarySketch ------------------------------------------------------


class ActorRelation(StrEnum):
    """How one name in an article relates to the others in it.

    Binary would have been cheaper and would have lost the thing worth knowing.
    Measured on real output: one article named `MOIS`, `IRGC Intelligence
    Organization` and `Handala Hack Team`. They are not synonyms, and they are
    not strangers either: two are state organs and the third is a front. A
    same-actor / not-same-actor answer collapses that into whichever error the
    reader is unlucky enough to make.
    """

    #: One actor under two names. The vendor's cryptonym against the group's own.
    SAME_ACTOR = "same_actor"
    #: Runs intrusions under the other's programme and takes a share.
    AFFILIATE_OF = "affiliate_of"
    #: Runs the programme the other affiliates to.
    OPERATOR_OF = "operator_of"
    #: The other is what this one became, or what it was before a rebrand.
    REBRAND_OF = "rebrand_of"
    #: Sells the access, does not deploy the payload.
    BROKER_FOR = "broker_for"
    #: Distinct actors that this article merely mentions together.
    SEPARATE = "separate"
    #: The article names them together and does not say how they connect.
    UNSTATED = "unstated"


class NamedActor(_Strict):
    """One name the article uses, and what the article says it is.

    A flat list of names made the reader supply the relationship, and the
    reader supplied a wrong one: every name became an alias of every other. The
    fix is not a better guess downstream, it is asking the question here.
    """

    name: str = Field(max_length=_SHORT)
    #: Whether this name matches one already in the adversary database, whose
    #: names are supplied to the prompt as data. The model's answer to a
    #: question the resolver can also answer, and kept for exactly that reason:
    #: a disagreement between the two is a signal about the article's wording.
    matches_known: bool = False
    relation: ActorRelation = ActorRelation.UNSTATED
    #: The other name this one relates to, verbatim as the article writes it.
    #: Empty for `separate` and `unstated`, which relate to nothing.
    related_to: str = Field(default="", max_length=_SHORT)
    #: The stretch of the article that establishes the relation, copied not
    #: paraphrased. Checked against the body downstream exactly as a technique's
    #: evidence is: a claimed relation whose quote cannot be found is not a
    #: weaker claim, it is an unsupported one, and it is reduced to `unstated`
    #: rather than believed. Empty is the honest answer where the article says
    #: nothing, and `unstated` is the relation that goes with it.
    evidence_quote: str = Field(default="", max_length=_QUOTE)


class AdversarySketchOutput(_Strict):
    """Never a `Group.id`: the LLM describes, a deterministic matcher resolves
    (ADR-006 §3). `named_actors` holds names *as the article states them*, and
    resolving them to rows is Phase 5's problem.

    The two caveat fields are required rather than optional. In ransomware
    reporting the operator/affiliate/broker distinction and the false-flag
    question are not edge cases, and a sketch that never considered them is
    the one most likely to be confidently wrong.
    """

    attribution_level: AttributionLevel = AttributionLevel.TACTICAL
    cluster_summary: str = Field(max_length=_PROSE)
    named_actors: list[NamedActor] = Field(default_factory=list, max_length=20)
    likelihood: Likelihood
    confidence: ConfidenceLevel
    shared_infrastructure_note: str = Field(max_length=_PROSE)
    false_flag_note: str = Field(max_length=_PROSE)


# --- 8. Verify ---------------------------------------------------------------


class AuditedClaim(_Strict):
    claim: str = Field(min_length=1, max_length=_QUOTE)
    label: AuditLabel
    justification: str = Field(default="", max_length=_QUOTE)

    @property
    def identity(self) -> str:
        """The claim as an assertion rather than as a string.

        Case, spacing and a trailing full stop are not what makes two claims
        different; the words are.
        """
        return " ".join(self.claim.split()).casefold().rstrip(".;:!? ")


class VerifyOutput(_Strict):
    """A second pass that re-examines the earlier states' claims.

    Pattern taken from `the-italian-job`'s AUDIT_SYSTEM_PROMPT. Run it on a
    different model family from the generator: a model asked to audit itself
    grades its own homework.

    `evidence_quality` is **computed, not supplied**. Letting the model report
    its own score adds a field it can get wrong in the one place we are trying
    to catch it being wrong.
    """

    claims: list[AuditedClaim] = Field(default_factory=list, max_length=_MAX_CLAIMS)

    @property
    def distinct_labels(self) -> dict[str, AuditLabel]:
        """One label per distinct assertion, the worst of any repeats.

        Both halves were measured on the 2026-08-12 acceptance run, where the
        judge returned 23 claims of which 15 were distinct.

        **Repeats are not evidence of quality.** The three generative states
        restate the same facts, and the judge audits them state by state, so the
        same assertion arrives two or three times. Since the rating is the
        fraction labelled `observed`, easy repeats *raise* it and dilute the
        weight of a single unverified claim — the exact thing the threshold is
        there to prevent.

        **The worst label wins.** Otherwise a repeat could launder an
        `unverified` into a majority of `observed`, which is the same hole
        reopened from the other side.

        The claims themselves are never rewritten: they are the audit trail, and
        what gets deduplicated is the count, not the evidence.
        """
        severity = {AuditLabel.OBSERVED: 0, AuditLabel.INFERRED: 1, AuditLabel.UNVERIFIED: 2}
        worst: dict[str, AuditLabel] = {}
        for claim in self.claims:
            current = worst.get(claim.identity)
            if current is None or severity[claim.label] > severity[current]:
                worst[claim.identity] = claim.label
        return worst

    @computed_field  # type: ignore[prop-decorator]
    @property
    def evidence_quality(self) -> EvidenceQuality:
        """High above 80% observed; low if anything is unverified.

        An unverified claim traces to no source at all, so one is enough to
        sink the rating — the threshold exists to stop a wall of sourced
        statements from burying a fabricated one. Counted over distinct
        assertions: see `distinct_labels` for why repeats do not count.
        """
        labels = list(self.distinct_labels.values())
        if not labels:
            return EvidenceQuality.LOW
        if AuditLabel.UNVERIFIED in labels:
            return EvidenceQuality.LOW
        observed = sum(label is AuditLabel.OBSERVED for label in labels)
        ratio = observed / len(labels)
        if ratio > 0.8:
            return EvidenceQuality.HIGH
        if ratio >= 0.5:
            return EvidenceQuality.MODERATE
        return EvidenceQuality.LOW


# The state name in `ArticleAnalysisRun.state` maps to the schema its output
# must satisfy. Keeping it here means the runner never grows a dispatch chain.
STATE_SCHEMAS: dict[str, type[_Strict]] = {
    "triage": TriageOutput,
    "classify": ClassifyOutput,
    "extract_ioc": ExtractIocOutput,
    "map_ttp": MapTtpOutput,
    "diamond_model": DiamondModelOutput,
    "narrative": NarrativeOutput,
    "adversary_sketch": AdversarySketchOutput,
    "verify": VerifyOutput,
}

STATE_ORDER: tuple[str, ...] = (
    "triage",
    "classify",
    "extract_ioc",
    "map_ttp",
    "diamond_model",
    "narrative",
    "adversary_sketch",
    "verify",
)
