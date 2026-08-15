# "I never guess. It is a shocking habit." — Sherlock Holmes
"""The two-axis evaluation, after UNODC chapter 4 (Phase 5, step 3b).

> Evaluation of the source must be made separately to the information.
> — UNODC, *Criminal Intelligence: Manual for Analysts*, ch. 4, principle 2

That sentence is the whole design. The reputation of the feed and the validity
of what it reported are two different questions with two different answers, and
a single number that fuses them cannot be taken apart again. So they stay apart:
two grades, two factors, both persisted beside the score they acted on.

**Why the 6x6 scale and not the 4x4 Europol uses.** The 4x4's information axis
is built on the source's personal knowledge, "hearsay information is afforded a
lower rating", which is a concept for a human informant and has no translation
for an RSS article. The 6x6's validity axis is built on confirmation, internal
consistency and contradiction, and those are predicates we can compute over
rows we already hold. On the source axis the 6x6 can say "fairly reliable,
history of periodic reliability" where the 4x4 can only say "in most instances
proved to be unreliable": BleepingComputer reports other people's research
competently and deserves the former.

**The grade is what an analyst sets; the factor is only its arithmetic.** Before
this, `article_sources.trust_weight` held 0.85 and nothing said why. A grade has
written criteria behind it, and the recalibration in Phase 7 then has six
meaningful values per axis to tune rather than twelve arbitrary floats.

**Not judgeable is a grade, not a middle.** F on the source axis and 6 on the
information axis mean the question could not be answered. UNODC is explicit that
this is recorded as its own value rather than collapsed into a mediocre one, and
the rule that follows is the important one: **a finding that cannot be judged on
either axis is never enriched automatically.** It goes to staging. The gate does
not guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from pestilentia.models.tables import (
    AdminAudit,
    Article,
    ArticleIoc,
    ArticleSource,
    ArticleTtp,
)


class SourceGrade(StrEnum):
    """The reliability of the feed, A to F (UNODC 6x6, source axis)."""

    COMPLETELY_RELIABLE = "A"
    USUALLY_RELIABLE = "B"
    FAIRLY_RELIABLE = "C"
    NOT_USUALLY_RELIABLE = "D"
    UNRELIABLE = "E"
    CANNOT_BE_JUDGED = "F"


class InfoGrade(StrEnum):
    """The validity of the report, 1 to 6 (UNODC 6x6, information axis)."""

    CONFIRMED = "1"
    PROBABLY_TRUE = "2"
    POSSIBLY_TRUE = "3"
    DOUBTFUL = "4"
    IMPROBABLE = "5"
    CANNOT_BE_JUDGED = "6"


#: Provisional, and step 9 of the phase plan is where they stop being so. Grade
#: A is 1.0 because "no doubt regarding authenticity, trustworthiness,
#: integrity, competence" has no reason to carry a penalty, and because the
#: arbitrary 0.9 ceiling it replaces made the 0.85 IOC threshold unreachable.
SOURCE_FACTORS: dict[SourceGrade, float] = {
    SourceGrade.COMPLETELY_RELIABLE: 1.00,
    SourceGrade.USUALLY_RELIABLE: 0.90,
    SourceGrade.FAIRLY_RELIABLE: 0.75,
    SourceGrade.NOT_USUALLY_RELIABLE: 0.55,
    SourceGrade.UNRELIABLE: 0.30,
}

INFO_FACTORS: dict[InfoGrade, float] = {
    InfoGrade.CONFIRMED: 1.00,
    InfoGrade.PROBABLY_TRUE: 0.90,
    InfoGrade.POSSIBLY_TRUE: 0.75,
    InfoGrade.DOUBTFUL: 0.50,
    InfoGrade.IMPROBABLE: 0.20,
}

#: The two grades that mean "no answer". They have no factor by design: giving
#: them one would turn an absent judgement into a poor one.
UNJUDGEABLE = (SourceGrade.CANNOT_BE_JUDGED, InfoGrade.CANNOT_BE_JUDGED)


@dataclass(frozen=True)
class Corroboration:
    """What the record already says about a claim, before it is graded.

    `independent_sources` counts **feeds**, not articles. Three write-ups of one
    vendor's research republished by three outlets are one source's claim
    repeated, and counting them as three would manufacture confirmation out of
    syndication, which is the failure mode this whole axis exists to avoid.
    """

    independent_sources: int = 0
    contradicted: bool = False
    #: False only where the record holds something incompatible in kind, not
    #: merely absent. Absence is what grade 3 is for.
    consistent_with_record: bool = True


@dataclass(frozen=True)
class GradedScore:
    """A raw composite after both axes have acted, with the working shown."""

    score_raw: float
    source_grade: SourceGrade
    source_factor: float | None
    info_grade: InfoGrade
    info_factor: float | None
    score_total: float
    #: True when either axis returned its cannot-be-judged grade. The gate
    #: stages these whatever the number says.
    unjudgeable: bool


def source_grade_of(letter: str | None) -> SourceGrade:
    """The feed's grade, or F when there is nothing to read.

    A missing grade is not a bad grade. A source nobody has assessed cannot be
    judged, which is exactly what F says, and the consequence is staging rather
    than a quiet low score.
    """
    if not letter:
        return SourceGrade.CANNOT_BE_JUDGED
    try:
        return SourceGrade(letter.strip().upper())
    except ValueError:
        return SourceGrade.CANNOT_BE_JUDGED


def info_grade_of(corroboration: Corroboration | None) -> InfoGrade:
    """The validity grade, from predicates the record can answer.

    The 6x6's own definitions, in the order the manual puts them:

    - **1, confirmed** by another independent source.
    - **2, probably true**, logical in itself and consistent with what is held,
      which for us means the same feed has said it before and nothing disagrees.
    - **3, possibly true**, not confirmed and not contradicted. This is where an
      ordinary first report lands, and it is the honest default.
    - **5, improbable**, contradicted by other information on the subject.
    - **6**, no basis to judge at all.

    Grade 4, doubtful, is deliberately not reachable from these predicates.
    Distinguishing "doubtful" from "possibly true" needs a judgement about the
    claim's own plausibility that nothing in the schema supports, and inventing
    a rule to reach it would be manufacturing a grade rather than assigning one.
    A human reviewer can set it in Phase 6.
    """
    if corroboration is None:
        return InfoGrade.CANNOT_BE_JUDGED
    if corroboration.contradicted:
        return InfoGrade.IMPROBABLE
    if corroboration.independent_sources >= 1:
        return InfoGrade.CONFIRMED
    if not corroboration.consistent_with_record:
        return InfoGrade.IMPROBABLE
    return InfoGrade.POSSIBLY_TRUE


def apply_axes(
    score_raw: float,
    source_grade: SourceGrade,
    info_grade: InfoGrade,
    *,
    source_factors: dict[SourceGrade, float] | None = None,
    info_factors: dict[InfoGrade, float] | None = None,
) -> GradedScore:
    """Multiply the composite by both axes, and say what was applied.

    Multiplied rather than added in, which is the closed decision 1 of the phase
    plan: folding the source's standing into the weighted sum would mix the
    evaluation of the source with the measurement of the model's behaviour in
    one number, and that is precisely what principle 2 forbids.

    An unjudgeable grade contributes no factor and the total falls back to the
    raw score, because a missing judgement must not silently act as a penalty.
    The `unjudgeable` flag is what the gate reads; the number is not the
    decision here.
    """
    sources = source_factors if source_factors is not None else SOURCE_FACTORS
    infos = info_factors if info_factors is not None else INFO_FACTORS

    source_factor = sources.get(source_grade)
    info_factor = infos.get(info_grade)
    total = score_raw
    if source_factor is not None:
        total *= source_factor
    if info_factor is not None:
        total *= info_factor

    return GradedScore(
        score_raw=score_raw,
        source_grade=source_grade,
        source_factor=source_factor,
        info_grade=info_grade,
        info_factor=info_factor,
        score_total=total,
        unjudgeable=source_factor is None or info_factor is None,
    )


#: The mechanical reading of a legacy `trust_weight`, highest band first. The
#: same bands migration 0020 applied once; kept here because the seed still
#: carries weights and a new feed needs a grade from somewhere.
_WEIGHT_BANDS = (
    (0.9, SourceGrade.COMPLETELY_RELIABLE),
    (0.8, SourceGrade.USUALLY_RELIABLE),
    (0.6, SourceGrade.FAIRLY_RELIABLE),
    (0.4, SourceGrade.NOT_USUALLY_RELIABLE),
)


def grade_for_weight(weight: float | None) -> SourceGrade:
    """A grade from a legacy weight, for seeding a feed nobody has assessed yet.

    Not reachable to F: a weight is knowledge, however crude, and F means the
    question was never asked. A feed with no weight at all is a different case
    and gets F, which stages its findings until an analyst grades it.
    """
    if weight is None:
        return SourceGrade.CANNOT_BE_JUDGED
    for threshold, grade in _WEIGHT_BANDS:
        if weight >= threshold:
            return grade
    return SourceGrade.UNRELIABLE


def set_source_grade(
    session: Session,
    source: ArticleSource,
    grade: SourceGrade,
    *,
    actor_name: str,
    actor_id: int | None = None,
    note: str | None = None,
) -> AdminAudit:
    """Change a feed's grade and record who changed it, from what, to what.

    The grade is the one number in this system a person is meant to set by
    hand, which makes it the one that most needs a trail. Before this it was a
    literal in `seeds.py` that `seed_article_sources` skipped for existing rows,
    so changing it meant SQL at a console and left nothing behind.

    Written to `admin_audit` rather than `ai_enrichment_audit`: this is a person
    changing configuration, not a model changing data, and mixing the two would
    put a human decision into the statistics that measure model behaviour. The
    same reasoning keeps `audit.py`'s TLP overrides out of Phase 5's numbers.

    The caller commits. A grade change that matters usually accompanies other
    work, and splitting the transaction would let the audit row survive a
    rollback of the change it describes.
    """
    before = source.reliability_grade
    source.reliability_grade = grade.value
    entry = AdminAudit(
        actor_id=actor_id,
        actor_name=actor_name,
        action="source_grade",
        target=source.name[:128],
        detail=f"{before} -> {grade.value}" + (f": {note}" if note else ""),
    )
    session.add(entry)
    return entry


def corroboration_for_ioc(session: Session, article_id: int, value: str) -> Corroboration:
    """How many other feeds have reported this indicator.

    Counts distinct `article_sources`, excluding this article's own feed, so a
    feed repeating itself never confirms itself. Indicators are exact strings
    after canonicalisation, so equality is the right comparison here; techniques
    need their own function because their identity is the ATT&CK id.
    """
    own_source = session.scalar(select(Article.source_id).where(Article.id == article_id))
    others = session.scalar(
        select(func.count(func.distinct(Article.source_id)))
        .select_from(ArticleIoc)
        .join(Article, Article.id == ArticleIoc.article_id)
        .where(
            ArticleIoc.value == value,
            ArticleIoc.article_id != article_id,
            Article.source_id.isnot(None),
            Article.source_id != own_source,
        )
    )
    return Corroboration(independent_sources=int(others or 0))


def corroboration_for_ttp(session: Session, article_id: int, technique_id: str) -> Corroboration:
    """How many other feeds have mapped this technique to their own reporting.

    Weaker confirmation than an indicator's and it should be read that way: two
    feeds naming T1059 are not necessarily describing the same activity. It is
    still the predicate the 6x6 asks for, and the alternative is grading every
    technique 3 forever.
    """
    own_source = session.scalar(select(Article.source_id).where(Article.id == article_id))
    others = session.scalar(
        select(func.count(func.distinct(Article.source_id)))
        .select_from(ArticleTtp)
        .join(Article, Article.id == ArticleTtp.article_id)
        .where(
            ArticleTtp.technique_id == technique_id,
            ArticleTtp.article_id != article_id,
            Article.source_id.isnot(None),
            Article.source_id != own_source,
        )
    )
    return Corroboration(independent_sources=int(others or 0))
