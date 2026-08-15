# "I'm a consultant. The police don't hire me." — Sherlock, Elementary
"""Confidence: the composite score and the two-axis evaluation on top of it.

Two layers, deliberately not one module. `composite` measures the model's
behaviour on this article; `grading` evaluates the source and the information
separately, per UNODC chapter 4, and applies them as factors. Fusing them would
produce one number that cannot be taken apart again, which is the thing the
method exists to prevent — and which would make recalibration impossible
without re-running the pipeline.
"""

from pestilentia.ai.confidence.composite import (
    CRITIC_SCORES,
    NEUTRAL,
    WEIGHT_ANCHOR,
    WEIGHT_CRITIC,
    WEIGHT_SCHEMA,
    WEIGHT_SELF,
    Components,
    anchor_ratio,
    composite,
    critic_agreement,
    schema_completeness,
)
from pestilentia.ai.confidence.grading import (
    INFO_FACTORS,
    SOURCE_FACTORS,
    Corroboration,
    GradedScore,
    InfoGrade,
    SourceGrade,
    apply_axes,
    corroboration_for_ioc,
    corroboration_for_ttp,
    grade_for_weight,
    info_grade_of,
    set_source_grade,
    source_grade_of,
)

__all__ = [
    "CRITIC_SCORES",
    "INFO_FACTORS",
    "NEUTRAL",
    "SOURCE_FACTORS",
    "WEIGHT_ANCHOR",
    "WEIGHT_CRITIC",
    "WEIGHT_SCHEMA",
    "WEIGHT_SELF",
    "Components",
    "Corroboration",
    "GradedScore",
    "InfoGrade",
    "SourceGrade",
    "anchor_ratio",
    "apply_axes",
    "composite",
    "corroboration_for_ioc",
    "corroboration_for_ttp",
    "critic_agreement",
    "grade_for_weight",
    "info_grade_of",
    "schema_completeness",
    "set_source_grade",
    "source_grade_of",
]
