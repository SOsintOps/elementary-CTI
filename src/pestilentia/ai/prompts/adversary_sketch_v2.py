# "I never make exceptions. An exception disproves the rule." — Sherlock Holmes
"""AdversarySketch v2 — v1 plus the house style.

Same reasoning as `narrative_v2`: v1 said what each field carried and left the
prose unguided. Three of this state's fields are prose a person reads, and the
one that suffers most from vagueness is `cluster_summary`, where "various
techniques" is available to the model and the extracted techniques are already
sitting in front of it.

A new file rather than an edit, per the package docstring: an edit would
rewrite the history of every run that cited v1.

Rules and sources: `docs/intelligence-writing-style.md`.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import (
    ACH,
    ATTRIBUTION,
    DATA_RULES,
    FENCE,
    GLOSSARY,
    HOUSE_STYLE,
    ICD_203,
    Prompt,
    system_prompt,
)

VERSION = "adversary_sketch_v2"

_SHAPE = """\
## What each field is

- `attribution_level` — how far this article's evidence reaches. Default tactical.
- `cluster_summary` — what can be said about whoever ran this activity: tooling, \
tradecraft, targeting, how they got in, how they monetise. Its first sentence \
carries the rest. Describe the actor through what they did, naming the \
techniques rather than gesturing at them, and say where the article stops \
telling you.
- `named_actors` — names the article gives, verbatim. Empty is a normal answer, \
and a group the article names only as a comparison does not belong here.
- `likelihood` and `confidence` — how probable the association is, and how good \
your basis is. Two scales, never mixed.
- `shared_infrastructure_note` — operator, affiliate or broker: which one does the \
evidence reach, and why?
- `false_flag_note` — what deception you considered and how you resolved it."""

_TASK = """\
Sketch the actor behind this activity from the article's own evidence, and be \
explicit about how far that evidence reaches. Your earlier findings are below."""

PROMPT = Prompt(
    state="adversary_sketch",
    version=VERSION,
    system=system_prompt(
        "adversary_sketch",
        VERSION,
        DATA_RULES,
        FENCE,
        ICD_203,
        GLOSSARY,
        ATTRIBUTION,
        ACH,
        HOUSE_STYLE,
        _SHAPE,
    ),
    task=_TASK,
    max_output_tokens=3000,
    requires=("extract_ioc", "map_ttp", "diamond_model"),
)
