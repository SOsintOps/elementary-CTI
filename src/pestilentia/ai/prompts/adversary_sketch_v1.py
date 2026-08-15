# "I never make exceptions. An exception disproves the rule." — Sherlock Holmes
"""AdversarySketch — describe the actor; never name it in our database.

Resolution to a `Group` row is deterministic and belongs to Phase 5 (ADR-006 §3),
so `named_actors` holds names exactly as the article states them and nothing
here chooses an id. The prompt's real work is holding the default at tactical
attribution against a corpus that hands out group names freely.

The two caveat fields are required for a reason particular to this domain. In
ransomware the operator/affiliate/broker distinction is the normal case, not an
edge case, and a sketch that never asked which one the evidence reaches is the
one most likely to be confidently wrong.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import (
    ACH,
    ATTRIBUTION,
    DATA_RULES,
    FENCE,
    GLOSSARY,
    ICD_203,
    Prompt,
    system_prompt,
)

VERSION = "adversary_sketch_v1"

_SHAPE = """\
## What each field is

- `attribution_level` — how far this article's evidence reaches. Default tactical.
- `cluster_summary` — what can be said about whoever ran this activity: tooling, \
tradecraft, targeting, how they got in, how they monetise. Describe the actor \
through what they did, and say where the article stops telling you.
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
        "adversary_sketch", VERSION, DATA_RULES, FENCE, ICD_203, GLOSSARY, ATTRIBUTION, ACH, _SHAPE
    ),
    task=_TASK,
    max_output_tokens=3000,
    requires=("extract_ioc", "map_ttp", "diamond_model"),
)
