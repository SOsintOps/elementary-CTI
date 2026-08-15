# "I never make exceptions. An exception disproves the rule." — Sherlock Holmes
"""AdversarySketch v3 — every name gets asked what it is.

v2 returned a flat list of names and left the relationship between them to
whoever read it. Whoever read it was the gate, and it guessed: it proposed every
name in an article as an alias of every other, so `MOIS`, `IRGC Intelligence
Organization` and `Handala Hack Team` became aliases of one another. Two are
state organs and the third is a front.

The minimum fix was to stop guessing, and it landed first. This is the real one:
ask. Each name now carries whether it matches something the database already
holds, whether it is a synonym of another name in the same article, and if not,
what the link actually is. Between "the same" and "unrelated" lies almost
everything that matters in this domain, and a flat list had nowhere to put it.

The known adversary names are supplied as data, so question one is answered
against the record rather than against the model's recollection. Names only: no
ids reach the model and the deterministic resolver still does the resolving,
which is roadmap criterion 3 intact.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import (
    ACH,
    ACTOR_IDENTITY,
    ATTRIBUTION,
    DATA_RULES,
    FENCE,
    GLOSSARY,
    HOUSE_STYLE,
    ICD_203,
    Prompt,
    system_prompt,
)

VERSION = "adversary_sketch_v3"

_SHAPE = """\
## What each field is

- `attribution_level` — how far this article's evidence reaches. Default tactical.
- `cluster_summary` — what can be said about whoever ran this activity: tooling, \
tradecraft, targeting, how they got in, how they monetise. Its first sentence \
carries the rest. Describe the actor through what they did, naming the \
techniques rather than gesturing at them, and say where the article stops \
telling you.
- `named_actors` — one entry per name the article gives, verbatim, each with its \
three answers. An empty list is a normal result, and a group the article names \
only as a comparison does not belong here at all.
- `likelihood` and `confidence` — how probable the association is, and how good \
your basis is. Two scales, never mixed.
- `shared_infrastructure_note` — operator, affiliate or broker: which one does the \
evidence reach, and why?
- `false_flag_note` — what deception you considered and how you resolved it."""

_TASK = """\
Sketch the actor behind this activity from the article's own evidence, and be \
explicit about how far that evidence reaches. For every name you return, answer \
the three identity questions in the schema. Your earlier findings are below."""

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
        ACTOR_IDENTITY,
        HOUSE_STYLE,
        _SHAPE,
    ),
    task=_TASK,
    max_output_tokens=4000,
    requires=("extract_ioc", "map_ttp", "diamond_model"),
    wants_known_adversaries=True,
)
