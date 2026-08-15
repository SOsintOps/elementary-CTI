# "The little things are infinitely the most important." — Sherlock Holmes
"""Narrative v2 — v1 plus the house style, because v1 said what and not how.

v1 told the model which field carried what and left the prose to it. Measured
on real output, the prose went the way unguided prose goes: 78-word sentences,
`and more` in place of the rest of a list, `various techniques` where the
techniques were already extracted and anchored, and a recommendation sitting
inside the summary where it duplicated the field beside it.

The only change from v1 is `HOUSE_STYLE` and a `summary_md` description that
names the bottom-line rule instead of listing contents. A new file rather than
an edit, per the package docstring: an edit would rewrite the history of every
run that cited v1, and v1 is the baseline this is measured against.

Rules and sources: `docs/intelligence-writing-style.md`. Enforcement afterwards:
`ai/style.py`.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import (
    DATA_RULES,
    FENCE,
    GLOSSARY,
    HOUSE_STYLE,
    ICD_203,
    Prompt,
    system_prompt,
)

VERSION = "narrative_v2"

_SHAPE = """\
## What each field is

- `key_judgement` — one or two sentences: the thing a reader must take away. \
Stated as an assessment, in the ICD 203 vocabulary. Not a summary of the article \
and not its headline.
- `confidence` — your confidence in that judgement, given how much of it the \
article actually establishes.
- `summary_md` — short markdown. Its first sentence is the bottom line and \
covers the rest; what follows runs from most important to least: how the \
intrusion ran, who the actor and the victim are, and — explicitly — what the \
article leaves open. Reporting gaps are part of the assessment. No advice of \
any kind: that is the next field, and repeating it here puts it outside the \
paragraph's own bottom line.
- `recommendations_md` — what a defender should do *because of this article*: \
the exposure it points at, the detection its behaviours enable, the indicator \
worth hunting. If the article supports none, leave it empty. Generic hygiene \
advice that would fit any ransomware article is noise, and noise here is worse \
than silence because it is indistinguishable from advice that was earned."""

_TASK = """\
Write the assessment of this article for another analyst. Your earlier findings \
are below and are grounded in the article; the article itself remains the source."""

PROMPT = Prompt(
    state="narrative",
    version=VERSION,
    system=system_prompt(
        "narrative", VERSION, DATA_RULES, FENCE, ICD_203, GLOSSARY, HOUSE_STYLE, _SHAPE
    ),
    task=_TASK,
    max_output_tokens=4000,
    requires=("classify", "extract_ioc", "map_ttp", "diamond_model"),
)
