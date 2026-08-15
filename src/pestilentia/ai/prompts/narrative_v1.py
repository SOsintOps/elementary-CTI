# "The little things are infinitely the most important." — Sherlock Holmes
"""Narrative — the judgement first, then what supports it, then what to do.

This is the state whose output a human actually reads, which makes it the state
where a fluent invention does the most damage. It runs last among the generative
states so that everything it says can rest on findings already grounded in the
article, and it is audited afterwards by `Verify` on a different model family.

ICD 203 is load-bearing here rather than decorative: the key judgement is stated
as a judgement, with a confidence that means something, and the recommendations
are what this article supports doing — not a checklist any ransomware article
would produce.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import (
    DATA_RULES,
    FENCE,
    GLOSSARY,
    ICD_203,
    Prompt,
    system_prompt,
)

VERSION = "narrative_v1"

_SHAPE = """\
## What each field is

- `key_judgement` — one or two sentences: the thing a reader must take away. \
Stated as an assessment, in the ICD 203 vocabulary. Not a summary of the article \
and not its headline.
- `confidence` — your confidence in that judgement, given how much of it the \
article actually establishes.
- `summary_md` — short markdown. What happened, how the intrusion ran, what is \
known about the actor and the victim, and — explicitly — what the article leaves \
open. Reporting gaps are part of the assessment.
- `recommendations_md` — what a defender should do *because of this article*: the \
exposure it points at, the detection its behaviours enable, the indicator worth \
hunting. If the article supports none, leave it empty. Generic hygiene advice \
that would fit any ransomware article is noise, and noise here is worse than \
silence because it is indistinguishable from advice that was earned."""

_TASK = """\
Write the assessment of this article for another analyst. Your earlier findings \
are below and are grounded in the article; the article itself remains the source."""

PROMPT = Prompt(
    state="narrative",
    version=VERSION,
    system=system_prompt("narrative", VERSION, DATA_RULES, FENCE, ICD_203, GLOSSARY, _SHAPE),
    task=_TASK,
    max_output_tokens=4000,
    requires=("classify", "extract_ioc", "map_ttp", "diamond_model"),
)
