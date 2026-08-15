# "There is nothing like first-hand evidence." — Sherlock Holmes
"""Classify — what kind of document this is, which sets what can be asked of it.

The type is not a label for its own sake: an IOC dump has no narrative to write
and an advisory has no victim to identify, so the states downstream read this to
know what the article can honestly support.

`disinformation` is a type rather than a rejection. A fabricated claim of a
breach is a fact about the claimant, and this platform tracks claimants.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import DATA_RULES, Prompt, system_prompt

VERSION = "classify_v1"

_TYPES = """\
## The types

- **incident_report** — an intrusion that happened, told as a case: victim or \
sector, timeline, what the intruder did.
- **advisory** — guidance issued by a vendor, CERT or agency: what to look for, \
what to patch, what to do. Written to be acted on rather than read as a story.
- **blog** — research, analysis or commentary. Malware reversing, group profiles, \
trend pieces, quarterly reviews.
- **ioc_dump** — predominantly a list of indicators with little narrative around it.
- **disinformation** — a claim the article itself gives reason to doubt: an \
extortion claim contradicted by the named victim, a recycled leak presented as \
new, a group taking credit for someone else's incident.

Pick the one the article mostly is. A research blog that ends with an indicator \
table is a blog; a table with three sentences of preamble is an ioc_dump.

`evidence_quote` is a verbatim stretch of the body that shows the type — the \
sentence that made the decision, not a summary of the article. Copy it exactly."""

_TASK = """\
Classify the article below, state your confidence, and quote the sentence that \
settles it."""

PROMPT = Prompt(
    state="classify",
    version=VERSION,
    system=system_prompt("classify", VERSION, DATA_RULES, _TYPES),
    task=_TASK,
    max_output_tokens=500,
)
