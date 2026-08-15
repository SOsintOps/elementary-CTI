# "You see, but you do not observe." — Sherlock Holmes
"""ExtractIOC — the model selects; it cannot add.

Whatever this prompt returns is intersected with a regex pre-pass over the
article (`extraction/iocs.py`) and anything the article does not contain is
dropped, however plausible. So the instructions here are aimed at the job that
is actually left: an indicator dump lists hundreds of strings and almost none of
them are the article's point. Choosing is the work.

Two fields exist for one indicator because articles defang. `value` is the clean
form, `value_as_written` is the form on the page (`1.2.3[.]4`), and the anchor
step searches for both — the defanged one is usually the one really there.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import DATA_RULES, PYRAMID, Prompt, system_prompt

VERSION = "extract_ioc_v1"

_VERBATIM = """\
## Copy, do not correct

- `value_as_written` is the indicator exactly as the article writes it, including \
defanging: `1.2.3[.]4`, `hxxps://evil[.]com/a`, `support[at]evil[.]com`. Do not \
clean it up.
- `value` is the same indicator refanged, and nothing else changed. Do not expand \
an abbreviated hash, complete a truncated address or fix an apparent typo — the \
article's version is the evidence.
- `context` is a verbatim sentence from the body that shows what the indicator \
does in this activity. A sentence that is not in the body is discarded and \
replaced with the text around the indicator, so a paraphrase buys nothing.
- Every indicator you return is checked against the article. One that is not \
found there is dropped and counted as an invention, whatever its shape.
- `ioc_type` is your route to the value; the pattern that finds it in the text \
decides what it is stored as. Do not agonise over the boundary between a domain \
and a URL."""

_TASK = """\
Select the indicators that carry this article's meaning, and say for each what \
the article has it doing. Take them from the article below only."""

PROMPT = Prompt(
    state="extract_ioc",
    version=VERSION,
    system=system_prompt("extract_ioc", VERSION, DATA_RULES, PYRAMID, _VERBATIM),
    task=_TASK,
    max_output_tokens=6000,
)
