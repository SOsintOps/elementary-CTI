# "When you have eliminated the impossible, whatever remains must be the truth." — Sherlock Holmes
"""Verify — a second reader whose only job is to catch the first one out.

Adapted from `the-italian-job`'s AUDIT_SYSTEM_PROMPT, which contributed the part
this plan was missing: not a vague "check the work" but an auditor with three
labels, of which the third — **unverified** — is the one that earns its keep. A
claim traceable to nothing at all is the failure mode that fluent output hides,
and it is invisible to a scheme that only asks observed-or-inferred.

Run this on a different model family from the generator; a model auditing itself
grades its own homework. The evidence-quality rating is computed from the labels
in `VerifyOutput`, never returned by the model — this is the one state whose
purpose is to catch a mistake, so it is the last place to hand the model a score
to report about its own work.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import (
    ACH,
    DATA_RULES,
    FENCE,
    GLOSSARY,
    Prompt,
    system_prompt,
)

VERSION = "verify_v1"

_AUDIT = """\
## The audit

You are auditing an analysis of the article below, produced by another model. \
You did not write it and you are not defending it.

**The claims you label are the ones in `<prior_analysis>`, and only those.** The \
article is the evidence you check them against — it is not the material under \
audit. A fact the article states and the analysis never claims is not yours to \
label, and labelling it `observed` is trivially true and tells nobody anything. \
If you find yourself restating the article, you are auditing the wrong document.

Break it into individual claims — one statement each, in the words it used, \
trimmed to what is being asserted — and label each one.

**Aim for the ten to twenty claims that carry the analysis.** Audit what it \
*asserts*, not every sentence it contains: combine near-duplicates, and do not \
re-audit the indicator and technique lists item by item, since those are already \
checked against the article mechanically. An audit of forty restatements of the \
same three claims hides the one claim that matters.

The labels:

- **observed** — the article states it. You could point at the sentence.
- **inferred** — it follows from what the article states. The reasoning holds \
even if the conclusion is arguable; say in `justification` what it rests on.
- **unverified** — neither. The article does not state it and it does not follow: \
a detail from elsewhere, an inference with a step missing, or a plausible \
sentence with nothing under it. Say in `justification` what is missing.

Rules:
- Audit every substantive claim, including ones you agree with. A claim omitted \
is a claim passed.
- The article is the only source. Something you know to be true that the article \
does not support is **unverified** — being right about the world is not the same \
as being supported by this document.
- Do not rewrite, improve or soften the claims. Quote and label them.
- Do not rate the analysis overall. The rating is derived from your labels, and \
supplying one would let a summary judgement paper over an unverified claim."""

_TASK = """\
Audit the analysis in `<prior_analysis>` at the end of this message. Every claim \
you label must be one *that analysis* makes; the article is there so you can \
check them, and the analysis is the last thing you will read for that reason."""

PROMPT = Prompt(
    state="verify",
    version=VERSION,
    system=system_prompt("verify", VERSION, DATA_RULES, _AUDIT, FENCE, GLOSSARY, ACH),
    task=_TASK,
    # 6000, with the work bounded in the prompt rather than here. Measured:
    # the generator auditing itself closed in 708 tokens; the independent judge
    # overran 4000 three times, and raising the ceiling to 8000 only traded a
    # truncation for a five-minute read timeout. The fix was not a bigger
    # number — it was telling the auditor how much work the job is.
    max_output_tokens=6000,
    requires=("diamond_model", "narrative", "adversary_sketch"),
)
