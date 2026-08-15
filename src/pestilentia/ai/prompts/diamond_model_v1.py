# "The world is full of obvious things which nobody by any chance ever observes." — Sherlock Holmes
"""DiamondModel — four vertices, each standing on its own evidence.

The classic failure is derivation: the infrastructure is known, a group is known
to use that infrastructure, therefore the adversary vertex is filled in. In
ransomware that inference is not merely weak, it is usually wrong — the same
hosting, the same encryptor and the same leak site are shared between an
operator and every affiliate it licenses.

Hence a schema where a vertex is nullable and each carries its own label and
quote: the empty vertex is a supported answer, and the prompt has to say so
plainly or the model will fill it anyway.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import (
    DATA_RULES,
    DIAMOND,
    FENCE,
    GLOSSARY,
    Prompt,
    system_prompt,
)

VERSION = "diamond_model_v1"

_TASK = """\
Build the Diamond Model for the activity this article reports. Fill only the \
vertices the article supports; return null for the others.

Your earlier indicator and technique findings are given below as context. They \
are grounded in this article, so you may reason from them — but each vertex \
still needs its own evidence, and an indicator alone tells you about \
infrastructure, not about who was operating it."""

PROMPT = Prompt(
    state="diamond_model",
    version=VERSION,
    system=system_prompt("diamond_model", VERSION, DATA_RULES, FENCE, GLOSSARY, DIAMOND),
    task=_TASK,
    max_output_tokens=2500,
    requires=("extract_ioc", "map_ttp"),
)
