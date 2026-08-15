# "I'm a consultant. The police don't hire me." — Sherlock, Elementary
"""The eight versioned prompts, one per state of the extraction pipeline.

The version lives in the module name and in the prompt text, and is written to
`ArticleAnalysisRun.prompt_version` on every run: comparing two runs from
different weeks means nothing unless the prompt each used can be named. A change
to a prompt's wording is a new file — `triage_v2.py` — not an edit, because an
edit silently rewrites the history of every run that cited the old version.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from pydantic import BaseModel

from pestilentia.ai.prompts import (
    adversary_sketch_v3,
    classify_v1,
    diamond_model_v1,
    extract_ioc_v1,
    map_ttp_v1,
    narrative_v2,
    triage_v1,
    verify_v1,
)
from pestilentia.ai.prompts.base import ArticleContext, Prompt, RenderedPrompt

PROMPTS: dict[str, Prompt] = {
    prompt.state: prompt
    for prompt in (
        triage_v1.PROMPT,
        classify_v1.PROMPT,
        extract_ioc_v1.PROMPT,
        map_ttp_v1.PROMPT,
        diamond_model_v1.PROMPT,
        narrative_v2.PROMPT,
        adversary_sketch_v3.PROMPT,
        verify_v1.PROMPT,
    )
}


def render(
    state: str,
    article: ArticleContext,
    prior: Mapping[str, BaseModel] | None = None,
    known_adversaries: Sequence[str] | None = None,
) -> RenderedPrompt:
    """The prompt for `state`, ready to hand to a provider.

    Raises KeyError for a state with no prompt — the runner iterates
    `STATE_ORDER`, so a missing prompt is a wiring error and must not be
    answered with a silently generic one.
    """
    return PROMPTS[state].render(article, prior, known_adversaries)


__all__ = ["PROMPTS", "ArticleContext", "Prompt", "RenderedPrompt", "render"]
