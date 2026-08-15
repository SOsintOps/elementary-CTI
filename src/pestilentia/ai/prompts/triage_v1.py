# "Eliminate all other factors, and the one which remains must be the truth." — Sherlock Holmes
"""Triage — the state that decides whether any of the others are worth paying for.

Runs on the cheap tier before a single analysis-tier token is spent (ADR-006 §2),
so it is deliberately the shortest prompt in the set: no tradecraft blocks, no
glossary, one question. Everything added here is paid on every article the
platform ingests, relevant or not.

The bias is stated explicitly and it is towards keeping. A false negative is
silent — the article is dropped and nobody ever sees what was in it — while a
false positive costs one analysis run and is visible in the output.
"""

from __future__ import annotations

from pestilentia.ai.prompts.base import DATA_RULES, Prompt, system_prompt

VERSION = "triage_v1"

_SCOPE = """\
## What this platform is for

Elementary CTI tracks ransomware and data-extortion activity: the groups, their \
affiliates, their tooling and infrastructure, the intrusions they run and the \
organisations they hit.

Relevant:
- Incidents, intrusions and campaigns involving ransomware or extortion.
- Research on the groups, their affiliates, brokers who sell them access, or the \
malware they deploy.
- Advisories about activity these groups are known to conduct — exploited edge \
devices, abused remote access, the initial access they buy.
- Law enforcement action, leak-site activity, negotiation and payment reporting.
- Disinformation or fabricated claims about any of the above: knowing a claim is \
false is intelligence about the claimant.

Not relevant:
- General security news with no extortion angle: patch roundups, breach \
notifications with no actor, privacy or policy commentary.
- Espionage or hacktivism with no extortion component.
- Vendor marketing, product announcements, conference write-ups, opinion pieces.
- Articles that only mention ransomware in passing as background.

When it is genuinely borderline, mark it relevant. Dropping it here is silent and \
final; keeping it costs one analysis and shows up in the output where a reader \
can see it."""

_TASK = """\
Decide whether this article is worth analysing, and say what decided it in **one \
sentence of at most forty words** — a summary of the article is not what is being \
asked for. Judge only the article below."""

PROMPT = Prompt(
    state="triage",
    version=VERSION,
    system=system_prompt("triage", VERSION, DATA_RULES, _SCOPE),
    task=_TASK,
    max_output_tokens=300,
)
