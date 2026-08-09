# "When you have eliminated the impossible…" — Sherlock Holmes, Elementary
"""Upstream API contract fingerprinting for the weekly sentinel.

The in-app health monitor answers "is the source up and roughly the right
size?". This module answers the question that check cannot: **has the shape of
the data changed?** A renamed field or a type change sails through a row-count
check and only surfaces when ingestion breaks; a fingerprint catches it while
it is still just a diff.

A fingerprint is the *type structure* of a sample, values discarded:

    {"name": "akira", "victims": 3, "tags": ["a"]}
        -> {"name": "str", "victims": "int", "tags": ["str"]}

Keys are sorted, list structure is taken from the first element, and unions of
observed scalar types are collapsed deterministically — so the same contract
always yields the same fingerprint regardless of which record was sampled or
how the server ordered its keys.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE_DIR = _REPO_ROOT / "contracts"
REPORT_DIR = _REPO_ROOT / ".reports" / "api-drift"


def fingerprint(value: Any, _depth: int = 0) -> Any:
    """Reduce a sample to its type structure.

    Depth-capped: a pathological or adversarial payload (these are external
    APIs) must not recurse us to death. Beyond the cap the structure is
    summarised, which still changes if the upstream changes shape there.
    """
    if _depth > 8:
        return "…"
    if isinstance(value, dict):
        return {key: fingerprint(sub, _depth + 1) for key, sub in sorted(value.items())}
    if isinstance(value, list):
        # The first element stands for the list. Mixed-type lists exist in the
        # wild, but sampling every element makes the fingerprint depend on
        # which records happened to be present — exactly the instability a
        # contract check cannot afford.
        return [fingerprint(value[0], _depth + 1)] if value else []
    if value is None:
        # Nullable fields flap between null and a value from sample to sample.
        # Treating null as its own type would make the fingerprint depend on
        # the record drawn, so it is recorded as unknown-compatible.
        return "null"
    return type(value).__name__


def diff_structures(baseline: Any, observed: Any, path: str = "$") -> list[str]:
    """Human-readable differences between two fingerprints.

    A `null` on either side matches anything: nullable fields are part of the
    contract, not drift.
    """
    if baseline == observed:
        return []
    if baseline == "null" or observed == "null":
        return []
    if isinstance(baseline, dict) and isinstance(observed, dict):
        problems: list[str] = []
        for key in sorted(baseline.keys() | observed.keys()):
            if key not in observed:
                problems.append(f"{path}.{key}: field removed")
            elif key not in baseline:
                problems.append(f"{path}.{key}: new field (type {observed[key]!r})")
            else:
                problems.extend(diff_structures(baseline[key], observed[key], f"{path}.{key}"))
        return problems
    if isinstance(baseline, list) and isinstance(observed, list):
        if not baseline or not observed:
            # An empty sample proves nothing about element shape — the
            # upstream may simply have had no rows in that window.
            return []
        return diff_structures(baseline[0], observed[0], f"{path}[0]")
    return [f"{path}: type changed {baseline!r} -> {observed!r}"]


@dataclass(frozen=True)
class ContractResult:
    name: str
    ok: bool
    #: "alive+match" | "drift" | "unreachable" | "no-baseline"
    status: str
    problems: list[str]

    def as_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "status": self.status, "problems": self.problems}


def baseline_path(name: str) -> Path:
    return BASELINE_DIR / f"{name}.json"


def load_baseline(name: str) -> Any | None:
    path = baseline_path(name)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_baseline(name: str, structure: Any) -> Path:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    path = baseline_path(name)
    path.write_text(json.dumps(structure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def check_sample(name: str, sample: Any) -> ContractResult:
    """Compare one live sample against its committed baseline."""
    observed = fingerprint(sample)
    baseline = load_baseline(name)
    if baseline is None:
        return ContractResult(
            name,
            ok=False,
            status="no-baseline",
            problems=[f"no committed baseline at {baseline_path(name)}; run with --update"],
        )
    problems = diff_structures(baseline, observed)
    if problems:
        return ContractResult(name, ok=False, status="drift", problems=problems)
    return ContractResult(name, ok=True, status="alive+match", problems=[])
