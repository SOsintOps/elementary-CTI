# "When you have eliminated the impossible…" — Sherlock Holmes, Elementary
"""Upstream API contract fingerprinting for the weekly sentinel.

The in-app health monitor answers "is the source up and roughly the right
size?". This module answers the question that check cannot: **has the shape of
the data changed?** A renamed field or a type change sails through a row-count
check and only surfaces when ingestion breaks; a fingerprint catches it while
it is still just a diff.

A fingerprint is the *type structure* of a sample, values discarded:

    {"name": "akira", "victims": 3, "tags": ["a"]}
        -> {"name": "str", "victims": "number", "tags": ["str"]}

Keys are sorted and every element of a list is folded into one structure, so
the same contract always yields the same fingerprint however the server ordered
its keys or its rows.

Three kinds of observation are not claims about a type, and all three match
anything on the other side of a diff:

- `null` — the value was absent
- `empty` — an empty string, list or object: nothing to learn from
- `varies` — the upstream types this field two different ways, so there is no
  contract here to check

That last one is why the fingerprint merges every record rather than trusting
one. ransomware.live returns `infostealer` as an object for victims it has data
on and as `""` for the rest, and `claim_gang` as a string or as `False`, both
interleaved within a single page: whichever record sorted first decided the
committed contract, and the sentinel went red on the weeks the other kind won.
Merging is what makes this stable — a merged fingerprint changes when the
upstream's consistency changes, not when the draw does. A sentinel red on
alternate weeks stops being read, which is the one failure mode it cannot
survive.

Merging also distinguishes records from maps. `{"Lumma": 3, "Vidar": 1}` is not
an object with a Lumma field; its keys are data, and pinning them would report
the next infostealer family as drift. A dict whose keys move from record to
record while its values keep one type is recorded as `{"*": "int"}` — names
unconstrained, value type still under contract.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE_DIR = _REPO_ROOT / "contracts"
REPORT_DIR = _REPO_ROOT / ".reports" / "api-drift"

#: Fingerprint tokens that are not claims about a type. `null` and `empty` say
#: nothing was observed (absent value; empty string, list or object); `varies`
#: says the upstream itself is not consistent, so there is no type to check.
#: All three match anything on either side of a diff.
NULL = "null"
EMPTY = "empty"
VARIES = "varies"
_WILDCARDS = frozenset({NULL, EMPTY, VARIES})

#: `null` and `empty` yield to anything informative when merged; `varies` wins
#: over everything, because a conflict once seen stays seen.
_UNOBSERVED = frozenset({NULL, EMPTY})

#: The single key standing for "any key" in a dict whose keys are data rather
#: than schema — `{"*": "number"}` reads as: names unconstrained, values numeric.
MAP_KEY = "*"

#: JSON has one number type; Python's parser has two. The fingerprint follows
#: JSON, so a whole-dollar amount written without a decimal point is not drift.
NUMBER = "number"


def fingerprint(value: Any, _depth: int = 0) -> Any:
    """Reduce a sample to its type structure.

    Depth-capped: a pathological or adversarial payload (these are external
    APIs) must not recurse us to death. Beyond the cap the structure is
    summarised, which still changes if the upstream changes shape there.
    """
    if _depth > 8:
        return "…"
    if isinstance(value, (str, list, dict)) and not value:
        # An empty string, list or object carries no information about the
        # shape it would have when populated — so it must not be allowed to
        # assert one. Upstreams pick their own sentinel for "no data here":
        # ransomware.live returns "" for victims with no infostealer record
        # and a nine-key object for those that have one, interleaved within
        # a single page. Fingerprinting "" as `str` would make the contract
        # depend on which victim happened to be drawn first, and a sentinel
        # that is red half the weeks reports nothing at all.
        return EMPTY
    if isinstance(value, dict):
        return {key: fingerprint(sub, _depth + 1) for key, sub in sorted(value.items())}
    if isinstance(value, list):
        # Every element is folded in, not just the first. A single element
        # cannot tell a stable contract from a field the upstream types two
        # different ways, and guessing from element [0] is how the sentinel
        # spent three days red over ransomware.live's `infostealer`.
        return [_merge_all(fingerprint(item, _depth + 1) for item in value)]
    if value is None:
        # Nullable fields flap between null and a value from sample to sample.
        # Treating null as its own type would make the fingerprint depend on
        # the record drawn, so it is recorded as unknown-compatible.
        return NULL
    if isinstance(value, bool):
        return "bool"  # before the numeric test: isinstance(True, int) is True
    if isinstance(value, (int, float)):
        # JSON has one number type. Python's parser splits it in two on the
        # presence of a decimal point, so ransomwhe.re's amountUSD arrives as
        # a float 21,787 times and an int 15 times — for the fifteen whole-
        # dollar amounts. That is a punctuation detail, not a contract, and
        # calling it a conflict would blind the field the sentinel's own drill
        # named as its silent failure mode.
        return NUMBER
    return type(value).__name__


def _is_token(structure: Any, tokens: frozenset[str]) -> bool:
    """A fingerprint may be a dict or a list, neither of which is hashable —
    so the membership test must be reached only for the scalar tokens."""
    return isinstance(structure, str) and structure in tokens


def _is_unobserved(structure: Any) -> bool:
    return _is_token(structure, _UNOBSERVED)


def _is_map(structure: Any) -> bool:
    return isinstance(structure, dict) and set(structure) == {MAP_KEY}


def _as_map(left: dict, right: dict) -> dict | None:
    """Read two dicts as one map, or decline.

    Some objects are records — a fixed set of named fields — and some are maps
    whose keys are data. `infostealer_stats` counts sightings per infostealer
    family, so its keys are family names: pinning them would turn the arrival
    of a new family into reported drift. The tell is that the keys differ from
    record to record while the values are all of one type.

    A record with an optional field also has differing keys, but its values
    are a mix of types, so it does not qualify. One that is *not* a mix will
    be read as a map — trading the check on its field names for the check on
    their type, which is the conservative direction: a false alarm every week
    is more expensive than a name left unwatched.
    """
    settled = _is_map(left) or _is_map(right)
    if not (settled or left.keys() != right.keys()):
        return None
    values = _merge_all([*left.values(), *right.values()])
    if values == VARIES and not settled:
        return None  # keys move *and* types conflict: a record, badly behaved
    # Once read as a map it stays one, even if a later record makes the value
    # type conflict — a shape already seen is not unseen by the next record.
    return {MAP_KEY: values}


def merge_fingerprints(left: Any, right: Any) -> Any:
    """Combine two fingerprints of the same thing into what is known about it.

    Agreement keeps the type. A side that observed nothing (`null`, `empty`)
    yields to the side that did. Anything else in conflict — two scalar types,
    a scalar against a container, two containers of different kinds — is not a
    contract at all, and says so: `varies`.
    """
    if left == right:
        return left
    if _is_unobserved(left):
        return right
    if _is_unobserved(right):
        return left
    if _is_wildcard(left) or _is_wildcard(right):
        return VARIES  # one side already gave up on this field
    if isinstance(left, dict) and isinstance(right, dict):
        mapping = _as_map(left, right)
        if mapping is not None:
            return mapping
        # A key seen in only some records is still a key that was seen; the
        # week it disappears from all of them is a removal worth reporting.
        return {
            key: merge_fingerprints(left.get(key, EMPTY), right.get(key, EMPTY))
            for key in sorted(left.keys() | right.keys())
        }
    if isinstance(left, list) and isinstance(right, list):
        if not left or not right:
            return left or right
        return [merge_fingerprints(left[0], right[0])]
    return VARIES


def _merge_all(structures: Iterable[Any]) -> Any:
    merged: Any = EMPTY
    for structure in structures:
        merged = merge_fingerprints(merged, structure)
    return merged


def _is_wildcard(structure: Any) -> bool:
    return _is_token(structure, _WILDCARDS)


def diff_structures(baseline: Any, observed: Any, path: str = "$") -> list[str]:
    """Human-readable differences between two fingerprints.

    A `null`, `empty` or `varies` on either side matches anything: a field that
    was absent, unpopulated, or inconsistently typed upstream is part of the
    contract, not drift. The cost is real — such a field stops being checked
    for type changes at all. It buys the property everything else rests on:
    that a red run means something moved.
    """
    if baseline == observed:
        return []
    if _is_wildcard(baseline) or _is_wildcard(observed):
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
            # upstream may simply have had no rows in that window. Since
            # `fingerprint` began reducing empty lists to EMPTY this can only
            # be reached from a baseline committed before that change; it is
            # kept so an un-updated checkout reads as "not observed" rather
            # than going red on its first run.
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
