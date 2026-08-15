# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""ATT&CK technique catalogue — the authority a mapped TTP is checked against.

Phase 4 needs to answer one question about every TTP an LLM proposes: is this
a real, current technique? ADR-006 §3 names `mitreattack-python` for the job.
This module does it from the STIX bundle `clients/mitre_attack.py` already
downloads and caches, because that client also already parses attack-patterns
and honours `revoked`/`x_mitre_deprecated` — adding a dependency that drags in
stix2 and taxii2-client to re-derive what we hold would be paying twice.

The bundle's own numbers (enterprise-attack, verified 2026-08-12): 858
attack-patterns, of which 697 live, 149 revoked and 12 deprecated with no
successor.

Two properties of the real data drive the design:

- **Revocation chains exist.** T1150 was revoked by T1547.011, which was itself
  revoked by T1647. Three such chains are present, so resolution follows the
  pointer until it lands on a live technique; a single hop would hand back a
  revoked id and call it valid.
- **Deprecation is not revocation.** Twelve techniques (T1064, T1153, …) are
  deprecated with no replacement. They resolve to nothing and must be rejected,
  not silently mapped to something plausible.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from pestilentia.clients.mitre_attack import CACHE_PATH, TACTIC_MAP

# A revoked technique pointing at a revoked technique is normal; a cycle is
# not, but a malformed bundle must fail closed rather than spin forever.
_MAX_REVOCATION_HOPS = 10


@dataclass(frozen=True)
class Technique:
    """A live ATT&CK technique. `technique_id` is the ATT&CK id (T1486),
    not the STIX id."""

    technique_id: str
    name: str
    tactics: tuple[tuple[str, str], ...]  # (tactic_id, tactic_name)


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id") or None
    return None


def _tactics(obj: dict) -> tuple[tuple[str, str], ...]:
    found = [
        TACTIC_MAP[phase["phase_name"]]
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name") in TACTIC_MAP
    ]
    return tuple(found)


class AttackCatalog:
    """Lookup from an ATT&CK technique id to the live technique it denotes."""

    def __init__(self, live: dict[str, Technique], superseded: dict[str, str]) -> None:
        self._live = live
        self._superseded = superseded

    # -- construction ----------------------------------------------------

    @classmethod
    def from_bundle(cls, bundle: dict) -> Self:
        patterns = {
            obj["id"]: obj
            for obj in bundle.get("objects", ())
            if obj.get("type") == "attack-pattern" and _attack_id(obj)
        }

        live: dict[str, Technique] = {}
        for obj in patterns.values():
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            attack_id = _attack_id(obj)
            assert attack_id is not None  # filtered above
            live[attack_id] = Technique(
                technique_id=attack_id,
                name=obj.get("name", ""),
                tactics=_tactics(obj),
            )

        # revoked-by relationships also link intrusion-sets and software; only
        # the attack-pattern pairs concern us.
        superseded: dict[str, str] = {}
        for obj in bundle.get("objects", ()):
            if obj.get("type") != "relationship" or obj.get("relationship_type") != "revoked-by":
                continue
            source = patterns.get(obj.get("source_ref"))
            target = patterns.get(obj.get("target_ref"))
            if source is None or target is None:
                continue
            old, new = _attack_id(source), _attack_id(target)
            if old and new and old != new:
                superseded[old] = new

        return cls(live, superseded)

    @classmethod
    def load(cls, path: Path | None = None) -> Self:
        """Build from the bundle `clients/mitre_attack.py` caches.

        Raises FileNotFoundError when the bundle was never fetched: a caller
        must not silently validate TTPs against an empty catalogue, which
        would reject every mapping and look like a model failure.
        """
        source = path or CACHE_PATH
        if not source.exists():
            raise FileNotFoundError(
                f"ATT&CK bundle not cached at {source}. Run the MITRE enrichment "
                "cycle, or call clients.mitre_attack.download_stix_bundle() first."
            )
        return cls.from_bundle(json.loads(source.read_text(encoding="utf-8")))

    # -- lookup ----------------------------------------------------------

    def resolve(self, technique_id: str | None) -> Technique | None:
        """The live technique for `technique_id`, following revocations.

        Returns None for anything that does not denote a current technique:
        an invented id, a deprecated one with no successor, or a revocation
        chain that does not terminate. Callers reject on None — a TTP the
        catalogue cannot vouch for is not evidence.
        """
        if not technique_id:
            return None
        current = technique_id.strip().upper()

        for _ in range(_MAX_REVOCATION_HOPS):
            hit = self._live.get(current)
            if hit is not None:
                return hit
            successor = self._superseded.get(current)
            if successor is None:
                return None
            current = successor
        return None

    def __contains__(self, technique_id: str) -> bool:
        return self.resolve(technique_id) is not None

    def __len__(self) -> int:
        return len(self._live)
