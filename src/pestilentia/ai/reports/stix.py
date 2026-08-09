# "I've been reliably informed that I can be quite disagreeable." — Sherlock, Elementary
"""STIX 2.1 export for adversary profiles.

The plan filed this behind Phase 4 because IOC objects need extraction that
does not exist yet. That is true of *indicators* — but a `Group` with its
ATT&CK techniques and tooling is already a complete, valid STIX story:
intrusion-set, attack-pattern, tool, and the `uses` relationships between
them. That much can be pushed into MISP or OpenCTI today, so it ships now and
gains indicators later.

No new dependency. The `stix2` library validates and round-trips, which is
worth having when *consuming*; emitting a bundle is JSON assembly, and a
dependency on a Raspberry Pi should earn its place.

Identifiers are deterministic UUIDv5 over a namespace plus the object's
natural key, as the specification prescribes for the SCO/SDO "id contributing
properties" pattern. Re-exporting the same group therefore produces the same
ids, so a downstream MISP or OpenCTI updates its objects instead of
accumulating duplicates on every push.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

# The OASIS-registered namespace for deterministic STIX 2.1 identifiers.
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# TLP 2.0 marking definitions are fixed, specification-assigned ids — they are
# not minted per producer.
TLP_MARKINGS = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "amber+strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}


def _det_id(obj_type: str, key: str) -> str:
    return f"{obj_type}--{uuid.uuid5(STIX_NAMESPACE, f'{obj_type}:{key}')}"


def _aliases(raw: str | None) -> list[str]:
    """Aliases are stored as a JSON list, but legacy rows hold a bare scalar.

    Duplicated from the web layer rather than imported: `pestilentia.ai` must
    not depend on `pestilentia.web`, and a layering test enforces it.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else [str(parsed)]


def _ts(value: datetime | None) -> str:
    if value is None:
        value = datetime.now(UTC)
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def group_to_bundle(group, *, tlp: str = "clear", created: datetime | None = None) -> dict:
    """One adversary and everything we can say about it, as a STIX 2.1 bundle.

    A ransomware crew is modelled as an `intrusion-set` rather than a
    `threat-actor`: we track a named set of behaviours and tooling, not
    evidence about the humans behind it. Aliases become the object's
    `aliases` list, which is what a consumer deduplicates on.
    """
    stamp = _ts(created)
    marking = TLP_MARKINGS.get((tlp or "clear").lower(), TLP_MARKINGS["clear"])

    intrusion_id = _det_id("intrusion-set", group.group_name.lower())
    objects: list[dict] = [
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": intrusion_id,
            "created": stamp,
            "modified": stamp,
            "name": group.group_name,
            "description": (group.description or "")[:5000] or None,
            "aliases": _aliases(group.aliases) or None,
            "object_marking_refs": [marking],
        }
    ]

    for ttp in getattr(group, "ttps", []) or []:
        pattern_id = _det_id("attack-pattern", ttp.technique_id)
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": pattern_id,
                "created": stamp,
                "modified": stamp,
                "name": ttp.technique_name,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": ttp.technique_id,
                        "url": "https://attack.mitre.org/techniques/"
                        + ttp.technique_id.replace(".", "/")
                        + "/",
                    }
                ],
                "object_marking_refs": [marking],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _det_id("relationship", f"{intrusion_id}|uses|{pattern_id}"),
                "created": stamp,
                "modified": stamp,
                "relationship_type": "uses",
                "source_ref": intrusion_id,
                "target_ref": pattern_id,
                "object_marking_refs": [marking],
            }
        )

    for tool in getattr(group, "tools", []) or []:
        name = getattr(tool, "tool_name", None) or getattr(tool, "name", None)
        if not name:
            continue
        tool_id = _det_id("tool", name.lower())
        objects.append(
            {
                "type": "tool",
                "spec_version": "2.1",
                "id": tool_id,
                "created": stamp,
                "modified": stamp,
                "name": name,
                "object_marking_refs": [marking],
            }
        )
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": _det_id("relationship", f"{intrusion_id}|uses|{tool_id}"),
                "created": stamp,
                "modified": stamp,
                "relationship_type": "uses",
                "source_ref": intrusion_id,
                "target_ref": tool_id,
                "object_marking_refs": [marking],
            }
        )

    # Drop nulls: STIX forbids a property present with a null value.
    cleaned = [{k: v for k, v in obj.items() if v is not None} for obj in objects]
    # De-duplicate by id — two groups can use the same technique, and a bundle
    # must not carry the same object twice.
    seen: dict[str, dict] = {}
    for obj in cleaned:
        seen.setdefault(obj["id"], obj)

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": list(seen.values()),
    }


def bundle_to_json(bundle: dict) -> str:
    return json.dumps(bundle, indent=2, ensure_ascii=False)
