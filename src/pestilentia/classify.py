# "Education never ends, Watson." — Sherlock Holmes, Elementary
"""Group classification helpers (kept out of the web layer — NI-04)."""

HACKTIVIST_KEYWORDS = frozenset({"not a ransomware", "hacktivist", "data broker", "not ransomware"})


def is_hacktivist_description(description: str | None) -> bool:
    """True when the feed description marks the group as non-ransomware.

    Computed once at ingest time and persisted on ``Group.is_hacktivist``
    (ME-11) instead of re-scanning the description on every page render.
    """
    if not description:
        return False
    desc = description.lower()
    return any(kw in desc for kw in HACKTIVIST_KEYWORDS)
