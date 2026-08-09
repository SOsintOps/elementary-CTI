# "It is a capital mistake to theorize before one has data." — Sherlock Holmes, Elementary
"""Shared helpers for data-source clients."""


def normalize_group_name(name: str) -> str:
    """Normalize a group name for cross-source matching.

    Same normalization on both sides of every lookup: lowercase, no
    surrounding whitespace, separators stripped ("Black Basta" ==
    "black-basta" == "blackbasta").
    """
    return name.lower().strip().replace(" ", "").replace("-", "").replace("_", "")
