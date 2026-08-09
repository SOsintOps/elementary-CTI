# "The balance of probability." — Sherlock Holmes, Elementary
from enum import StrEnum


class TlpLevel(StrEnum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"


# Restrictiveness ordering — higher integer = more restrictive
TLP_ORDER: dict[TlpLevel, int] = {
    TlpLevel.CLEAR: 0,
    TlpLevel.GREEN: 1,
    TlpLevel.AMBER: 2,
    TlpLevel.AMBER_STRICT: 3,
    TlpLevel.RED: 4,
}

_VALID_VALUES: set[str] = {level.value for level in TlpLevel}


def most_restrictive(levels: list[TlpLevel]) -> TlpLevel:
    """Return the most restrictive level from a list.

    Returns TlpLevel.AMBER_STRICT (default-deny) if the list is empty.
    """
    return max(levels, key=TLP_ORDER.__getitem__, default=TlpLevel.AMBER_STRICT)


def display_label(level: TlpLevel) -> str:
    """Return the canonical FIRST display label, e.g. 'TLP:AMBER+STRICT'."""
    return f"TLP:{level.value.upper()}"


def cloud_allowed(
    article_tlp: TlpLevel | str | None,
    source_share_flag: bool,
    cloud_max: TlpLevel | str | None,
) -> bool:
    """Return True iff the article may be sent to a cloud LLM provider.

    The per-source kill-switch (share_with_third_party=False) overrides TLP level.
    cloud_max is typically set from PEST_AI_TLP_CLOUD_MAX (default 'green').

    Fail-closed: inputs are coerced via coerce_tlp, so an unrecognized or NULL
    TLP value is treated as AMBER_STRICT (denied under any sane cloud_max).
    """
    if not source_share_flag:
        return False
    return TLP_ORDER[coerce_tlp(article_tlp)] <= TLP_ORDER[coerce_tlp(cloud_max)]


def coerce_tlp(raw: TlpLevel | str | None) -> TlpLevel:
    """Coerce a raw value to TlpLevel; default-deny (AMBER_STRICT) on NULL/invalid."""
    if raw is None or raw.lower() not in _VALID_VALUES:
        return TlpLevel.AMBER_STRICT
    return TlpLevel(raw.lower())
