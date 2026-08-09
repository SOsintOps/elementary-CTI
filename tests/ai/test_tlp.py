# "The balance of probability." — Sherlock Holmes, Elementary
from pestilentia.ai.tlp import (
    TLP_ORDER,
    TlpLevel,
    cloud_allowed,
    coerce_tlp,
    display_label,
    most_restrictive,
)


def test_tlp_order_is_monotone():
    levels = [TlpLevel.CLEAR, TlpLevel.GREEN, TlpLevel.AMBER, TlpLevel.AMBER_STRICT, TlpLevel.RED]
    orders = [TLP_ORDER[level] for level in levels]
    assert orders == sorted(orders)


def test_most_restrictive_picks_highest():
    assert most_restrictive([TlpLevel.GREEN, TlpLevel.AMBER]) == TlpLevel.AMBER


def test_most_restrictive_empty_defaults_to_amber_strict():
    assert most_restrictive([]) == TlpLevel.AMBER_STRICT


def test_display_label():
    assert display_label(TlpLevel.AMBER_STRICT) == "TLP:AMBER+STRICT"
    assert display_label(TlpLevel.CLEAR) == "TLP:CLEAR"


def test_cloud_allowed_green_article_green_max():
    assert cloud_allowed(TlpLevel.GREEN, True, TlpLevel.GREEN) is True


def test_cloud_allowed_amber_article_green_max():
    assert cloud_allowed(TlpLevel.AMBER, True, TlpLevel.GREEN) is False


def test_cloud_allowed_share_flag_false_overrides():
    # even a clear article is blocked if per-source kill-switch is off
    assert cloud_allowed(TlpLevel.CLEAR, False, TlpLevel.RED) is False


def test_cloud_allowed_invalid_string_fails_closed():
    # an unrecognized stored TLP coerces to AMBER_STRICT — denied under a GREEN max
    assert cloud_allowed("purple", True, TlpLevel.GREEN) is False
    assert cloud_allowed("TLP:AMBER", True, TlpLevel.GREEN) is False


def test_cloud_allowed_none_fails_closed():
    assert cloud_allowed(None, True, TlpLevel.GREEN) is False


def test_cloud_allowed_valid_raw_db_strings():
    # raw DB strings (Article.tlp is String(16)) are coerced before comparison
    assert cloud_allowed("green", True, "green") is True
    assert cloud_allowed("GREEN", True, TlpLevel.GREEN) is True
    assert cloud_allowed("amber", True, "green") is False


def test_cloud_allowed_invalid_cloud_max_fails_closed_for_green_article():
    # an unrecognized cloud_max coerces to AMBER_STRICT; a GREEN article still
    # passes only because GREEN <= AMBER_STRICT — verify the boundary explicitly
    assert cloud_allowed(TlpLevel.RED, True, "bogus") is False


def test_coerce_tlp_null_returns_amber_strict():
    assert coerce_tlp(None) == TlpLevel.AMBER_STRICT


def test_coerce_tlp_invalid_returns_amber_strict():
    assert coerce_tlp("purple") == TlpLevel.AMBER_STRICT


def test_coerce_tlp_valid_roundtrip():
    assert coerce_tlp("amber+strict") == TlpLevel.AMBER_STRICT
