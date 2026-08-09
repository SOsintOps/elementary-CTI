"""G0: the Pyramid of Pain uses a sequential ramp, not a categorical rainbow.

Pain is an ordered scale, so its colour job is sequential — one hue, monotonic
in luminance. The previous six-family rainbow failed CVD separation (adjacent
bands at deutan ΔE 0.5 on the dark surface). These tests pin the encoding so a
future edit cannot quietly reintroduce a rainbow.
"""

import re
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parents[1] / "src/pestilentia/web/templates/group_detail.html"

# Light surface #ffffff, dark card #1a2433 (UI-SPEC §2 / base.html noir.card).
RAMP_LIGHT = ["#0d52bf", "#3689e6", "#64baff", "#8cd5ff", "#c6e2ff", "#e8f3ff"]
RAMP_DARK = ["#8cd5ff", "#64baff", "#3689e6", "#2a6bb0", "#1d4a7a", "#16324f"]

# The rainbow that must never come back (elementary families, one step each).
RAINBOW = ["#a10705", "#cc3b02", "#ad5f00", "#206b00", "#4c158a", "#ff8c82", "#ffa154", "#ffe16b"]


def _srgb_to_linear(c: float) -> float:
    c /= 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def _pyramid_block() -> str:
    """The Pyramid's own <svg>.

    Anchored on the heading text (">Pyramid of Pain<"), not the bare string:
    "Pyramid of Pain" also appears in an earlier layout comment, and starting
    there would capture the Diamond Model's SVG instead.
    """
    html = TEMPLATE.read_text()
    start = html.index(">Pyramid of Pain<")
    end = html.index("</svg>", start)
    return html[start:end]


def test_light_ramp_is_monotonic_in_luminance():
    lums = [relative_luminance(c) for c in RAMP_LIGHT]
    assert lums == sorted(lums), "light ramp must run dark -> light going down the pyramid"


def test_dark_ramp_is_monotonic_in_luminance():
    lums = [relative_luminance(c) for c in RAMP_DARK]
    assert lums == sorted(lums, reverse=True), "dark ramp must invert: brightest = most pain"


def test_ramps_are_a_single_hue_family():
    """Every step is blue-dominant: blue channel is the largest of the three."""
    for ramp in (RAMP_LIGHT, RAMP_DARK):
        for c in ramp:
            r, g, b = (int(c[i : i + 2], 16) for i in (1, 3, 5))
            assert b >= r and b >= g, f"{c} is not blue-dominant — ramp must stay one hue"


def test_template_uses_the_ramp_and_not_the_rainbow():
    block = _pyramid_block()
    for step in RAMP_LIGHT + RAMP_DARK:
        assert step in block, f"ramp step {step} missing from the Pyramid block"
    for banned in RAINBOW:
        assert banned not in block, f"categorical rainbow colour {banned} is back in the Pyramid"


def test_pyramid_ships_dark_variants():
    """Inactive bands were near-white on the noir card before this was fixed."""
    block = _pyramid_block()
    assert "dark:fill-[#222c3b]" in block, "inactive band needs a dark fill"
    assert "dark:stroke-[#1a2433]" in block, "band separator must match the dark surface"
    assert re.search(r"dark:fill-noir-(hi|mute)", block), "labels need dark text tokens"


def test_unpopulated_levels_say_not_collected_yet():
    """ "Not collected yet" and "None found" are different claims."""
    block = _pyramid_block()
    assert "Not collected yet" in block
    assert "None found" in block
    assert "requires IOC extraction" in block, "pending levels need an explanatory title"
