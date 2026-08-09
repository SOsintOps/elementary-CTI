"""Deterministic pixel-art mugshot avatar generator.

Generates a human face on a small grid, scales up with nearest-neighbor,
and composites onto a mugshot backdrop with height-scale lines.

Usage:
    from pestilentia.web.mugshot import generate_mugshot
    img = generate_mugshot("lockbit", size=256)
    img.save("lockbit.png")
"""

# "Your appearance is quite acceptable, Watson." — Sherlock Holmes, Elementary
from __future__ import annotations

import hashlib
import random

from PIL import Image, ImageDraw

SKIN_TONES = [
    (255, 224, 189),
    (255, 205, 148),
    (234, 192, 134),
    (255, 173, 96),
    (196, 142, 72),
    (141, 85, 36),
    (87, 57, 28),
    (60, 40, 20),
]

HAIR_COLORS = [
    (30, 20, 10),
    (60, 40, 20),
    (100, 60, 30),
    (140, 80, 40),
    (180, 140, 80),
    (220, 200, 160),
    (200, 60, 30),
    (80, 80, 80),
    (50, 50, 60),
]

EYE_COLORS = [
    (40, 30, 20),
    (60, 100, 60),
    (50, 80, 140),
    (100, 70, 40),
    (30, 30, 30),
]

SHIRT_COLORS = [
    (180, 100, 30),
    (60, 60, 70),
    (80, 80, 90),
    (100, 60, 40),
    (50, 50, 55),
    (70, 50, 40),
    (90, 90, 100),
]

BG_COLOR = (180, 185, 190)
LINE_COLOR = (120, 125, 130)
GRID = 16
FACE_W = 8
FACE_H = 9


HAIR_STYLES = [
    "bald",
    "short",
    "flat",
    "mohawk",
    "side",
    "long",
    "buzz",
    "parted",
]


def _seed(name: str) -> random.Random:
    h = hashlib.sha256(name.lower().strip().encode()).hexdigest()
    return random.Random(h)


def _draw_hair(draw, rng, x0, y0, hair_color, style):
    if style == "bald":
        return
    elif style == "short":
        for dx in range(FACE_W):
            draw.point((x0 + dx, y0), fill=hair_color)
            if rng.random() > 0.3:
                draw.point((x0 + dx, y0 - 1), fill=hair_color)
    elif style == "flat":
        for dx in range(FACE_W):
            draw.point((x0 + dx, y0), fill=hair_color)
            draw.point((x0 + dx, y0 - 1), fill=hair_color)
    elif style == "mohawk":
        for dx in range(2, FACE_W - 2):
            draw.point((x0 + dx, y0), fill=hair_color)
            draw.point((x0 + dx, y0 - 1), fill=hair_color)
            draw.point((x0 + dx, y0 - 2), fill=hair_color)
    elif style == "side":
        for dx in range(FACE_W):
            draw.point((x0 + dx, y0), fill=hair_color)
        for dy in range(1, 4):
            draw.point((x0, y0 + dy), fill=hair_color)
            draw.point((x0 + FACE_W - 1, y0 + dy), fill=hair_color)
    elif style == "long":
        for dx in range(FACE_W):
            draw.point((x0 + dx, y0), fill=hair_color)
            draw.point((x0 + dx, y0 - 1), fill=hair_color)
        for dy in range(1, 6):
            draw.point((x0, y0 + dy), fill=hair_color)
            draw.point((x0 + FACE_W - 1, y0 + dy), fill=hair_color)
    elif style == "buzz":
        for dx in range(FACE_W):
            draw.point((x0 + dx, y0), fill=hair_color)
    elif style == "parted":
        for dx in range(FACE_W):
            draw.point((x0 + dx, y0), fill=hair_color)
        for dx in range(FACE_W // 2):
            draw.point((x0 + dx, y0 - 1), fill=hair_color)


# "I'm an expert in criminal behavior, not normal behavior." — Sherlock, Elementary
def _draw_face(img, rng):
    draw = ImageDraw.Draw(img)
    skin = rng.choice(SKIN_TONES)
    hair_color = rng.choice(HAIR_COLORS)
    eye_color = rng.choice(EYE_COLORS)
    shirt_color = rng.choice(SHIRT_COLORS)
    hair_style = rng.choice(HAIR_STYLES)

    x0 = (GRID - FACE_W) // 2
    y0_hair = 2
    y0_face = y0_hair + 1

    # Head shape
    for dy in range(FACE_H):
        for dx in range(FACE_W):
            # Round top corners
            if dy == 0 and (dx == 0 or dx == FACE_W - 1):
                continue
            draw.point((x0 + dx, y0_face + dy), fill=skin)

    # Eyes (row 3 from face top)
    eye_y = y0_face + 3
    eye_l = x0 + 2
    eye_r = x0 + FACE_W - 3
    draw.point((eye_l, eye_y), fill=eye_color)
    draw.point((eye_r, eye_y), fill=eye_color)

    # Eyebrows
    brow_y = eye_y - 1
    darker_skin = tuple(max(0, c - 40) for c in skin)
    draw.point((eye_l, brow_y), fill=darker_skin)
    draw.point((eye_l - 1, brow_y), fill=darker_skin)
    draw.point((eye_r, brow_y), fill=darker_skin)
    draw.point((eye_r + 1, brow_y), fill=darker_skin)

    # Nose
    nose_y = eye_y + 2
    nose_shade = tuple(max(0, c - 20) for c in skin)
    draw.point((x0 + FACE_W // 2, nose_y), fill=nose_shade)

    # Mouth
    mouth_y = nose_y + 2
    mouth_color = tuple(max(0, c - 30) for c in skin)
    mouth_w = rng.choice([2, 3, 4])
    mouth_start = x0 + (FACE_W - mouth_w) // 2
    for dx in range(mouth_w):
        draw.point((mouth_start + dx, mouth_y), fill=mouth_color)

    # Hair
    _draw_hair(draw, rng, x0, y0_hair, hair_color, hair_style)

    # Ears
    ear_y = y0_face + 3
    draw.point((x0 - 1, ear_y), fill=skin)
    draw.point((x0 + FACE_W, ear_y), fill=skin)

    # Neck
    neck_y = y0_face + FACE_H
    neck_x = x0 + FACE_W // 2
    for dx in range(-1, 2):
        draw.point((neck_x + dx, neck_y), fill=skin)

    # Shoulders / shirt
    shirt_y = neck_y + 1
    for dy in range(GRID - shirt_y):
        for dx in range(GRID):
            dist = abs(dx - GRID // 2)
            if dist < 5 + dy:
                draw.point((dx, shirt_y + dy), fill=shirt_color)

    # Facial hair (random)
    if rng.random() > 0.6:
        beard_color = tuple(max(0, c - 10) for c in hair_color)
        for dx in range(mouth_start - 1, mouth_start + mouth_w + 1):
            if rng.random() > 0.4:
                draw.point((dx, mouth_y + 1), fill=beard_color)

    # Scar (rare)
    if rng.random() > 0.85:
        scar_color = tuple(min(255, c + 40) for c in skin)
        scar_x = rng.choice([eye_l + 1, eye_r - 1])
        for dy in range(2):
            draw.point((scar_x, eye_y + dy), fill=scar_color)


def _draw_backdrop(img, size):
    """Draw mugshot backdrop with height-scale lines."""
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, size - 1, size - 1], fill=BG_COLOR)

    scale = size / GRID
    line_positions = [
        (int(2 * scale), "6'0\""),
        (int(4 * scale), "5'6\""),
        (int(7 * scale), "5'0\""),
        (int(10 * scale), "4'6\""),
    ]

    for y, _label in line_positions:
        draw.line([(0, y), (size - 1, y)], fill=LINE_COLOR, width=1)
        for tick_x in [0, size // 4, size // 2, 3 * size // 4, size - 1]:
            draw.line([(tick_x, y - 2), (tick_x, y + 2)], fill=LINE_COLOR, width=1)


# "Watson, I am in need of a puzzle." — Sherlock Holmes, Elementary
def generate_mugshot(name: str, size: int = 256) -> Image.Image:
    rng = _seed(name)

    pixel_img = Image.new("RGB", (GRID, GRID), BG_COLOR)
    _draw_face(pixel_img, rng)

    backdrop = Image.new("RGB", (size, size), BG_COLOR)
    _draw_backdrop(backdrop, size)

    face_scaled = pixel_img.resize((size, size), Image.NEAREST)

    # Composite: backdrop lines show through transparent-ish areas
    # Since both are RGB, paste face on top — face pixels override backdrop
    for y in range(size):
        for x in range(size):
            px = face_scaled.getpixel((x, y))
            if px != BG_COLOR:
                backdrop.putpixel((x, y), px)

    return backdrop
