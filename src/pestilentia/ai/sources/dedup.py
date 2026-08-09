# "Dirt is eloquent." — Sherlock Holmes, Elementary
"""Near-duplicate detection via 64-bit simhash over word unigrams.

Unigrams (not shingles): feed items are short (title+summary), where
shingle-level simhash is hypersensitive to single-word edits."""

from __future__ import annotations

import hashlib
import re

from sqlalchemy.orm import Session

from pestilentia.models.tables import Article

_TOKEN_RE = re.compile(r"[a-z0-9]+")
DEFAULT_HAMMING_THRESHOLD = 6


def simhash64(text: str) -> int:
    tokens = _TOKEN_RE.findall(text.lower())
    weights = [0] * 64
    for sh in tokens or [""]:
        h = int.from_bytes(hashlib.blake2b(sh.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if (h >> bit) & 1 else -1
    value = 0
    for bit in range(64):
        if weights[bit] > 0:
            value |= 1 << bit
    return value


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def find_near_duplicate(
    session: Session, sh: int, threshold: int = DEFAULT_HAMMING_THRESHOLD
) -> int | None:
    """Return the id of an existing article within the hamming threshold.

    Linear scan over stored simhashes — fine at our volume (hundreds/day);
    move to BK-tree/bands if it ever hurts.
    """
    for art_id, stored in session.query(Article.id, Article.body_simhash).filter(
        Article.body_simhash.isnot(None)
    ):
        if hamming(sh, int(stored, 16)) <= threshold:
            return art_id
    return None
