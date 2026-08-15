# "The temptation to form premature theories upon insufficient data." — Sherlock Holmes
"""Indicator extraction — the regex decides what exists, the model decides what matters.

The rule this module enforces (ADR-006 §3, Phase 4 plan): **the regex pre-pass
is the admissible set.** An indicator the model returns that no pattern found in
the article is dropped, no matter how plausible it looks. A model that invents a
C2 address invents one that parses; only presence in the text separates the two.

That leaves the model a real job rather than a rubber stamp — an IOC dump lists
hundreds of strings and almost none of them are the article's point. The model
picks the ones that carry meaning and says why. It cannot add.

Two consequences of putting the regex first:

**The pre-pass leans towards recall.** Anything it misses is unrecoverable,
while anything spurious it emits survives only if the model independently names
it. So the patterns are permissive and the *validators* are strict, in the one
direction where being strict is free: an address either parses as an address, a
hash is hex of exactly one of three lengths, a Bitcoin address either carries a
valid checksum or does not. Shape is checked by `ipaddress`, `hashlib` and
arithmetic, never by a plausible-looking regex alone.

**The type is not the model's to state.** Whether a string is a domain or a URL
is a property of the string, so the stored `ioc_type` is the pattern's. The
model's `ioc_type` is only how it found its way to the value.

Overlaps are deliberate: `https://evil.com/a.bin` yields both the URL and the
domain, and the model keeps whichever it is actually reasoning about.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum

from pestilentia.ai.extraction.anchors import Anchor, AnchorIndex, refang
from pestilentia.ai.schemas import ExtractIocOutput, IocType

# Patterns run over the refanged, lowercased view of the body (see
# `AnchorIndex.scan`), so they are written for clean text and still find
# `1.2.3[.]4`. Lookarounds rather than `\b` at the numeric and hex edges: `\b`
# treats `.` as a boundary, which would let `1.2.3.4` match inside a build
# number like `10.0.19041.1`.
#
# The trailing guards on the two dotted types spell out what a following `.`
# means, and it is the same lesson `anchors._extends_indicator` records: a dot
# continues the token only when something follows it. `(?![\d.])` refused
# `203.0.113.7.` at the end of a sentence — the commonest position an address
# appears in — so it is `(?!\d)(?!\.\d)` here and the same shape for domains.
# Found by the runner's integration test, not by reading the pattern.
_PATTERNS: tuple[tuple[IocType, re.Pattern[str]], ...] = (
    (IocType.URL, re.compile(r"(?:https?|ftp)://[^\s<>\"'\[\]]+(?<![.,;:!?)])")),
    (
        IocType.EMAIL,
        re.compile(r"(?<![a-z0-9._%+-])[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}"),
    ),
    (IocType.SHA256, re.compile(r"(?<![0-9a-z])[0-9a-f]{64}(?![0-9a-z])")),
    (IocType.SHA1, re.compile(r"(?<![0-9a-z])[0-9a-f]{40}(?![0-9a-z])")),
    (IocType.MD5, re.compile(r"(?<![0-9a-z])[0-9a-f]{32}(?![0-9a-z])")),
    (IocType.IPV4, re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")),
    (IocType.IPV6, re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")),
    (IocType.BTC_ADDRESS, re.compile(r"(?<![a-z0-9])(?:[13][a-z0-9]{25,34}|bc1[a-z0-9]{11,71})")),
    (
        IocType.DOMAIN,
        re.compile(
            r"(?<![a-z0-9.@_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}"
            r"(?![a-z0-9-])(?!\.[a-z0-9])"
        ),
    ),
)

# Filenames look exactly like domains, and malware reporting is full of them.
# Only extensions that are *not* real TLDs are listed: `.sh`, `.md`, `.pl`,
# `.zip` and `.mov` are all delegated, so `payload.zip` stays admissible and
# the model settles it — refusing there would lose real domains for good.
# fmt: off
_FILE_EXTENSIONS = frozenset({
    "exe", "dll", "sys", "scr", "lnk", "bat", "cmd", "vbs", "ps1", "psm1", "hta", "jar", "apk",
    "msi", "iso", "img", "dmg", "pkg", "deb", "rpm", "php", "aspx", "asp", "jsp", "html", "htm",
    "css", "json", "xml", "yaml", "yml", "csv", "txt", "log", "conf", "cfg", "ini", "dat",
    "tmp", "bak", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "odt", "png",
    "jpg", "jpeg", "gif", "bmp", "svg", "ico", "mp3", "mp4", "avi", "wav", "rar", "gz", "bz2",
    "xz", "tar", "cab", "pyc", "jsx", "tsx", "cpp", "hpp", "sql", "dump", "bin", "ova", "vhd",
    "vmdk",
})
# fmt: on

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# BIP-173 (segwit v0) and BIP-350 (bech32m, segwit v1+) differ only in this
# constant; an address is valid if it satisfies either.
_BECH32_CONSTANTS = (1, 0x2BC830A3)


class RejectionReason(StrEnum):
    """Why an indicator the model returned did not survive."""

    MODEL_ONLY = "model_only"  # nothing in the article says this
    DUPLICATE = "duplicate"  # the same indicator, returned twice


@dataclass(frozen=True)
class Candidate:
    """One indicator the pre-pass found, with the span it occupies."""

    ioc_type: IocType
    value: str
    anchor: Anchor


@dataclass(frozen=True)
class Indicator:
    """A model-selected indicator that the article actually contains.

    Maps one-to-one onto an `article_iocs` row (migration 0018).
    """

    ioc_type: IocType
    value: str
    value_defanged: str
    span_start: int
    span_end: int
    context: str


@dataclass(frozen=True)
class Rejected:
    ioc_type: IocType
    value: str
    reason: RejectionReason


@dataclass(frozen=True)
class IocReconciliation:
    """Both halves of the decision — what was kept and what was refused.

    The refusals are the interesting half: a run whose model invents indicators
    is a run to look at, and that is invisible if rejects are dropped on the
    floor rather than counted.
    """

    kept: tuple[Indicator, ...]
    rejected: tuple[Rejected, ...]


def _decode_base58(value: str) -> bytes | None:
    number = 0
    for char in value:
        index = _BASE58.find(char)
        if index < 0:
            return None
        number = number * 58 + index
    payload = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + payload


def _is_base58check(value: str) -> bool:
    """A 25-byte payload whose last four bytes are its own double-SHA256.

    Worth the arithmetic: `[13][a-z0-9]{25,34}` also matches an MD5 that
    happens to start with a 1, and a plausible-looking ransom address is
    exactly the sort of thing a model will confirm if asked.
    """
    raw = _decode_base58(value)
    if raw is None or len(raw) != 25:
        return False
    digest = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()
    return digest[:4] == raw[-4:]


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, coefficient in enumerate(generator):
            if (top >> bit) & 1:
                checksum ^= coefficient
    return checksum


def _is_bech32(value: str) -> bool:
    """BIP-173/350 checksum over the `bc1` addresses ransom notes now carry."""
    if value != value.lower() or "1" not in value:
        return False
    prefix, _, data = value.rpartition("1")
    if not prefix or len(data) < 6 or any(char not in _BECH32 for char in data):
        return False
    expanded = (
        [ord(char) >> 5 for char in prefix]
        + [0]
        + [ord(char) & 31 for char in prefix]
        + [_BECH32.index(char) for char in data]
    )
    return _bech32_polymod(expanded) in _BECH32_CONSTANTS


def _canonical(ioc_type: IocType, matched: str, written: str) -> str | None:
    """The value to store, or None when the shape does not hold up.

    `matched` is the normalised text (lowercased, refanged); `written` is the
    article's own wording refanged. Types whose case is significant — URL paths
    and base58 addresses — canonicalise from `written`; the rest, where case is
    noise, from `matched`.
    """
    match ioc_type:
        case IocType.IPV4:
            try:
                return str(ipaddress.IPv4Address(matched))
            except ValueError:
                return None
        case IocType.IPV6:
            try:
                return str(ipaddress.IPv6Address(matched))
            except ValueError:
                return None
        case IocType.DOMAIN:
            return None if matched.rsplit(".", 1)[-1] in _FILE_EXTENSIONS else matched
        case IocType.BTC_ADDRESS:
            if _is_base58check(written) or _is_bech32(written):
                return written
            return None
        case IocType.URL:
            return written
        case _:
            return matched


def scan(body: str | AnchorIndex) -> tuple[Candidate, ...]:
    """Every indicator the article itself contains — the admissible set.

    Deduplicated on `(type, value)`, keeping the first occurrence, because a
    domain repeated eleven times is one indicator with one span to show.
    """
    index = body if isinstance(body, AnchorIndex) else AnchorIndex(body)
    found: dict[tuple[IocType, str], Candidate] = {}
    for ioc_type, pattern in _PATTERNS:
        for matched, located in index.scan(pattern):
            value = _canonical(ioc_type, matched, refang(located.text))
            if value is None:
                continue
            found.setdefault((ioc_type, value), Candidate(ioc_type, value, located))
    return tuple(found.values())


def _key(value: str) -> str:
    return refang(value.strip()).casefold()


def reconcile(body: str, output: ExtractIocOutput) -> IocReconciliation:
    """Intersect the model's selection with what the article contains.

    Matching is by value, not by type: the model reaches a value however it
    likes, and the pattern that found it in the text says what it is.
    """
    index = AnchorIndex(body)
    admissible: dict[str, Candidate] = {}
    for candidate in scan(index):
        # Keyed under both the canonical value and the article's own wording: a
        # model echoing `2001:0db8::1` is naming the same address the
        # `ipaddress` module canonicalises to `2001:db8::1`.
        for key in (_key(candidate.value), _key(candidate.anchor.text)):
            admissible.setdefault(key, candidate)

    kept: list[Indicator] = []
    rejected: list[Rejected] = []
    seen: set[tuple[IocType, str]] = set()

    for proposed in output.iocs:
        candidate = next(
            (
                admissible[key]
                for key in (_key(proposed.value_as_written), _key(proposed.value))
                if key in admissible
            ),
            None,
        )
        if candidate is None:
            rejected.append(Rejected(proposed.ioc_type, proposed.value, RejectionReason.MODEL_ONLY))
            continue
        identity = (candidate.ioc_type, candidate.value)
        if identity in seen:
            rejected.append(
                Rejected(candidate.ioc_type, candidate.value, RejectionReason.DUPLICATE)
            )
            continue
        seen.add(identity)
        kept.append(
            Indicator(
                ioc_type=candidate.ioc_type,
                value=candidate.value,
                value_defanged=candidate.anchor.text,
                span_start=candidate.anchor.start,
                span_end=candidate.anchor.end,
                context=_context(index, candidate, proposed.context),
            )
        )

    return IocReconciliation(kept=tuple(kept), rejected=tuple(rejected))


def _context(index: AnchorIndex, candidate: Candidate, offered: str) -> str:
    """The model's context sentence when it is really in the article, else the
    text around the indicator.

    A context we cannot find is not context — it is a second claim, and one we
    would be storing beside the indicator as though it were evidence.
    """
    if offered and index.find_quote(offered) is not None:
        return offered
    return index.window(candidate.anchor)
