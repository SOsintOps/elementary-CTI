# "I never guess. It is a shocking habit." — Sherlock Holmes
"""What a name is, answered from what the project already holds.

The sketch produces names, and until now every name the database did not
recognise went to the same place. Reading them shows they are not the same kind
of thing at all: `Amadey` is malware, `Storm-2372` is a vendor's designator for a
cluster it has deliberately not named, `MOIS` is a ministry, `@BonJoviGoesHard`
is a handle. Sending all of those to a human as "unknown adversary" wastes the
human on questions the ATT&CK bundle on disk can already answer.

**Offline by construction.** Nothing here opens a socket or calls a model. That
is not frugality, it is what makes the answers checkable: an alias asserted
because MITRE lists it can be verified by anyone with the same file, and an alias
asserted because a model found it plausible cannot. The layers that do reach the
network are built on top of this one and are expected to answer less often.

**No fuzzy matching, and the corpus is why.** The project's usual threshold of 85
puts `UAC-0145` within reach of `UAC-0114`, which is Winter Vivern. For a
designator the digits *are* the identity, so a rule that tolerates one being
wrong is a rule that merges two adversaries. In the other direction the same
threshold is too strict: `Sandworm` does not reach `Sandworm Team`, because the
extra word costs more similarity than a wrong digit does. The two failures are
symmetric and no single threshold fixes both, so this module uses none. It
strips the generic trailing word and compares exactly, which resolves
`Sandworm` → `Sandworm Team` and `Handala Hack Team` → `Handala Hack` without
deciding anything on a score.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Self

#: Words that a report adds or drops without meaning a different actor.
#: Stripped from the end of a name before comparing, on both sides. Only at the
#: end, and only one: `Lazarus Group` and `Lazarus` are the same actor, while
#: `Group 88` is a name that starts with one.
GENERIC_SUFFIXES = frozenset(
    {"group", "team", "gang", "crew", "collective", "apt", "actors", "operation"}
)

#: How a vendor writes "we have clustered this activity and not named it".
#: The prefix names the authority, which is the useful half: a Storm number is
#: Microsoft's and cannot be looked up anywhere else, and knowing that is the
#: difference between an open question and a dead end.
DESIGNATOR_AUTHORITIES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^storm[-\s]?\d{3,5}$", re.I), "Microsoft"),
    (re.compile(r"^dev[-\s]?\d{3,5}$", re.I), "Microsoft (retired scheme)"),
    (re.compile(r"^unc\s?\d{3,5}$", re.I), "Mandiant"),
    (re.compile(r"^temp\.\w+$", re.I), "Mandiant"),
    (re.compile(r"^uac[-\s]?\d{3,5}$", re.I), "CERT-UA"),
    (re.compile(r"^uat[-\s]?\d{3,6}$", re.I), "Cisco Talos"),
    (re.compile(r"^cl[-\s]?[a-z]{3}[-\s]?\d{3,5}$", re.I), "Unit 42"),
    (re.compile(r"^ta\d{3,4}$", re.I), "Proofpoint"),
)


#: What a vendor's naming scheme encodes, read off the names themselves.
#:
#: Derived from the 191 intrusion sets in the bundle rather than from anyone's
#: memory, and the derivation is repeatable: group the two-word aliases by their
#: second word, then read what ATT&CK's own descriptions say about the actors
#: carrying each. The families separate cleanly.
#:
#:   Panda 19 actors, 19 mention China     Bear 10, 13 mention Russia
#:   Typhoon 12, 12 mention China          Blizzard 8, 11 mention Russia
#:   Kitten 9, 14 mention Iran             Sandstorm 9, 12 mention Iran
#:   Chollima 5, 5 mention North Korea     Sleet 6, 6 mention North Korea
#:   Spider 9, financially motivated       Tempest 10, criminal or financial
#:
#: **That the two columns are two schemes and not one is also measured.** The
#: only family pairs that ever land on the same actor are exactly one from each
#: column: Bear+Blizzard 7, Panda+Typhoon 6, Spider+Tempest 5, Chollima+Sleet 4,
#: Kitten+Sandstorm 4. No two animals share an actor and no two weathers do,
#: because each house gives an actor one name. Two parallel alphabets over the
#: same axis, which is why a name alone is never an identity.
NAMING_FAMILIES: dict[str, tuple[str, str]] = {
    # CrowdStrike, animal by attribution. Verified against CrowdStrike's own
    # account of the scheme: SPIDER is monetary gain, nation states take the
    # national animal, JACKAL is hacktivism.
    "panda": ("CrowdStrike", "China"),
    "bear": ("CrowdStrike", "Russia"),
    "kitten": ("CrowdStrike", "Iran"),
    "chollima": ("CrowdStrike", "North Korea"),
    "buffalo": ("CrowdStrike", "Vietnam"),
    # Corroborated through Microsoft's cross-reference table rather than
    # CrowdStrike's: MYTHIC LEOPARD sits beside APT36 under Pakistan, and
    # SHADOW CRANE beside Zigzag Hail under Korea.
    "leopard": ("CrowdStrike", "Pakistan"),
    "crane": ("CrowdStrike", "Korea"),
    "spider": ("CrowdStrike", "financially motivated"),
    "jackal": ("CrowdStrike", "hacktivist"),
    # Microsoft, weather by origin or motivation. Taken from Microsoft's
    # published table, not from anyone's recollection, after three entries
    # written from memory turned out to be wrong: `rain` is Lebanon and not
    # South Korea, `cyclone` is Vietnam and not the offensive-industry
    # category, and that category is `tsunami`, which was missing entirely.
    "typhoon": ("Microsoft", "China"),
    "blizzard": ("Microsoft", "Russia"),
    "sandstorm": ("Microsoft", "Iran"),
    "sleet": ("Microsoft", "North Korea"),
    "rain": ("Microsoft", "Lebanon"),
    "hail": ("Microsoft", "South Korea"),
    "cyclone": ("Microsoft", "Vietnam"),
    "monsoon": ("Microsoft", "India"),
    "vortex": ("Microsoft", "Pakistan"),
    "lightning": ("Microsoft", "Palestinian Authority"),
    "heatwave": ("Microsoft", "Israel"),
    "squall": ("Microsoft", "Singapore"),
    "derecho": ("Microsoft", "Spain"),
    "haze": ("Microsoft", "Syria"),
    "dust": ("Microsoft", "Turkiye"),
    "frost": ("Microsoft", "Ukraine"),
    "gust": ("Microsoft", "United Arab Emirates"),
    "fog": ("Microsoft", "United Kingdom"),
    "tornado": ("Microsoft", "United States"),
    "waterspout": ("Microsoft", "Australia"),
    "freeze": ("Microsoft", "Canada"),
    "gale": ("Microsoft", "Germany"),
    "swell": ("Microsoft", "New Zealand"),
    "tempest": ("Microsoft", "financially motivated"),
    "tsunami": ("Microsoft", "private sector offensive actor"),
    "flood": ("Microsoft", "influence operations"),
}

#: Secureworks prefixes a metal instead of suffixing an animal. Same axis, and
#: measured the same way against ATT&CK's descriptions: IRON on 7 actors whose
#: description names Russia, BRONZE on 11 naming China, GOLD on 5 described as
#: financially motivated, COBALT on 3 naming Iran. NICKEL rests on one case,
#: `NICKEL GLADSTONE` beside APT38, and is held loosely for that reason.
#:
#: `Earth` is Trend Micro's, and what it encodes is not stated anywhere the
#: data can reach, so nothing is claimed about it beyond the house.
NAMING_PREFIXES: dict[str, tuple[str, str]] = {
    "iron": ("Secureworks", "Russia"),
    "bronze": ("Secureworks", "China"),
    "gold": ("Secureworks", "financially motivated"),
    "cobalt": ("Secureworks", "Iran"),
    "nickel": ("Secureworks", "North Korea"),
    "earth": ("Trend Micro", "unstated"),
}

#: Microsoft's own scheme before 2023 was chemical elements: STRONTIUM became
#: Forest Blizzard, NOBELIUM became Midnight Blizzard, HAFNIUM became Silk
#: Typhoon. Kept as a note rather than a table because an element name alone is
#: one word and this module only reads two-word forms — but it is why an older
#: report and a newer one can name the same actor with no word in common, and
#: why the archive has to hold the retired names too.
RETIRED_SCHEMES = ("Microsoft chemical elements, retired 2023", "Microsoft DEV-####, retired 2023")


@dataclass(frozen=True)
class NamingScheme:
    """Whose alphabet a name is written in, and what the word encodes."""

    vendor: str
    encodes: str
    word: str

    def __str__(self) -> str:
        return f"{self.vendor} scheme, {self.word!r} encodes {self.encodes}"


def naming_scheme(name: str) -> NamingScheme | None:
    """The house that coined this name, from the shape of the name alone.

    Useful precisely where the resolver fails: `Fox Tempest` is in no catalogue
    on disk, and knowing it is Microsoft's word for a financially motivated
    actor is most of what a reader wanted. It is a **classification and not an
    identification** — the vendor named it, we still do not know who it is, and
    the two must not be confused in a database.
    """
    parts = _key(name).split()
    if len(parts) < 2:
        return None
    last, first = parts[-1], parts[0]
    if last in NAMING_FAMILIES:
        vendor, encodes = NAMING_FAMILIES[last]
        return NamingScheme(vendor=vendor, encodes=encodes, word=last)
    if first in NAMING_PREFIXES:
        vendor, encodes = NAMING_PREFIXES[first]
        return NamingScheme(vendor=vendor, encodes=encodes, word=first)
    return None


class NameKind(StrEnum):
    """What the name turned out to be."""

    #: An actor an authority names, with the other names it goes by.
    KNOWN_ACTOR = "known_actor"
    #: Software, not an actor. Naming it as an adversary is a category error the
    #: reports themselves invite, since an intrusion is often called after its
    #: malware.
    MALWARE = "malware"
    TOOL = "tool"
    #: A vendor's cluster number. Says who coined it, and says that whoever
    #: coined it declined to call it anything.
    CLUSTER_DESIGNATOR = "cluster_designator"
    #: Written in a house alphabet nobody on disk has catalogued yet. We know
    #: who named it and what their word encodes; we do not know who it is.
    VENDOR_NAMED = "vendor_named"
    #: Nothing on disk knows it. The honest answer, and the only one that earns
    #: the cost of looking further afield.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Resolution:
    """What a name is, and who says so.

    `authority` and `evidence` are not decoration. An alias with no provenance
    cannot be revoked later, because nothing distinguishes it from one that was
    checked: the reason this carries its source is the same reason a finding
    carries its anchor.
    """

    name: str
    kind: NameKind
    canonical: str = ""
    aliases: tuple[str, ...] = ()
    authority: str = ""
    evidence: str = ""

    @property
    def resolved(self) -> bool:
        """Did this land on something nameable, rather than merely classified?"""
        return self.kind is NameKind.KNOWN_ACTOR

    def is_alias_of(self, other: str) -> bool:
        """Would an authority call these two names one actor?

        The question the gate has to ask before proposing a merge, and the one
        it used to answer by assuming.
        """
        if not self.resolved:
            return False
        return _key(other) in {_key(alias) for alias in self.aliases}


#: Typographic dashes a report uses where a catalogue types a plain hyphen.
#: `I-SOON` arrived written with U+2011 and missed `isoon` in the galaxy over
#: one invisible character, the same class of defect the evidence anchor had:
#: a difference that no reader would call a difference.
_DASHES = str.maketrans({c: "-" for c in "\u2010\u2011\u2012\u2013\u2014\u2015\u2212"})


def _key(name: str) -> str:
    """A name reduced to what a comparison should care about.

    Case and spacing are not identity, and neither is which dash was typed.
    Punctuation mostly is not either, with one exception kept deliberately: the
    digits inside a designator survive, because `UAC-0145` and `UAC-0114`
    differ by exactly those.
    """
    return " ".join(name.casefold().translate(_DASHES).replace("'", "").split())


def _squashed(name: str) -> str:
    """The name with its separators gone, for catalogues that spell it solid.

    `I-SOON` and `isoon` are one company; `APT 29` and `APT29` are one actor.
    Safe for designators rather than dangerous to them: squashing `UAC-0145`
    and `UAC-0114` yields two strings that still differ, because what tells
    them apart was never the hyphen.
    """
    return _key(name).replace("-", "").replace(" ", "")


def _stripped(name: str) -> str:
    """The name without one trailing generic word.

    `Sandworm Team` and `Sandworm` are one actor; so are `Handala Hack Team` and
    the `Handala Hack` that ATT&CK lists. One word, from the end only, and never
    the whole name: `Group 88` keeps its `Group`, since removing a leading word
    would be inventing a different name rather than recognising the same one.
    """
    parts = _key(name).split()
    if len(parts) > 1 and parts[-1] in GENERIC_SUFFIXES:
        return " ".join(parts[:-1])
    return " ".join(parts)


def designator_authority(name: str) -> str:
    """Who coined this, if it is a cluster number at all."""
    stripped = _key(name)
    for pattern, authority in DESIGNATOR_AUTHORITIES:
        if pattern.match(stripped):
            return authority
    return ""


@dataclass
class IdentityCatalog:
    """Names to what they denote, built once from the ATT&CK bundle.

    Deliberately the same bundle `AttackCatalog` reads. A second copy of the
    same file, loaded under a second set of rules, is how two answers to one
    question start disagreeing.
    """

    _actors: dict[str, dict] = field(default_factory=dict)
    _malware: dict[str, str] = field(default_factory=dict)
    _tools: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_bundle(cls, bundle: dict) -> Self:
        actors: dict[str, dict] = {}
        malware: dict[str, str] = {}
        tools: dict[str, str] = {}

        for obj in bundle.get("objects", ()):
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            kind = obj.get("type")
            name = obj.get("name") or ""
            if kind == "intrusion-set":
                names = tuple(dict.fromkeys([name, *(obj.get("aliases") or [])]))
                entry = {"canonical": name, "aliases": names, "authority": "mitre-attack"}
                for alias in names:
                    # First writer wins: a later set claiming a name another
                    # already holds is a conflict to look at, not something to
                    # settle silently by overwriting.
                    actors.setdefault(_key(alias), entry)
                    actors.setdefault(_stripped(alias), entry)
                    actors.setdefault(_squashed(alias), entry)
            elif kind == "malware":
                malware.setdefault(_key(name), name)
                malware.setdefault(_stripped(name), name)
            elif kind == "tool":
                tools.setdefault(_key(name), name)
                tools.setdefault(_stripped(name), name)

        return cls(actors, malware, tools)

    @classmethod
    def from_misp_galaxy(cls, cluster: dict) -> Self:
        """The `threat-actor` galaxy, whose synonyms are the point of it.

        Five times the actors ATT&CK carries, because it catalogues the
        criminal brands and the regional clusters that ATT&CK does not track.
        The measurement that earned it a place: it is the only source on disk
        that knows `Labubu` and `Bearlyfy` are one actor.
        """
        actors: dict[str, dict] = {}
        for value in cluster.get("values", ()):
            canonical = value.get("value") or ""
            if not canonical:
                continue
            meta = value.get("meta") or {}
            names = tuple(dict.fromkeys([canonical, *(meta.get("synonyms") or [])]))
            entry = {"canonical": canonical, "aliases": names, "authority": "misp-galaxy"}
            for alias in names:
                for key in (_key(alias), _stripped(alias), _squashed(alias)):
                    actors.setdefault(key, entry)
        return cls(actors, {}, {})

    @classmethod
    def from_microsoft_mapping(cls, rows: list[dict]) -> Self:
        """Microsoft's own table of what it calls an actor and what others do.

        Small and authoritative about exactly one house's names, which is worth
        having on its own: it is the only source that says a `Storm` number was
        merged into an existing actor rather than promoted to a new one.
        """
        actors: dict[str, dict] = {}
        for row in rows:
            canonical = (row.get("Threat actor name") or "").strip()
            if not canonical:
                continue
            others = [n.strip() for n in (row.get("Other names") or "").split(",") if n.strip()]
            names = tuple(dict.fromkeys([canonical, *others]))
            entry = {"canonical": canonical, "aliases": names, "authority": "microsoft"}
            for alias in names:
                for key in (_key(alias), _stripped(alias), _squashed(alias)):
                    actors.setdefault(key, entry)
        return cls(actors, {}, {})

    @classmethod
    def from_group_names(cls, rows: Iterable[tuple[str, Sequence[str]]]) -> Self:
        """The adversaries this deployment already holds, with their alias lists.

        Layer one of the stack and the last one written, which is its own small
        lesson: the report showed `Warlock` as recognised by nothing while
        `warlock` sat in the local table, because every catalogue had been
        wired except the one at home.

        Asked first, ahead of ATT&CK and the galaxy, because a name this
        deployment already tracks is one an analyst here has already reasoned
        about, and an outside catalogue must not quietly rename it.
        """
        actors: dict[str, dict] = {}
        for canonical, aliases in rows:
            if not canonical:
                continue
            names = tuple(dict.fromkeys([canonical, *(aliases or [])]))
            entry = {"canonical": canonical, "aliases": names, "authority": "this database"}
            for alias in names:
                for key in (_key(alias), _stripped(alias), _squashed(alias)):
                    actors.setdefault(key, entry)
        return cls(actors, {}, {})

    @classmethod
    def merged(cls, *catalogs: Self) -> Self:
        """One catalogue from several, earlier ones winning.

        Precedence is the caller's and is a real decision: where two houses
        disagree about which names belong together, the first asked is the one
        answered with, and the disagreement is not averaged away. Averaging two
        opinions about identity would produce a third that nobody holds.
        """
        actors: dict[str, dict] = {}
        malware: dict[str, str] = {}
        tools: dict[str, str] = {}
        for catalog in catalogs:
            for key, entry in catalog._actors.items():
                actors.setdefault(key, entry)
            for key, found in catalog._malware.items():
                malware.setdefault(key, found)
            for key, found in catalog._tools.items():
                tools.setdefault(key, found)
        return cls(actors, malware, tools)

    def resolve(self, name: str) -> Resolution:
        """What this name is, from the bundle alone.

        Order matters and is not arbitrary. An authority naming the actor comes
        first, because `APT29` and `TA505` are shaped like designators *and* are
        the names their actors are known by: classifying them as unnamed
        clusters would throw away the answer while holding it. Only a
        designator nobody has adopted falls through to being described by its
        shape.
        """
        cleaned = name.strip()
        if not cleaned:
            return Resolution(name=name, kind=NameKind.UNKNOWN)

        for key in (_key(cleaned), _stripped(cleaned), _squashed(cleaned)):
            entry = self._actors.get(key)
            if entry is not None:
                authority = entry.get("authority", "mitre-attack")
                return Resolution(
                    name=cleaned,
                    kind=NameKind.KNOWN_ACTOR,
                    canonical=entry["canonical"],
                    aliases=entry["aliases"],
                    authority=authority,
                    evidence=(
                        f"{authority} lists {cleaned!r} among the names of {entry['canonical']}"
                    ),
                )

        for table, kind in ((self._malware, NameKind.MALWARE), (self._tools, NameKind.TOOL)):
            for key in (_key(cleaned), _stripped(cleaned)):
                found = table.get(key)
                if found is not None:
                    return Resolution(
                        name=cleaned,
                        kind=kind,
                        canonical=found,
                        authority="mitre-attack",
                        evidence=f"ATT&CK holds {found!r} as {kind.value}, not as an actor",
                    )

        authority = designator_authority(cleaned)
        if authority:
            return Resolution(
                name=cleaned,
                kind=NameKind.CLUSTER_DESIGNATOR,
                authority=authority,
                evidence=f"{authority} assigns this form to activity it has not named",
            )

        scheme = naming_scheme(cleaned)
        if scheme is not None:
            return Resolution(
                name=cleaned,
                kind=NameKind.VENDOR_NAMED,
                authority=scheme.vendor,
                evidence=str(scheme),
            )

        return Resolution(name=cleaned, kind=NameKind.UNKNOWN)
