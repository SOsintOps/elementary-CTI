# "Data! Data! Data! I can't make bricks without clay." — Sherlock Holmes
"""The curated catalogues this project treats as authorities, and how to get them.

Every feed here is published by the organisation that maintains it, versioned in
public, reachable without a key, and **licensed in terms somebody has actually
read**. That combination is what makes it usable as evidence rather than as a
hint: an alias asserted because MISP's galaxy lists it can be checked by anyone
with the same file and the same commit, and the claim survives the person who
made it.

The licence clause is the newest of the four and was added on 2026-08-15 at the
cost of a source. A vendor's own live API was the obvious replacement for a feed
that had died — same data, from the house itself, no key needed — and it was
turned down because no terms grant anyone the right to reuse it, and the page
that would say otherwise answers automated requests with a 403. A register with
nowhere to write a licence is a register that will keep accepting "it answered
when I asked".

**They are not all the same kind of thing, and the register says so.** Some
answer "who is this name". Others answer "what is this address", and answer it
in the negative — space announced by a provider whose business is renting it is
not an adversary's durable infrastructure, and until something knows that, the
gate can promote a rented server into a `Group`'s permanent property. Tor's exit
nodes answer the same way but are kept in their own kind, because leaving
through Tor and buying a server say different things about an operator. A list
that only ever says *no* is still evidence, and the register keeps it apart from
the ones that say *yes* so that nobody wires it up as intelligence about an
actor.

**A feed can also lie by standing still**, which is the failure this register
learned last. `nordvpn-servers` declared itself daily on the strength of an
upstream folder name and had in fact been frozen since March 2024; nothing in
the file could have said so, because a stale file and a stable one are the same
bytes. Hence `frozen_since`, and hence the health check that reads a feed's age
rather than its presence.

**Grade A, and the grade is a claim about the publisher and not about the data.**
These are curated by the houses that coin the names. That earns the top of
`article_sources.reliability_grade`, and it earns nothing else: a name that
appears here still has to match, and a match still records where it came from.
"""

from __future__ import annotations

import gzip
import json
import logging
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pestilentia.clients.http import get_with_retry

log = logging.getLogger(__name__)

#: Beside the ATT&CK bundle, which follows the same rules and predates this
#: module. Gitignored for the same reason: they are large, they change under
#: their own schedule, and a repository is not a mirror.
FEED_DIR = Path("data/feeds")


class FeedKind(StrEnum):
    """What a feed can be asked, which is not the same for all of them."""

    #: Names to actors. Answers "who is this".
    IDENTITY = "identity"
    #: Address space that belongs to someone whose business is renting it out,
    #: or to a platform. Answers "this is not an adversary's own infrastructure"
    #: and answers nothing else.
    INFRASTRUCTURE_CONTEXT = "infrastructure_context"
    #: Indicators tied to a published investigation. Answers "who else has seen
    #: this", which is corroboration and not identity.
    CORROBORATION = "corroboration"
    #: An anonymity network's own published nodes. Excluded from an adversary's
    #: durable property for the same reason as rented space, and kept apart from
    #: it because the two mean different things to an analyst: "the traffic left
    #: through Tor" is tradecraft, "the server was at a hosting provider" is
    #: procurement. Merging them here would be irreversible in the data.
    ANONYMITY_NETWORK = "anonymity_network"


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    filename: str
    kind: FeedKind
    publisher: str
    #: Why this one is trusted, in a sentence, because a grade with no reason
    #: behind it is a number somebody will later be unable to defend.
    warrant: str
    #: The licence, read from the publisher and named here rather than assumed.
    #: A field of its own since 2026-08-15, when a replacement source was
    #: rejected for having none: it was live, keyless and published by the house
    #: that owned the data, and still granted nobody permission to reuse it.
    #: "It answered when I asked" is not a licence, and a register that has no
    #: place to write one invites exactly that reasoning.
    licence: str
    #: Set when the publisher has stopped updating the feed. Carries the date of
    #: the last real change upstream, because a frozen feed and a stable one are
    #: indistinguishable from the file alone — which is how a list of VPN exit
    #: nodes went two and a half years out of date while a check reported green.
    frozen_since: str | None = None

    @property
    def path(self) -> Path:
        return FEED_DIR / self.filename

    @property
    def is_frozen(self) -> bool:
        return self.frozen_since is not None


_RAW = "https://raw.githubusercontent.com"

FEEDS: tuple[Feed, ...] = (
    Feed(
        name="misp-galaxy-threat-actor",
        url=f"{_RAW}/MISP/misp-galaxy/main/clusters/threat-actor.json",
        filename="misp-threat-actor.json",
        kind=FeedKind.IDENTITY,
        publisher="MISP Project",
        licence="CC0-1.0 or BSD-2-Clause (dual, stated in the project README)",
        warrant=(
            "1041 actors under 2393 names, curated in the open with every change "
            "in the history. Measured against this corpus it resolved twelve names "
            "no other layer could, including two that turned out to be one actor."
        ),
    ),
    Feed(
        name="microsoft-actor-naming",
        url=f"{_RAW}/microsoft/mstic/master/PublicFeeds/ThreatActorNaming/MicrosoftMapping.json",
        filename="microsoft-actor-naming.json",
        kind=FeedKind.IDENTITY,
        publisher="Microsoft MSTIC",
        licence="CC-BY-4.0 (microsoft/mstic) — attribution required",
        warrant=(
            "The house's own table of what it calls an actor and what everyone "
            "else calls it. Known to lag the documentation page it is published "
            "beside, so it is read as a floor and never as the whole truth."
        ),
    ),
    Feed(
        name="nordvpn-servers",
        url=f"{_RAW}/microsoft/mstic/master/PublicFeeds/NordVPNDaily/nordvpn-servers.csv",
        filename="nordvpn-servers.csv",
        kind=FeedKind.INFRASTRUCTURE_CONTEXT,
        publisher="Microsoft MSTIC",
        licence="CC-BY-4.0 (microsoft/mstic)",
        frozen_since="2024-03-04",
        warrant=(
            "**Dead, and it used to claim otherwise.** This entry read 'Daily' "
            "until 2026-08-15, on the strength of the upstream folder being "
            "called NordVPNDaily. Measured against GitHub's commit history that "
            "day, the last real update was 2024-03-04 and the only thing after "
            "it is an October 2024 merge; Microsoft froze all three of its VPN "
            "feeds (PIA October 2024, TorGuard August 2024) without saying so. "
            "The bytes we hold match upstream exactly, so nothing local was "
            "wrong — the file was simply two and a half years old while the "
            "gate's refusal-without-feeds guard reported itself satisfied. "
            "Kept only as a **point observation of 2024-03-04**, never widened "
            "into a claim about any other date, and superseded for live use by "
            "the ASN layer below."
        ),
    ),
    Feed(
        name="microsoft-ip-ranges",
        url=f"{_RAW}/microsoft/mstic/master/PublicFeeds/MSFTIPRanges/MSFT_PublicIPs.csv",
        filename="microsoft-public-ips.csv",
        kind=FeedKind.INFRASTRUCTURE_CONTEXT,
        publisher="Microsoft MSTIC",
        licence="CC-BY-4.0 (microsoft/mstic) — attribution required",
        warrant=(
            "A platform's own address space, published by the platform. Alive: "
            "commits verified on 2026-08-15, most recent 2026-07-30, though the "
            "cadence is irregular rather than the daily one its neighbours "
            "claimed."
        ),
    ),
    Feed(
        name="iptoasn-v4",
        url="https://iptoasn.com/data/ip2asn-v4.tsv.gz",
        filename="ip2asn-v4.tsv.gz",
        kind=FeedKind.INFRASTRUCTURE_CONTEXT,
        publisher="iptoasn.com (Frank Denis), from RouteViews",
        licence="PDDL-1.0 (public domain)",
        warrant=(
            "Answers the ownership question one level up, where it is durable: "
            "an ASN says whose address space this is, and it keeps saying it "
            "when a provider replaces its fleet. Rebuilt daily from RouteViews. "
            "Measured on 2026-08-15: 532,734 ranges, of which the curated "
            "hosting list below keeps 15,275 covering 305,269,782 addresses — "
            "against roughly twelve thousand single addresses in the dead "
            "vendor list it replaces. It is the ASNs, not this file, that carry "
            "the judgement; see HOSTING_ASNS."
        ),
    ),
    Feed(
        name="tor-exit-addresses",
        url="https://check.torproject.org/exit-addresses",
        filename="tor-exit-addresses.txt",
        kind=FeedKind.ANONYMITY_NETWORK,
        publisher="The Tor Project",
        licence="CC0 — the Tor Project waives copyright in its data",
        warrant=(
            "The network's own published list of the nodes traffic leaves "
            "through, which is the only authority on the question. Current "
            "state only; the dated question is answered by the CollecTor "
            "archive, which reaches back to February 2010."
        ),
    ),
)

#: The address space we treat as rented rather than owned, named by ASN.
#:
#: **This is the judgement in the exclusion layer, and it is deliberately the
#: only one.** The feed above is a fact about who announces which prefix; which
#: of those announcers are in the business of renting is an assessment, so it
#: lives here with a reason per entry rather than dissolved into code. Getting
#: it wrong is survivable in one direction only: a provider wrongly listed costs
#: an indicator that would have been kept, while one wrongly omitted lets rented
#: space become a group's permanent property, which is the mistake that put a
#: vendor's own distribution network into an adversary's record.
#:
#: Matching is by ASN and never by the description string beside it. Those
#: strings are edited upstream without notice, and a rule keyed on one would
#: fail silently the day it was reworded.
HOSTING_ASNS: dict[int, str] = {
    # Consumer-VPN infrastructure. These are where the exit nodes of the big
    # VPN brands actually live, which is why an ASN layer replaces a vendor's
    # server list instead of merely supplementing it.
    9009: "M247 — hosts the exit fleets of several consumer VPN brands, NordVPN's included",
    60068: "CDN77 / Datacamp — the same trade, and the same use",
    212238: "Datacamp Limited — sibling range of the above",
    136787: "PacketHub S.A. — resells to VPN operators",
    # Hyperscale platforms. Adversaries rent here constantly, and so does
    # everyone else, which is the entire point of excluding it.
    16509: "Amazon AWS (AMAZON-02) — hourly compute, and the largest single pool of it",
    14618: "Amazon AWS (AMAZON-AES) — the same tenancy under a second announcement",
    15169: "Google — shared with its consumer services, so an address here names no tenant",
    396982: "Google Cloud — hourly compute under Google's separate cloud announcement",
    8075: "Microsoft — Azure tenancy and Microsoft's own services share this space",
    13335: "Cloudflare — a proxy in front of someone else's host, so it names the proxy",
    45102: "Alibaba Cloud — hourly compute, the usual pool for operations staged from Asia",
    132203: "Tencent Cloud — hourly compute under the same reasoning",
    # Mid-market hosting, the ordinary home of a rented server.
    14061: "DigitalOcean — cheap rented droplets, minutes to acquire and to abandon",
    16276: "OVH — bare metal and VPS by the month, a routine home for staging servers",
    24940: "Hetzner — the same trade in Germany and Finland",
    20473: "Vultr / Choopa — hourly VPS, widely used for short-lived infrastructure",
    63949: "Linode / Akamai — rented VPS estate, now under Akamai's ownership",
    51167: "Contabo — low-cost VPS, common in commodity abuse reporting",
    62240: "Clouvider — rented UK and US capacity, resold onward",
    9370: "Sakura Internet — Japanese hosting, rented rather than owned by its occupants",
}

FEEDS_BY_NAME = {feed.name: feed for feed in FEEDS}


def download_feed(feed: Feed, *, force: bool = False) -> Path:
    """Fetch a feed to its cache, or leave the cached copy alone.

    No TTL, deliberately, and for the same reason the ATT&CK bundle has none:
    a cache that refreshes itself on a timer refreshes in the middle of a run,
    and two articles analysed an hour apart then disagree for a reason that has
    nothing to do with the articles. Refreshing is something a person does
    between runs.
    """
    if feed.path.exists() and not force:
        return feed.path
    log.info("downloading %s from %s", feed.name, feed.url)
    response = get_with_retry(feed.url, timeout=120)
    response.raise_for_status()
    feed.path.parent.mkdir(parents=True, exist_ok=True)
    feed.path.write_bytes(response.content)
    return feed.path


def load_json_feed(feed: Feed) -> object | None:
    """The parsed feed, or None when it was never fetched.

    None rather than an exception, and never an empty catalogue: a resolver
    silently running against nothing would report every name as unknown, which
    reads exactly like a corpus of unknown names and would be believed.
    """
    if not feed.path.exists():
        log.warning("feed %s is not on disk; layers that need it will not answer", feed.name)
        return None
    return json.loads(feed.path.read_text(encoding="utf-8"))


def load_asn_ranges(feed: Feed | None = None) -> list[str]:
    """Start-end spans announced by the ASNs in `HOSTING_ASNS`, from iptoasn.

    The file is a gzipped TSV of `first  last  asn  country  description`, half
    a million rows of which the curated ASNs are about three per cent. Filtering
    on the number and never on the description is deliberate: those strings are
    reworded upstream without notice, and a rule keyed on one would stop
    matching quietly on the day it changed.
    """
    feed = feed or FEEDS_BY_NAME["iptoasn-v4"]
    if not feed.path.exists():
        log.warning("feed %s is not on disk; rented address space will not be excluded", feed.name)
        return []

    spans: list[str] = []
    with gzip.open(feed.path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 3:
                continue
            try:
                asn = int(fields[2])
            except ValueError:
                continue
            if asn in HOSTING_ASNS:
                spans.append(f"{fields[0]}-{fields[1]}")
    return spans


def load_tor_exit_addresses(feed: Feed | None = None) -> list[str]:
    """The addresses traffic leaves the Tor network through.

    The published format repeats a node's details over several lines and only
    the `ExitAddress` ones carry an address, so the file's ~3,200 such lines
    reduce to far fewer distinct addresses. Read for that one prefix rather than
    parsed as a whole, which is what keeps it working when the format gains a
    field.
    """
    feed = feed or FEEDS_BY_NAME["tor-exit-addresses"]
    if not feed.path.exists():
        log.warning("feed %s is not on disk; exit nodes will not be excluded", feed.name)
        return []

    addresses: list[str] = []
    with feed.path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.startswith("ExitAddress "):
                parts = line.split()
                if len(parts) > 1:
                    addresses.append(parts[1])
    return addresses


def load_address_ranges() -> tuple[str, ...]:
    """Every address, block and span the exclusion feeds publish.

    Four shapes now, each read for the one column it is for: Microsoft's file
    lists CIDR prefixes, the frozen VPN file one server per row, iptoasn
    start-end spans for the ASNs we treat as rented, and the Tor file the
    addresses traffic exits through. Anything else on a line is ignored rather
    than parsed, which keeps this working when a publisher adds a column.

    Returns an empty tuple when nothing has been fetched, and the caller must
    treat that as "this check cannot run" rather than as "nothing is excluded".
    The two look identical in the output and mean opposite things.

    **A third state exists and is the one that bit us:** a feed that was fetched
    and is stale. `nordvpn-servers` was two and a half years dead while this
    function returned its rows exactly as if they were current.

    **A feed marked `frozen_since` is therefore not read here at all.** The rule
    is on the field rather than on the feed's name, so the next publisher to go
    quiet is handled by setting a date instead of by remembering to edit this
    loop. Its rows are not lost: they are a true observation of the day the
    publisher stopped, and that is how they enter the record — as a point on
    that date, never as a claim about today. Reading them live and calling them
    a point observation in the register at the same time is the contradiction
    this guard removes.
    """
    entries: list[str] = []
    entries.extend(load_asn_ranges())
    entries.extend(load_tor_exit_addresses())
    for name, column in (("microsoft-ip-ranges", 0), ("nordvpn-servers", 1)):
        feed = FEEDS_BY_NAME[name]
        if feed.is_frozen:
            log.info(
                "feed %s is frozen upstream since %s; not read as current exclusion data",
                name,
                feed.frozen_since,
            )
            continue
        if not feed.path.exists():
            log.warning("feed %s is not on disk; its addresses will not be excluded", name)
            continue
        with feed.path.open(encoding="utf-8", errors="replace") as handle:
            for index, line in enumerate(handle):
                # The header, and the merge-conflict markers one publisher was
                # found shipping in the middle of its own rows. Grade A is a
                # claim about who publishes a file, never about it being clean.
                if index == 0 or line[:1] in "<=>":
                    continue
                fields = line.split(",")
                if len(fields) > column:
                    entries.append(fields[column].strip())
    return tuple(entries)
