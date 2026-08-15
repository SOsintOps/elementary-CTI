# "Data! Data! Data! I can't make bricks without clay." — Sherlock Holmes
"""The curated catalogues this project treats as authorities, and how to get them.

Every feed here is published by the organisation that maintains it, versioned in
public, and reachable without a key. That combination is what makes it usable as
evidence rather than as a hint: an alias asserted because MISP's galaxy lists it
can be checked by anyone with the same file and the same commit, and the claim
survives the person who made it.

**They are not all the same kind of thing, and the register says so.** Two of
them answer "who is this name", one answers "what is this address" and answers it
in the negative — an address on a commercial VPN's daily server list is not an
adversary's durable infrastructure, and until something knows that, the gate can
promote an exit node into a `Group`'s permanent property. A list that only ever
says *no* is still evidence, and the register keeps it apart from the ones that
say *yes* so that nobody wires it up as intelligence about an actor.

**Grade A, and the grade is a claim about the publisher and not about the data.**
These are curated by the houses that coin the names. That earns the top of
`article_sources.reliability_grade`, and it earns nothing else: a name that
appears here still has to match, and a match still records where it came from.
"""

from __future__ import annotations

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

    @property
    def path(self) -> Path:
        return FEED_DIR / self.filename


_RAW = "https://raw.githubusercontent.com"

FEEDS: tuple[Feed, ...] = (
    Feed(
        name="misp-galaxy-threat-actor",
        url=f"{_RAW}/MISP/misp-galaxy/main/clusters/threat-actor.json",
        filename="misp-threat-actor.json",
        kind=FeedKind.IDENTITY,
        publisher="MISP Project",
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
        warrant="Daily. An exit node is rented, so it says nothing durable about who used it.",
    ),
    Feed(
        name="microsoft-ip-ranges",
        url=f"{_RAW}/microsoft/mstic/master/PublicFeeds/MSFTIPRanges/MSFT_PublicIPs.csv",
        filename="microsoft-public-ips.csv",
        kind=FeedKind.INFRASTRUCTURE_CONTEXT,
        publisher="Microsoft MSTIC",
        warrant="A platform's own address space, published by the platform.",
    ),
)

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
