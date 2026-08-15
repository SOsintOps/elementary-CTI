# "It is a capital mistake to theorise before one has data." — Sherlock Holmes
"""Whose address is this, which is a different question from whether it is real.

The gate can say how much it believes an indicator and cannot say who owns it,
and the live acceptance measured what that costs: the group `warlock` was given
`https://vscode.download.prss.microsoft.com/...` as one of its own profile URLs,
because the intruder had downloaded a legitimate tool from there. The quote
anchored, the type was right, the score was high, and the address belonged to
somebody else. No threshold reaches that.

**The test is not legitimate against malicious. It is durable against rented.**
A VPN exit node is rented. A file on a storage platform sits in an account that
will be closed. A package pulled from a vendor's own distribution network
belongs to the vendor. None of the three is a property of the adversary, and
`profile_urls` is the field for properties: the leak sites, the portals a group
gives itself. The same reasoning already justifies the VPN server lists this
project treats as authorities.

**What an exclusion does not do is delete anything.** The indicator stays in
`article_iocs` with its anchor and its provenance. What is refused is the
promotion to a permanent property of an adversary, which is a much stronger
claim than "this address appeared in this article".

**The loss is stated rather than discovered later.** An abused platform really
does host adversary infrastructure, and this rule loses it: in the acceptance
run `warlock` ends with no profile URL at all rather than one right and one
wrong. That trade was put to the user and taken deliberately.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

#: Domains that host other people's things. Each carries why it is here, because
#: an entry with no reason is one nobody will be able to defend later, and a
#: list nobody can defend is a list that grows until it is wrong.
#:
#: Deliberately short. Length is not coverage: a long list stops being read, and
#: an unread exclusion list quietly removes evidence.
PLATFORM_DOMAINS: dict[str, str] = {
    # Vendors' own distribution. The intruder is a customer here, like anyone.
    "microsoft.com": "Microsoft's own distribution network",
    "windows.net": "Microsoft platform",
    "azureedge.net": "Microsoft content delivery",
    "apple.com": "vendor distribution",
    "google.com": "vendor distribution",
    "googleapis.com": "Google platform",
    # Code and file hosting, where an account is opened in a minute and closed
    # in a minute. Abused constantly, and durable for nobody.
    "github.com": "code hosting, per-account and revocable",
    "githubusercontent.com": "code hosting, per-account and revocable",
    "gitlab.com": "code hosting, per-account and revocable",
    "supabase.co": "backend platform, per-project and revocable",
    "amazonaws.com": "cloud platform, per-account and revocable",
    "cloudfront.net": "content delivery, per-account and revocable",
    "workers.dev": "edge platform, per-account and revocable",
    "pages.dev": "edge platform, per-account and revocable",
    "dropbox.com": "file hosting, per-account and revocable",
    "mediafire.com": "file hosting, per-account and revocable",
    "discord.com": "chat platform, per-account and revocable",
    "discordapp.com": "chat platform, per-account and revocable",
    "pastebin.com": "paste hosting, per-post and revocable",
    "t.me": "chat platform, per-channel and revocable",
    # Research publishers. Their reporting is about the adversary and is
    # regularly cited inside articles about it; it is never the adversary's own.
    "talosintelligence.com": "research publisher writing about adversaries",
    "welivesecurity.com": "research publisher writing about adversaries",
    "unit42.paloaltonetworks.com": "research publisher writing about adversaries",
    "sentinelone.com": "research publisher writing about adversaries",
    "trendmicro.com": "research publisher writing about adversaries",
    "securelist.com": "research publisher writing about adversaries",
    "cisa.gov": "government publisher writing about adversaries",
    "bleepingcomputer.com": "news publisher writing about adversaries",
    "thedfirreport.com": "research publisher writing about adversaries",
}

#: A leak site is the one thing in this domain that genuinely is the group's
#: own property, and it is exactly what an exclusion list must never touch.
_ONION = re.compile(r"\.onion$", re.I)


def _host(url: str) -> str:
    """The host of a URL, however casually the article wrote it."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    try:
        return (urlsplit(candidate).hostname or "").lower()
    except ValueError:
        return ""


def not_the_adversarys(url: str, rented: RentedSpace | None = None) -> str:
    """Why this URL is not a property of an adversary, or empty if it may be.

    A reason rather than a boolean, so the refusal can be recorded and argued
    with. "Excluded" tells a reviewer nothing; "Microsoft's own distribution
    network" tells them whether the rule was right.
    """
    host = _host(url)
    if not host:
        return ""
    if _ONION.search(host):
        return ""
    for domain, reason in PLATFORM_DOMAINS.items():
        if host == domain or host.endswith(f".{domain}"):
            return reason
    if rented is not None:
        return rented.covers(host)
    return ""


@dataclass(frozen=True)
class RentedSpace:
    """Address space somebody publishes as theirs, or as rented out by the hour.

    Built once and asked many times: the VPN list alone carries twelve thousand
    servers, and parsing that per indicator would make the check cost more than
    the analysis it guards.
    """

    exact: frozenset[str] = frozenset()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @classmethod
    def from_entries(cls, entries: Iterable[str]) -> RentedSpace:
        """Individual addresses and CIDR blocks, from lines somebody else wrote.

        A line that does not parse is skipped rather than raised on. These files
        are fetched daily from other people, and one of them was found shipping
        unresolved merge-conflict markers in the middle of its rows: one bad
        line must cost that line and not the run.
        """
        exact: set[str] = set()
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in entries:
            candidate = entry.strip()
            if not candidate:
                continue
            try:
                if "/" in candidate:
                    networks.append(ipaddress.ip_network(candidate, strict=False))
                else:
                    exact.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        return cls(frozenset(exact), tuple(networks))

    def covers(self, value: str) -> str:
        """Why this address says nothing durable, or empty if it might."""
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return ""
        if str(address) in self.exact:
            return "published as a rented server address"
        for network in self.networks:
            if address.version == network.version and address in network:
                return f"inside {network}, published as rented or platform space"
        return ""

    def __bool__(self) -> bool:
        return bool(self.exact or self.networks)


def rented_address(value: str, ranges: tuple[str, ...] = ()) -> str:
    """One-shot `RentedSpace.covers`, for a caller with a handful of entries."""
    return RentedSpace.from_entries(ranges).covers(value)
