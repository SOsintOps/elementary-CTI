# "The value of data is in its application." — Sherlock Holmes, Elementary
from dataclasses import dataclass, field
from datetime import datetime


# "There is nothing more deceptive than an obvious fact." — Sherlock Holmes, Elementary
@dataclass(frozen=True)
class RawVictim:
    victim_name: str
    group: str
    domain: str = ""
    country: str = ""
    activity: str = ""
    description: str = ""
    attackdate: datetime | None = None
    discovered: datetime | None = None
    claim_url: str = ""
    screenshot: str = ""
    url: str = ""
    source: str = ""


@dataclass(frozen=True)
class RawGroup:
    name: str
    description: str = ""
    url: str = ""
    profile: str = ""
    meta: str = ""
    locations: list[dict] = field(default_factory=list)
    altname: str = ""
    source: str = ""
    # Detail fields (from /group/{name} endpoint)
    group_type: str = ""
    extensions: str = ""
    lineage: str = ""
    btc_addresses: str = ""


@dataclass(frozen=True)
class RawCyberattack:
    victim_name: str
    domain: str = ""
    country: str = ""
    attack_date: datetime | None = None
    added: datetime | None = None
    discovered: datetime | None = None
    title: str = ""
    summary: str = ""
    article_url: str = ""
    source: str = ""
