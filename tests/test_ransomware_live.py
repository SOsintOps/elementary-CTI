import httpx
import pytest

from pestilentia.clients.base import RateLimitError, SourceError
from pestilentia.clients.ransomware_live import RansomwareLiveSource, _parse_datetime
from pestilentia.clients.registry import SOURCES
from pestilentia.clients.schemas import RawCyberattack, RawGroup, RawVictim

VICTIM_FIXTURE = [
    {
        "victim": "acme-corp",
        "group": "lockbit",
        "domain": "acme.com",
        "country": "US",
        "activity": "manufacturing",
        "description": "Data leaked",
        "attackdate": "2026-01-15",
        "discovered": "2026-01-16 10:30:00",
        "claim_url": "http://onion.example/claim",
        "screenshot": "http://onion.example/screen.png",
        "url": "http://acme.com",
    }
]

GROUP_FIXTURE = [
    {
        "name": "lockbit",
        "description": "Ransomware group",
        "url": "http://lockbit.onion",
        "profile": "Active since 2019",
        "meta": None,
        "locations": [{"fqdn": "lockbit.onion", "title": "DLS", "type": "DLS"}],
    }
]

CYBERATTACK_FIXTURE = [
    {
        "victim": "globex",
        "domain": "globex.com",
        "country": "DE",
        "date": "2026-02-01",
        "added": "2026-02-02 08:00:00",
        "title": "Globex hit by ransomware",
        "summary": "Major attack on Globex",
        "url": "https://news.example/globex",
    }
]


@pytest.fixture
def source():
    return RansomwareLiveSource(base_url="https://api.ransomware.live/api/v2")


def test_registered():
    assert "ransomware.live" in SOURCES
    assert SOURCES["ransomware.live"] is RansomwareLiveSource


def test_parse_datetime_formats():
    from datetime import UTC

    # Current API format: ISO 8601 with 'T' and offset (regression — was parsed to None)
    dt = _parse_datetime("2026-06-11T15:50:04.568000+00:00")
    assert dt is not None and dt.year == 2026 and dt.month == 6 and dt.day == 11
    assert dt.tzinfo is not None
    # 'Z' suffix
    assert _parse_datetime("2026-06-11T15:50:04Z") is not None
    # Legacy space-separated and date-only forms still work, tz-aware
    assert _parse_datetime("2024-06-28 23:36:32").replace(tzinfo=UTC).year == 2024
    assert _parse_datetime("2026-01-15").day == 15
    # Garbage / empty -> None
    assert _parse_datetime("") is None
    assert _parse_datetime("not-a-date") is None


@pytest.mark.anyio
async def test_fetch_victims(source, httpx_mock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/api/v2/recentvictims",
        json=VICTIM_FIXTURE,
    )
    victims = await source.fetch_victims()
    assert len(victims) == 1
    v = victims[0]
    assert isinstance(v, RawVictim)
    assert v.victim_name == "acme-corp"
    assert v.group == "lockbit"
    assert v.domain == "acme.com"
    assert v.country == "US"
    assert v.attackdate is not None
    assert v.attackdate.year == 2026
    assert v.source == "ransomware.live"
    await source.close()


@pytest.mark.anyio
async def test_fetch_groups(source, httpx_mock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/api/v2/groups",
        json=GROUP_FIXTURE,
    )
    groups = await source.fetch_groups()
    assert len(groups) == 1
    g = groups[0]
    assert isinstance(g, RawGroup)
    assert g.name == "lockbit"
    assert g.meta == ""
    assert len(g.locations) == 1
    assert g.source == "ransomware.live"
    await source.close()


@pytest.mark.anyio
async def test_fetch_cyberattacks(source, httpx_mock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/api/v2/recentcyberattacks",
        json=CYBERATTACK_FIXTURE,
    )
    attacks = await source.fetch_cyberattacks()
    assert len(attacks) == 1
    a = attacks[0]
    assert isinstance(a, RawCyberattack)
    assert a.victim_name == "globex"
    assert a.attack_date is not None
    assert a.article_url == "https://news.example/globex"
    assert a.source == "ransomware.live"
    await source.close()


@pytest.mark.anyio
async def test_http_error_raises_source_error(source, httpx_mock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/api/v2/recentvictims",
        status_code=500,
    )
    with pytest.raises(SourceError, match="HTTP 500"):
        await source.fetch_victims()
    await source.close()


@pytest.mark.anyio
async def test_rate_limit_retries_then_raises(source, httpx_mock):
    for _ in range(3):
        httpx_mock.add_response(
            url="https://api.ransomware.live/api/v2/recentvictims",
            status_code=429,
            headers={"Retry-After": "0"},
        )
    with pytest.raises(RateLimitError):
        await source.fetch_victims()
    await source.close()


@pytest.mark.anyio
async def test_network_error_retries_then_raises(source, httpx_mock):
    for _ in range(3):
        httpx_mock.add_exception(
            httpx.ConnectError("Connection refused"),
            url="https://api.ransomware.live/api/v2/groups",
        )
    with pytest.raises(SourceError, match="Request failed"):
        await source.fetch_groups()
    await source.close()


@pytest.mark.anyio
async def test_empty_response(source, httpx_mock):
    httpx_mock.add_response(
        url="https://api.ransomware.live/api/v2/recentvictims",
        json=[],
    )
    victims = await source.fetch_victims()
    assert victims == []
    await source.close()
