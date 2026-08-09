# "Not everything is a conspiracy, Watson." — Sherlock Holmes, Elementary
from datetime import UTC, datetime
from urllib.parse import quote

import anyio
import httpx

from pestilentia.clients.base import BaseSource, RateLimitError, SourceError
from pestilentia.clients.registry import register
from pestilentia.clients.schemas import RawCyberattack, RawGroup, RawVictim

_SOURCE = "ransomware.live"
_DEFAULT_BASE_URL = "https://api.ransomware.live/v2"
_MAX_RETRIES = 3
_INITIAL_BACKOFF = 2


# "The simplest explanation is almost always somebody did something stupid." — Sherlock
def _parse_datetime(value: str | None) -> datetime | None:
    """Parse an upstream timestamp string into a tz-aware UTC datetime.

    Upstream values are documented as UTC without an offset; attaching tzinfo
    here keeps every downstream comparison against `datetime.now(UTC)` valid
    under both SQLite (naive) and PostgreSQL (timestamptz).
    """
    if not value:
        return None
    # Current API format is ISO 8601 with 'T' and an offset
    # (e.g. "2026-06-11T15:50:04.568000+00:00"); fromisoformat also accepts the
    # legacy space-separated and date-only forms. Normalize a trailing 'Z'.
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


# "Nothing more stimulating than a case where everything goes against you." — Sherlock
@register
class RansomwareLiveSource(BaseSource):
    source_name = _SOURCE

    def __init__(self, base_url: str = _DEFAULT_BASE_URL, timeout: float = 30.0):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout)

    async def _get(self, path: str) -> list[dict]:
        url = f"{self._base_url}{path}"
        backoff = _INITIAL_BACKOFF

        for attempt in range(_MAX_RETRIES):
            try:
                response = await self._client.get(url)
            except httpx.HTTPError as exc:
                if attempt == _MAX_RETRIES - 1:
                    raise SourceError(_SOURCE, f"Request failed: {url}", exc) from exc
                await anyio.sleep(backoff)
                backoff *= 2
                continue

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait = int(retry_after) if retry_after else backoff
                if attempt == _MAX_RETRIES - 1:
                    raise RateLimitError(_SOURCE, wait)
                await anyio.sleep(wait)
                backoff *= 2
                continue

            if response.status_code >= 400:
                raise SourceError(_SOURCE, f"HTTP {response.status_code} from {url}")

            return response.json()

        raise SourceError(_SOURCE, f"Request failed after {_MAX_RETRIES} retries: {url}")

    async def fetch_victims(self) -> list[RawVictim]:
        data = await self._get("/recentvictims")
        return [
            RawVictim(
                victim_name=r.get("victim", ""),
                group=r.get("group", ""),
                domain=r.get("domain", ""),
                country=r.get("country", ""),
                activity=r.get("activity", ""),
                description=r.get("description", ""),
                attackdate=_parse_datetime(r.get("attackdate")),
                discovered=_parse_datetime(r.get("discovered")),
                claim_url=r.get("claim_url", ""),
                screenshot=r.get("screenshot", ""),
                url=r.get("url", ""),
                source=_SOURCE,
            )
            for r in data
        ]

    async def fetch_groups(self) -> list[RawGroup]:
        data = await self._get("/groups")
        return [
            RawGroup(
                name=r.get("name", ""),
                description=r.get("description", ""),
                url=r.get("url", ""),
                profile=r.get("profile", "") if r.get("profile") else "",
                meta=r.get("meta", "") if r.get("meta") else "",
                locations=r.get("locations", []) or [],
                altname=r.get("altname", "") or "",
                source=_SOURCE,
            )
            for r in data
        ]

    async def fetch_cyberattacks(self) -> list[RawCyberattack]:
        data = await self._get("/recentcyberattacks")
        return [
            RawCyberattack(
                victim_name=r.get("victim", ""),
                domain=r.get("domain", ""),
                country=r.get("country", ""),
                attack_date=_parse_datetime(r.get("date") or r.get("attack_date")),
                added=_parse_datetime(r.get("added")),
                discovered=_parse_datetime(r.get("discovered")),
                title=r.get("title", ""),
                summary=r.get("summary", ""),
                article_url=r.get("url", ""),
                source=_SOURCE,
            )
            for r in data
        ]

    async def fetch_all_victims(self, year: int, month: int | None = None) -> list[RawVictim]:
        path = f"/victims/{year}/{month}" if month else f"/victims/{year}"
        data = await self._get(path)
        return [
            RawVictim(
                victim_name=r.get("victim", ""),
                group=r.get("group", ""),
                domain=r.get("domain", ""),
                country=r.get("country", ""),
                activity=r.get("activity", ""),
                description=r.get("description", ""),
                attackdate=_parse_datetime(r.get("attackdate")),
                discovered=_parse_datetime(r.get("discovered")),
                claim_url=r.get("claim_url", ""),
                screenshot=r.get("screenshot", ""),
                url=r.get("url", ""),
                source=_SOURCE,
            )
            for r in data
        ]

    async def fetch_all_cyberattacks(self) -> list[RawCyberattack]:
        data = await self._get("/allcyberattacks")
        return [
            RawCyberattack(
                victim_name=r.get("victim", ""),
                domain=r.get("domain", ""),
                country=r.get("country", ""),
                attack_date=_parse_datetime(r.get("date") or r.get("attack_date")),
                added=_parse_datetime(r.get("added")),
                discovered=_parse_datetime(r.get("discovered")),
                title=r.get("title", ""),
                summary=r.get("summary", ""),
                article_url=r.get("url", ""),
                source=_SOURCE,
            )
            for r in data
        ]

    async def fetch_group_detail(self, group_name: str) -> dict:
        url = f"{self._base_url}/group/{quote(group_name, safe='')}"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError:
            return {}
        if response.status_code >= 400:
            return {}
        data = response.json()
        if isinstance(data, list) and data:
            return data[0]
        return data if isinstance(data, dict) else {}

    async def fetch_group_details(self, group_names: list[str]) -> dict[str, dict]:
        """Fetch detail for multiple groups. Returns {name: raw_json}."""
        results: dict[str, dict] = {}
        for name in group_names:
            detail = await self.fetch_group_detail(name)
            if detail:
                results[name] = detail
        return results

    # "Education never ends, Watson." — Sherlock Holmes, Elementary
    async def close(self) -> None:
        await self._client.aclose()
