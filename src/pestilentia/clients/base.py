# "Detection is, or ought to be, an exact science." — Sherlock Holmes, Elementary
from abc import ABC, abstractmethod

from pestilentia.clients.schemas import RawCyberattack, RawGroup, RawVictim


# "People lie. That's their defining characteristic." — Sherlock, Elementary
class SourceError(Exception):
    """Base error for data source operations."""

    def __init__(self, source: str, message: str, cause: Exception | None = None):
        self.source = source
        self.message = message
        self.cause = cause
        super().__init__(f"[{source}] {message}")


class RateLimitError(SourceError):
    """Raised when a source returns HTTP 429."""

    def __init__(self, source: str, retry_after: int | None = None):
        self.retry_after = retry_after
        msg = f"Rate limited (retry after {retry_after}s)" if retry_after else "Rate limited"
        super().__init__(source, msg)


# "I don't guess. I observe. And once I've observed, I deduce." — Sherlock Holmes, Elementary
class BaseSource(ABC):
    source_name: str

    @abstractmethod
    async def fetch_victims(self) -> list[RawVictim]: ...

    @abstractmethod
    async def fetch_groups(self) -> list[RawGroup]: ...

    @abstractmethod
    async def fetch_cyberattacks(self) -> list[RawCyberattack]: ...

    async def fetch_all_victims(self, year: int, month: int | None = None) -> list[RawVictim]:
        """Fetch historical victims. Override in sources that support it."""
        return []

    async def fetch_all_cyberattacks(self) -> list[RawCyberattack]:
        """Fetch all cyberattacks (not just recent). Override in sources that support it."""
        return await self.fetch_cyberattacks()

    @abstractmethod
    async def close(self) -> None: ...
