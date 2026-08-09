"""The NVIDIA NIM caller — the first object that actually performs a call.

The router decides and stops; this is the seam where a `ModelChoice` becomes
HTTP. NIM speaks the OpenAI chat-completions dialect, which here is treated as
what it is — JSON over HTTP — so the ADR-006 "native SDKs, no LiteLLM" rule is
honoured with plain httpx and zero new dependencies.

Error texts are written for the operator who will read them in a log: the two
failure modes specific to NIM's free tier (a model family that was never
opted into, the ~40 RPM shared rate limit) each name their own fix instead of
surfacing as a generic HTTP status.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from pestilentia.ai.router.providers import PROVIDERS, ProviderSpec

BASE_URL = "https://integrate.api.nvidia.com/v1"


class NvidiaError(RuntimeError):
    """A call that did not produce a completion, with the status if one came back."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class CallResult:
    """What the audit trail needs from one completed call, nothing more."""

    text: str
    model_id: str
    tokens_in: int
    tokens_out: int
    #: Prompt tokens NIM served from its prefix cache. This is the observable
    #: behind the "cache observed" acceptance criterion.
    cached_tokens: int


class NvidiaProvider:
    def __init__(
        self,
        api_key: str,
        spec: ProviderSpec | None = None,
        base_url: str = BASE_URL,
        timeout: float = 60.0,
    ) -> None:
        # An empty key is legal here and refused at call time: the registry
        # must stay constructible in environments that will never call (the
        # zero-spend test suite, a dev box without the key).
        self._api_key = api_key
        self._spec = spec if spec is not None else PROVIDERS["nvidia"]
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def spec(self) -> ProviderSpec:
        return self._spec

    def complete(
        self,
        model_id: str,
        messages: list[dict[str, str]],
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> CallResult:
        if not self._api_key:
            raise NvidiaError(
                "no NVIDIA API key configured; set PEST_AI_NVIDIA_API_KEY "
                "(generate one at build.nvidia.com, Settings > API Keys)"
            )
        try:
            response = httpx.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": model_id,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise NvidiaError(f"NIM call failed before a response arrived: {exc!r}") from exc

        if response.status_code == 403:
            raise NvidiaError(
                f"NIM refused {model_id!r} with 403 — this usually means the "
                "model family needs a one-time opt-in on build.nvidia.com "
                "(open the model page while logged in), not that the key is bad",
                status=403,
            )
        if response.status_code == 429:
            raise NvidiaError(
                "NIM rate limit hit (~40 requests/min shared across all models "
                "on the free tier); slow the caller down rather than retrying hot",
                status=429,
            )
        if response.status_code != 200:
            raise NvidiaError(
                f"NIM answered {response.status_code} for {model_id!r}: {response.text[:200]}",
                status=response.status_code,
            )

        payload = response.json()
        try:
            text = payload["choices"][0]["message"]["content"]
            usage = payload["usage"]
        except (KeyError, IndexError, TypeError) as exc:
            raise NvidiaError(
                f"NIM answered 200 but not in the chat-completions shape: {exc!r}"
            ) from exc

        return CallResult(
            text=text or "",
            model_id=payload.get("model", model_id),
            tokens_in=int(usage.get("prompt_tokens") or 0),
            tokens_out=int(usage.get("completion_tokens") or 0),
            cached_tokens=_cached_tokens(usage),
        )


def _cached_tokens(usage: dict[str, Any]) -> int:
    """`prompt_tokens_details` is optional and its fields nullable — absence is 0."""
    details = usage.get("prompt_tokens_details")
    if not isinstance(details, dict):
        return 0
    return int(details.get("cached_tokens") or 0)
