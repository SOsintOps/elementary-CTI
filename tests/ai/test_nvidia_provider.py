"""The NIM adapter, exercised entirely offline via pytest-httpx.

The suite's zero-spend property extends to the first real caller: every
branch here — success, the free tier's two signature failures, a malformed
200, a dead network — runs without a key or a wire.
"""

from __future__ import annotations

import httpx
import pytest

from pestilentia.ai.router.nvidia import BASE_URL, CallResult, NvidiaError, NvidiaProvider

URL = f"{BASE_URL}/chat/completions"
MESSAGES = [{"role": "user", "content": "triage this"}]


def _provider() -> NvidiaProvider:
    return NvidiaProvider(api_key="nvapi-test")


def _payload(cached: object = 32) -> dict:
    return {
        "model": "meta/llama-3.1-8b-instruct",
        "choices": [{"message": {"role": "assistant", "content": "OK"}}],
        "usage": {
            "prompt_tokens": 40,
            "completion_tokens": 2,
            "prompt_tokens_details": {"audio_tokens": None, "cached_tokens": cached},
        },
    }


def test_a_completion_yields_text_and_the_audit_numbers(httpx_mock):
    httpx_mock.add_response(url=URL, json=_payload())
    result = _provider().complete("meta/llama-3.1-8b-instruct", MESSAGES)
    assert result == CallResult(
        text="OK",
        model_id="meta/llama-3.1-8b-instruct",
        tokens_in=40,
        tokens_out=2,
        cached_tokens=32,
    )
    request = httpx_mock.get_request()
    assert request.headers["Authorization"] == "Bearer nvapi-test"


def test_absent_cache_details_read_as_zero_not_a_crash(httpx_mock):
    payload = _payload()
    del payload["usage"]["prompt_tokens_details"]
    httpx_mock.add_response(url=URL, json=payload)
    assert _provider().complete("m", MESSAGES).cached_tokens == 0


def test_null_cached_tokens_reads_as_zero(httpx_mock):
    httpx_mock.add_response(url=URL, json=_payload(cached=None))
    assert _provider().complete("m", MESSAGES).cached_tokens == 0


def test_403_names_the_family_opt_in_not_the_key(httpx_mock):
    httpx_mock.add_response(url=URL, status_code=403)
    with pytest.raises(NvidiaError) as err:
        _provider().complete("nvidia/nemotron-x", MESSAGES)
    assert err.value.status == 403
    assert "opt-in" in str(err.value)
    assert "not that the key is bad" in str(err.value)


def test_429_names_the_shared_rate_limit(httpx_mock):
    httpx_mock.add_response(url=URL, status_code=429)
    with pytest.raises(NvidiaError) as err:
        _provider().complete("m", MESSAGES)
    assert err.value.status == 429
    assert "rate limit" in str(err.value)


def test_other_statuses_surface_status_and_body(httpx_mock):
    httpx_mock.add_response(url=URL, status_code=500, text="upstream sad")
    with pytest.raises(NvidiaError) as err:
        _provider().complete("m", MESSAGES)
    assert err.value.status == 500
    assert "upstream sad" in str(err.value)


def test_a_200_in_the_wrong_shape_is_an_error_not_a_keyerror(httpx_mock):
    httpx_mock.add_response(url=URL, json={"unexpected": True})
    with pytest.raises(NvidiaError, match="chat-completions shape"):
        _provider().complete("m", MESSAGES)


def test_network_failure_is_wrapped(httpx_mock):
    httpx_mock.add_exception(httpx.ReadTimeout("slow wire"))
    with pytest.raises(NvidiaError, match="before a response arrived"):
        _provider().complete("m", MESSAGES)


def test_an_empty_key_refuses_before_any_http(httpx_mock):
    with pytest.raises(NvidiaError, match="PEST_AI_NVIDIA_API_KEY"):
        NvidiaProvider(api_key="").complete("m", MESSAGES)
    assert httpx_mock.get_request() is None
