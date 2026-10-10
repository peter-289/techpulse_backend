"""The HTTP support-AI adapter.

Two things are worth pinning here. The response parser is carried over from the
old ``SupportChatService._extract_assistant_content`` and is easy to break by
tidying it, since three provider shapes have to keep working. And the reason this
class exists at all rather than a ``requests.post`` in the service is that the
old call blocked the event loop; ``test_concurrent_questions_do_not_serialize``
is the regression test for that.
"""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from app.infrastructure.external_apis.ai_support.http_support_ai import (
    HttpSupportAI,
    _extract_assistant_content,
)
from app.modules.user.domain.ports.support_ai import (
    SupportAIConfig,
    SupportAIUnavailableError,
)

PROMPT = "you are support"


def _config(**overrides) -> SupportAIConfig:
    defaults = {
        "base_url": "https://provider.invalid/v1",
        "api_key": "secret",
        "model": "a-model",
        "timeout_seconds": 5.0,
    }
    return SupportAIConfig(**{**defaults, **overrides})


@pytest.fixture
def provider(monkeypatch):
    """Serve a stubbed provider instead of a real one.

    Patches ``httpx.AsyncClient`` rather than adding a client-factory seam to
    the adapter: production code should not grow an injection point that only
    tests use.
    """

    def install(handler, **overrides) -> HttpSupportAI:
        real_client = httpx.AsyncClient

        def factory(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", factory)
        return HttpSupportAI(_config(**overrides))

    return install


# === configuration ===

@pytest.mark.asyncio
async def test_an_unconfigured_key_reports_unavailable_rather_than_raising_config_error(provider) -> None:
    """An empty key is a normal local-dev state, and must not reach the network."""
    adapter = provider(
        lambda request: pytest.fail("must not make a request without a key"),
        api_key="",
    )

    with pytest.raises(SupportAIUnavailableError):
        await adapter.generate_reply("help", system_prompt=PROMPT)


def test_is_configured_reflects_the_key() -> None:
    assert _config(api_key="k").is_configured is True
    assert _config(api_key="").is_configured is False
    assert _config(api_key="   ").is_configured is False


@pytest.mark.asyncio
async def test_the_request_carries_the_key_model_and_prompt(provider) -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "hello"}}]}
        )

    adapter = provider(handler, base_url="https://provider.invalid/v1/")
    reply = await adapter.generate_reply("my question", system_prompt=PROMPT)

    assert reply == "hello"
    assert seen["url"] == "https://provider.invalid/v1/chat/completions"
    assert seen["auth"] == "Bearer secret"
    assert seen["body"]["model"] == "a-model"
    assert seen["body"]["temperature"] == 0.2
    assert seen["body"]["messages"] == [
        {"role": "system", "content": PROMPT},
        {"role": "user", "content": "my question"},
    ]


# === failure modes all become one signal ===

@pytest.mark.asyncio
async def test_a_server_error_becomes_unavailable_and_truncates_the_body(provider) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="x" * 5000)

    adapter = provider(handler)
    with pytest.raises(SupportAIUnavailableError) as excinfo:
        await adapter.generate_reply("help", system_prompt=PROMPT)

    message = str(excinfo.value)
    assert "AI support service failed" in message
    # The old code truncated at 200 characters before logging. A provider can
    # return a page of HTML and the log line should not carry all of it.
    assert len(message) < 400


@pytest.mark.asyncio
async def test_a_non_json_response_becomes_unavailable(provider) -> None:
    adapter = provider(lambda request: httpx.Response(200, text="<html>nope</html>"))
    with pytest.raises(SupportAIUnavailableError) as excinfo:
        await adapter.generate_reply("help", system_prompt=PROMPT)
    assert "invalid response" in str(excinfo.value)


@pytest.mark.asyncio
async def test_an_empty_completion_becomes_unavailable(provider) -> None:
    adapter = provider(lambda request: httpx.Response(200, json={"choices": []}))
    with pytest.raises(SupportAIUnavailableError) as excinfo:
        await adapter.generate_reply("help", system_prompt=PROMPT)
    assert "empty response" in str(excinfo.value)


@pytest.mark.asyncio
async def test_a_transport_failure_becomes_unavailable(provider) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host", request=request)

    adapter = provider(handler)
    with pytest.raises(SupportAIUnavailableError) as excinfo:
        await adapter.generate_reply("help", system_prompt=PROMPT)
    assert "Failed to reach" in str(excinfo.value)


# === response parsing, carried over from the old service ===

def test_parses_a_plain_string_completion() -> None:
    data = {"choices": [{"message": {"content": "  spaced  "}}]}
    assert _extract_assistant_content(data) == "spaced"


def test_parses_a_multi_part_completion() -> None:
    data = {
        "choices": [
            {"message": {"content": [{"type": "text", "text": "one"}, {"text": "two"}]}}
        ]
    }
    assert _extract_assistant_content(data) == "one\ntwo"


def test_parses_the_bare_output_text_shape() -> None:
    assert _extract_assistant_content({"output_text": " direct "}) == "direct"


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"choices": []},
        {"choices": [{}]},
        {"choices": [{"message": {"content": None}}]},
        {"choices": [{"message": {"content": []}}]},
        {"choices": [{"message": {"content": [{}]}}]},
        {"output_text": 42},
    ],
)
def test_unusable_shapes_yield_nothing(data) -> None:
    assert _extract_assistant_content(data) == ""


# === the reason this class exists ===

@pytest.mark.asyncio
async def test_concurrent_questions_do_not_serialize(provider) -> None:
    """Regression test for the blocking call this port removed.

    The old implementation used ``requests.post(..., timeout=60)`` on the event
    loop thread, so a slow provider stalled every other request the worker was
    serving. With three concurrent questions that each take 0.2s of simulated
    latency, a blocking implementation takes at least 0.6s; an awaiting one
    finishes in about 0.2s.
    """

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.2)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    adapter = provider(handler)

    async def ask() -> str:
        return await adapter.generate_reply("help", system_prompt=PROMPT)

    started = time.monotonic()
    replies = await asyncio.gather(ask(), ask(), ask())
    elapsed = time.monotonic() - started

    assert replies == ["ok", "ok", "ok"]
    assert elapsed < 0.45, f"calls appear to be blocking ({elapsed:.2f}s)"
